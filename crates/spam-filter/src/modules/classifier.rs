/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::analysis::domain::SpamFilterAnalyzeDomain;
use crate::analysis::init::SpamFilterInit;
use crate::analysis::is_trusted_domain;
use crate::analysis::url::SpamFilterAnalyzeUrl;
use crate::modules::html::{A, ALT, HREF, HtmlToken, IMG, SRC, TITLE};
use crate::{Email, SpamFilterContext, TextPart};
use crate::{Hostname, SpamFilterInput};
use common::config::spamfilter;
use common::manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY};
use common::{Server, config::spamfilter::Location, ipc::BroadcastEvent};
use mail_auth::DmarcResult;
use mail_parser::{MessageParser, MimeHeaders};
use nlp::classifier::feature::{
    CcfhFeature, CcfhFeatureBuilder, FeatureBuilder, FhFeature, FhFeatureBuilder, Sample,
    UnprocessedFeature,
};
use nlp::classifier::ftrl::Ftrl;
use nlp::classifier::reservoir::SampleReservoir;
use nlp::classifier::train::{CcfhTrainer, FhTrainer};
use nlp::tokenizers::types::TypesTokenizer;
use nlp::tokenizers::{stream::WordStemTokenizer, types::TokenType};
use std::time::Instant;
use std::{
    borrow::Cow,
    collections::{HashMap, hash_map::Entry},
    hash::{Hash, RandomState},
    sync::Arc,
};
use store::rand::seq::SliceRandom;
use store::write::{BlobLink, now};
use store::{
    Deserialize, IterateParams, Serialize, U32_LEN, U64_LEN, ValueKey,
    write::{
        AlignedBytes, Archive, Archiver, BatchBuilder, BlobOp, ValueClass,
        key::DeserializeBigEndian,
    },
};
use tokio::sync::{mpsc, oneshot};
use trc::{AddContext, SpamEvent};
use types::blob_hash::BlobHash;
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;
use unicode_security::mixed_script::AugmentedScriptSet;

pub trait SpamClassifier {
    fn spam_train(&self, retrain: bool) -> impl Future<Output = trc::Result<()>> + Send;

    fn spam_classify(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn spam_build_tokens<'x>(
        &self,
        ctx: &'x SpamFilterContext<'_>,
    ) -> impl Future<Output = Tokens<'x>> + Send;
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Clone, PartialEq, Eq, Debug)]
pub struct TrainingSample {
    hash: BlobHash,
    account_id: u32,
}

struct TrainingTask {
    sample: TrainingSample,
    is_spam: bool,
    is_replay: bool,
    remove: Option<u64>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug)]
pub struct SpamTrainer {
    pub trainer: SpamTrainerClass,
    pub reservoir: SampleReservoir<TrainingSample>,
    pub last_sample_expiry: u64,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug)]
pub enum SpamTrainerClass {
    FtrlFh(Box<FhTrainer<Ftrl>>),
    FtrlCfh(Box<CcfhTrainer<Ftrl, Ftrl>>),
}

impl SpamClassifier for Server {
    async fn spam_train(&self, retrain: bool) -> trc::Result<()> {
        let Some(config) = &self.core.spam.classifier else {
            return Ok(());
        };

        let _permit = self
            .inner
            .ipc
            .train_task_controller
            .try_run()
            .ok_or_else(|| {
                trc::EventType::Spam(SpamEvent::TrainCompleted)
                    .reason("Spam training task is already running")
                    .caused_by(trc::location!())
            })?;

        let started = Instant::now();
        trc::event!(Spam(SpamEvent::TrainStarted));

        // Fetch or build trainer
        let mut trainer = if !retrain
            && let Some(trainer) = self
                .blob_store()
                .get_blob(SPAM_TRAINER_KEY, 0..usize::MAX)
                .await
                .and_then(|archive| match archive {
                    Some(archive) => <Archive<AlignedBytes> as Deserialize>::deserialize(&archive)
                        .and_then(|archive| archive.deserialize_untrusted::<SpamTrainer>())
                        .map(Some),
                    None => Ok(None),
                })
                .caused_by(trc::location!())?
        {
            trainer
        } else {
            SpamTrainer {
                trainer: match &config.i_params {
                    Some(i_params) => SpamTrainerClass::FtrlCfh(Box::new(CcfhTrainer::new(
                        Ftrl::new(config.w_params.feature_hash_size),
                        Ftrl::new(i_params.feature_hash_size).with_initial_weights(0.5),
                    ))),
                    None => SpamTrainerClass::FtrlFh(Box::new(FhTrainer::new(Ftrl::new(
                        config.w_params.feature_hash_size,
                    )))),
                },
                reservoir: SampleReservoir::default(),
                last_sample_expiry: 0,
            }
        };

        // Update hyperparameters
        match (&mut trainer.trainer, &config.i_params) {
            (SpamTrainerClass::FtrlFh(trainer), None) => {
                trainer.optimizer_mut().set_hyperparams(
                    config.w_params.alpha,
                    config.w_params.beta,
                    config.w_params.l1_ratio,
                    config.w_params.l2_ratio,
                );
            }
            (SpamTrainerClass::FtrlCfh(trainer), Some(i_params)) => {
                trainer.w_optimizer_mut().set_hyperparams(
                    config.w_params.alpha,
                    config.w_params.beta,
                    config.w_params.l1_ratio,
                    config.w_params.l2_ratio,
                );
                trainer.i_optimizer_mut().set_hyperparams(
                    i_params.alpha,
                    i_params.beta,
                    i_params.l1_ratio,
                    i_params.l2_ratio,
                );
            }
            _ => {}
        }

        // Fetch blob hashes for samples
        let mut samples = Vec::new();
        let mut remove_entries = false;
        let from_key = ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::SpamSample {
                hash: BlobHash::default(),
                until: trainer.last_sample_expiry + 1,
            }),
        };
        let to_key = ValueKey {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::Blob(BlobOp::SpamSample {
                hash: BlobHash::new_max(),
                until: u64::MAX,
            }),
        };
        let mut spam_count = 0;
        let mut ham_count = 0;
        self.store()
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    let until = key.deserialize_be_u64(1)?;
                    let account_id = key.deserialize_be_u32(U64_LEN + 1)?;
                    let hash = BlobHash::try_from_hash_slice(
                        key.get(U64_LEN + U32_LEN + 1..).ok_or_else(|| {
                            trc::Error::corrupted_key(key, value.into(), trc::location!())
                        })?,
                    )
                    .unwrap();
                    let (Some(is_spam), Some(hold)) = (value.first(), value.get(1)) else {
                        return Err(trc::Error::corrupted_key(
                            key,
                            value.into(),
                            trc::location!(),
                        ));
                    };

                    let do_remove = *hold == 0;
                    let is_spam = *is_spam == 1;
                    let sample = TrainingSample { hash, account_id };

                    // Add to reservoir
                    if !do_remove {
                        trainer.reservoir.update_reservoir(
                            &sample,
                            is_spam,
                            config.reservoir_capacity,
                        );
                    } else {
                        trainer.reservoir.update_counts(is_spam);
                    }

                    samples.push(TrainingTask {
                        sample,
                        is_spam,
                        is_replay: false,
                        remove: do_remove.then_some(until),
                    });

                    remove_entries |= do_remove;

                    // Update trainer stats
                    trainer.last_sample_expiry = until;
                    if is_spam {
                        spam_count += 1;
                    } else {
                        ham_count += 1;
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if samples.is_empty() {
            trc::event!(
                Spam(SpamEvent::TrainCompleted),
                Total = 0,
                Elapsed = started.elapsed()
            );

            return Ok(());
        } else if (trainer.reservoir.ham.total_seen < config.min_ham_samples)
            || (trainer.reservoir.spam.total_seen < config.min_spam_samples)
        {
            trc::event!(
                Spam(SpamEvent::ModelNotReady),
                Reason = "Not enough samples for training",
                Details = vec![
                    trc::Value::from(trainer.reservoir.ham.total_seen),
                    trc::Value::from(trainer.reservoir.spam.total_seen)
                ],
                Limit = vec![
                    trc::Value::from(config.min_ham_samples),
                    trc::Value::from(config.min_spam_samples)
                ],
                Elapsed = started.elapsed()
            );

            return Ok(());
        }

        // Balance classes if needed
        if spam_count > ham_count {
            // We have too much spam this time. We need to replay old HAM.
            samples.extend(
                trainer
                    .reservoir
                    .replay_samples((spam_count - ham_count) as usize, false)
                    .map(|sample| TrainingTask {
                        sample: sample.clone(),
                        is_spam: false,
                        is_replay: true,
                        remove: None,
                    }),
            );
        } else if ham_count > spam_count {
            // We have too much ham this time. We need to replay old SPAM.
            samples.extend(
                trainer
                    .reservoir
                    .replay_samples((ham_count - spam_count) as usize, true)
                    .map(|sample| TrainingTask {
                        sample: sample.clone(),
                        is_spam: true,
                        is_replay: true,
                        remove: None,
                    }),
            );
        }

        let num_samples = samples.len();
        samples.shuffle(&mut store::rand::rng());

        // Spawn training task
        let epochs = match trainer
            .reservoir
            .ham
            .total_seen
            .min(trainer.reservoir.spam.total_seen)
        {
            0..=50 => 3,   // Bootstrap
            51..=200 => 2, // Refinement
            _ => 1,        // Full online training
        };
        let task = trainer.trainer.spawn(epochs)?;
        let is_fh = matches!(task, TrainTask::Fh { .. });

        // Train
        for chunk in samples.chunks(128) {
            let mut fh_samples = if is_fh {
                Vec::with_capacity(chunk.len())
            } else {
                Vec::new()
            };
            let mut ccfh_samples = if !is_fh {
                Vec::with_capacity(chunk.len())
            } else {
                Vec::new()
            };

            for sample in chunk {
                let account_id = if sample.sample.account_id != u32::MAX {
                    Some(sample.sample.account_id)
                } else {
                    None
                };
                let Some(raw_message) = self
                    .blob_store()
                    .get_blob(sample.sample.hash.as_slice(), 0..usize::MAX)
                    .await
                    .caused_by(trc::location!())?
                else {
                    if sample.is_replay {
                        trainer
                            .reservoir
                            .remove_sample(&sample.sample, sample.is_spam);
                    } else {
                        trc::event!(
                            Spam(SpamEvent::TrainSampleNotFound),
                            Reason = "Blob not found",
                            AccountId = account_id,
                            BlobId = sample.sample.hash.to_hex(),
                        );
                    }
                    continue;
                };

                // Build features
                let message = MessageParser::new().parse(&raw_message).unwrap_or_default();
                let mut ctx =
                    self.spam_filter_init(SpamFilterInput::from_message(&message, 0).train_mode());
                self.spam_filter_analyze_domain(&mut ctx).await;
                self.spam_filter_analyze_url(&mut ctx).await;
                let mut tokens = self.spam_build_tokens(&ctx).await.0;

                match &task {
                    TrainTask::Fh { builder, .. } => {
                        if config.log_scale {
                            builder.scale(&mut tokens);
                        }
                        fh_samples.push(Sample::new(
                            builder.build(&tokens, account_id, config.l2_normalize),
                            sample.is_spam,
                        ));
                    }
                    TrainTask::Ccfh { builder, .. } => {
                        if config.log_scale {
                            builder.scale(&mut tokens);
                        }
                        ccfh_samples.push(Sample::new(
                            builder.build(&tokens, account_id, config.l2_normalize),
                            sample.is_spam,
                        ));
                    }
                }

                // Look for stop requests
                if self.inner.ipc.train_task_controller.should_stop() {
                    trc::event!(
                        Spam(SpamEvent::TrainCompleted),
                        Reason = "Training task was stopped",
                        Total = fh_samples.len() + ccfh_samples.len(),
                        Elapsed = started.elapsed()
                    );
                    return Ok(());
                }
            }

            // Send batch for training
            let (done_tx, done_rx) = oneshot::channel::<()>();
            match &task {
                TrainTask::Fh { batch_tx, .. } => {
                    batch_tx
                        .send(FhTrainJob {
                            samples: fh_samples,
                            done: done_tx,
                        })
                        .await
                        .map_err(|err| {
                            trc::EventType::Server(trc::ServerEvent::ThreadError)
                                .reason(err)
                                .details("Spam train task failed")
                                .caused_by(trc::location!())
                        })?;
                }
                TrainTask::Ccfh { batch_tx, .. } => {
                    batch_tx
                        .send(CcfhTrainJob {
                            samples: ccfh_samples,
                            done: done_tx,
                        })
                        .await
                        .map_err(|err| {
                            trc::EventType::Server(trc::ServerEvent::ThreadError)
                                .reason(err)
                                .details("Spam train task failed")
                                .caused_by(trc::location!())
                        })?;
                }
            }

            done_rx.await.map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .details("Spam train task failed")
                    .caused_by(trc::location!())
            })?;
        }

        // Take ownership of trainer
        trainer.trainer = match task {
            TrainTask::Fh {
                batch_tx,
                trainer_rx,
                ..
            } => {
                drop(batch_tx);
                SpamTrainerClass::FtrlFh(trainer_rx.await.map_err(|err| {
                    trc::EventType::Server(trc::ServerEvent::ThreadError)
                        .reason(err)
                        .details("Spam train task failed")
                        .caused_by(trc::location!())
                })?)
            }
            TrainTask::Ccfh {
                batch_tx,
                trainer_rx,
                ..
            } => {
                drop(batch_tx);
                SpamTrainerClass::FtrlCfh(trainer_rx.await.map_err(|err| {
                    trc::EventType::Server(trc::ServerEvent::ThreadError)
                        .reason(err)
                        .details("Spam train task failed")
                        .caused_by(trc::location!())
                })?)
            }
        };

        // Store updated trainer and classifier
        let ham_count = trainer.reservoir.ham.total_seen;
        let spam_count = trainer.reservoir.spam.total_seen;
        let classifier = Archiver::new(match &trainer.trainer {
            SpamTrainerClass::FtrlFh(fh_trainer) => spamfilter::SpamClassifier::FhClassifier {
                classifier: fh_trainer.build_classifier(),
                last_trained_at: now(),
            },
            SpamTrainerClass::FtrlCfh(ccfh_trainer) => spamfilter::SpamClassifier::CcfhClassifier {
                classifier: ccfh_trainer.build_classifier(),
                last_trained_at: now(),
            },
        });
        self.blob_store()
            .put_blob(
                SPAM_TRAINER_KEY,
                &Archiver::new(trainer)
                    .serialize()
                    .caused_by(trc::location!())?,
            )
            .await
            .caused_by(trc::location!())?;
        self.blob_store()
            .put_blob(
                SPAM_CLASSIFIER_KEY,
                &classifier.serialize().caused_by(trc::location!())?,
            )
            .await
            .caused_by(trc::location!())?;

        self.inner
            .data
            .spam_classifier
            .store(Arc::new(classifier.inner));
        self.cluster_broadcast(BroadcastEvent::ReloadSpamFilter)
            .await;

        trc::event!(
            Spam(SpamEvent::TrainCompleted),
            Total = num_samples,
            Details = vec![trc::Value::from(ham_count), trc::Value::from(spam_count)],
            Elapsed = started.elapsed()
        );

        // Remove samples marked for deletion
        if remove_entries {
            let mut batch = BatchBuilder::new();
            for sample in samples {
                if let Some(until) = sample.remove {
                    batch
                        .with_account_id(sample.sample.account_id)
                        .clear(BlobOp::Link {
                            hash: sample.sample.hash.clone(),
                            to: BlobLink::Temporary { until },
                        })
                        .clear(BlobOp::SpamSample {
                            hash: sample.sample.hash,
                            until,
                        });
                    if batch.is_large_batch() {
                        self.store()
                            .write(batch.build_all())
                            .await
                            .caused_by(trc::location!())?;
                        batch = BatchBuilder::new();
                    }
                }
            }
            if !batch.is_empty() {
                self.store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
        }

        Ok(())
    }

    async fn spam_classify(&self, ctx: &mut SpamFilterContext<'_>) -> trc::Result<()> {
        let classifier = self.inner.data.spam_classifier.load_full();
        let Some(config) = &self.core.spam.classifier else {
            return Ok(());
        };

        let started = Instant::now();
        match classifier.as_ref() {
            spamfilter::SpamClassifier::FhClassifier { classifier, .. } => {
                let mut classifier_confidence = Vec::with_capacity(ctx.input.env_rcpt_to.len());
                let mut has_prediction = false;
                let mut tokens = self.spam_build_tokens(ctx).await.0;
                let feature_builder = classifier.feature_builder();
                if config.log_scale {
                    feature_builder.scale(&mut tokens);
                }

                for rcpt in &ctx.input.env_rcpt_to {
                    let prediction = if let Some(account_id) = self
                        .directory()
                        .email_to_id(rcpt)
                        .await
                        .caused_by(trc::location!())?
                    {
                        has_prediction = true;
                        classifier
                            .predict_proba_sample(&feature_builder.build(
                                &tokens,
                                account_id.into(),
                                config.l2_normalize,
                            ))
                            .into()
                    } else {
                        None
                    };
                    classifier_confidence.push(prediction);
                }

                if has_prediction {
                    ctx.result.classifier_confidence = classifier_confidence;
                } else {
                    // None of the recipients are local, default to global model prediction
                    let prediction = classifier.predict_proba_sample(&feature_builder.build(
                        &tokens,
                        None,
                        config.l2_normalize,
                    ));
                    ctx.result.classifier_confidence =
                        vec![prediction.into(); ctx.input.env_rcpt_to.len()];
                }
            }
            spamfilter::SpamClassifier::CcfhClassifier { classifier, .. } => {
                let mut classifier_confidence = Vec::with_capacity(ctx.input.env_rcpt_to.len());
                let mut has_prediction = false;
                let mut tokens = self.spam_build_tokens(ctx).await.0;
                let feature_builder = classifier.feature_builder();
                if config.log_scale {
                    feature_builder.scale(&mut tokens);
                }

                for rcpt in &ctx.input.env_rcpt_to {
                    let prediction = if let Some(account_id) = self
                        .directory()
                        .email_to_id(rcpt)
                        .await
                        .caused_by(trc::location!())?
                    {
                        has_prediction = true;
                        classifier
                            .predict_proba_sample(&feature_builder.build(
                                &tokens,
                                account_id.into(),
                                config.l2_normalize,
                            ))
                            .into()
                    } else {
                        None
                    };
                    classifier_confidence.push(prediction);
                }

                if has_prediction {
                    ctx.result.classifier_confidence = classifier_confidence;
                } else {
                    // None of the recipients are local, default to global model prediction
                    let prediction = classifier.predict_proba_sample(&feature_builder.build(
                        &tokens,
                        None,
                        config.l2_normalize,
                    ));
                    ctx.result.classifier_confidence =
                        vec![prediction.into(); ctx.input.env_rcpt_to.len()];
                }
            }
            spamfilter::SpamClassifier::Disabled => {
                return Ok(());
            }
        }

        trc::event!(
            Spam(SpamEvent::Classify),
            Result = ctx
                .result
                .classifier_confidence
                .iter()
                .zip(ctx.input.env_rcpt_to.iter())
                .map(|(v, rcpt)| trc::Value::Array(vec![
                    trc::Value::from(rcpt.to_string()),
                    trc::Value::from(*v)
                ]))
                .collect::<Vec<_>>(),
            SpanId = ctx.input.span_id,
            Elapsed = started.elapsed()
        );

        Ok(())
    }

    async fn spam_build_tokens<'x>(&self, ctx: &'x SpamFilterContext<'_>) -> Tokens<'x> {
        let mut tokens = Tokens::default();

        // Add From addresses
        if ctx
            .input
            .dmarc_result
            .as_ref()
            .is_some_and(|result| **result != DmarcResult::Pass)
        {
            tokens.insert(Token::Sender { value: "!".into() });
        }
        for email in [&ctx.output.env_from_addr, &ctx.output.from.email] {
            tokens.insert_email(email, true);
        }

        // Add Email addresses
        for email in &ctx.output.emails {
            let is_sender = match &email.location {
                Location::HeaderReplyTo | Location::HeaderDnt => true,
                Location::BodyText
                | Location::BodyHtml
                | Location::Attachment
                | Location::HeaderSubject => false,
                _ => continue,
            };

            if is_sender
                || !is_trusted_domain(
                    self,
                    email.element.email.domain_part.sld_or_default(),
                    ctx.input.span_id,
                )
                .await
            {
                tokens.insert_email(&email.element.email, is_sender);
            }
        }

        // Add URLs
        for url in &ctx.output.urls {
            if let Some(url) = &url.element.url_parsed
                && !is_trusted_domain(self, url.host.sld_or_default(), ctx.input.span_id).await
            {
                if let Some(host) = &url.host.sld {
                    tokens.insert(Token::Url { value: host.into() });
                    if host != &url.host.fqdn {
                        tokens.insert(Token::Url {
                            value: url.host.fqdn.as_str().into(),
                        });
                    }
                } else {
                    tokens.insert(Token::Url {
                        value: url.host.fqdn.as_str().into(),
                    });
                }
                for token in url
                    .parts
                    .path()
                    .split(['/', '.', '_'])
                    .filter(|v| v.chars().all(|ch| ch.is_alphabetic()))
                {
                    if token.len() > 2 {
                        let token = truncate_word(token, MAX_TOKEN_LENGTH);
                        tokens.insert(Token::Url {
                            value: format!("_{token}").into(),
                        });
                    }
                }
            }
        }

        // Add hostnames
        for domain in &ctx.output.domains {
            if matches!(
                domain.location,
                Location::HeaderReceived | Location::HeaderMid | Location::Ehlo | Location::Tcp
            ) {
                let host = Hostname::new(&domain.element);
                let host_sld = host.sld_or_default();

                if !is_trusted_domain(self, host_sld, ctx.input.span_id).await {
                    if !host_sld.is_empty() && host_sld != host.fqdn {
                        tokens.insert(Token::Hostname {
                            value: host_sld.to_string().into(),
                        });
                    }

                    tokens.insert(Token::Hostname {
                        value: host.fqdn.into(),
                    });
                }
            }
        }

        // Add ASN
        if let Some(asn) = ctx.input.asn {
            tokens.insert(Token::Asn {
                number: asn.to_be_bytes(),
            });
        }

        // Add MIME and attachment indicators
        for part in &ctx.input.message.parts {
            if let Some(name) = part.attachment_name()
                && let Some((name, ext)) = name.rsplit_once('.')
            {
                if !ext.is_empty() {
                    tokens.insert(Token::Attachment {
                        value: lower_prefix("!", truncate_word(ext, MAX_TOKEN_LENGTH)).into(),
                    });
                }
                let name = name.to_lowercase();
                let word_tokenizer = WordStemTokenizer::new(&name);
                for token in TypesTokenizer::new(&name) {
                    if let TokenType::Alphabetic(word) = token.word {
                        word_tokenizer.tokenize(word, |token| {
                            tokens.insert(Token::Attachment {
                                value: format!(
                                    "_{}",
                                    truncate_word(token.as_ref(), MAX_TOKEN_LENGTH)
                                )
                                .into(),
                            });
                        });
                    }
                }
            }

            if let Some(ct) = part.content_type() {
                let mut ct_lower = String::with_capacity(
                    ct.c_type.len() + ct.c_subtype.as_ref().map_or(0, |s| s.len()),
                );
                for ch in ct.c_type.chars() {
                    ct_lower.push(ch.to_ascii_lowercase());
                }
                if let Some(st) = &ct.c_subtype {
                    ct_lower.push('/');
                    for ch in st.chars() {
                        ct_lower.push(ch.to_ascii_lowercase());
                    }
                }

                tokens.insert(Token::MimeType { value: ct_lower });
            }
        }

        // Tokenize the subject
        for token in &ctx.output.subject_tokens {
            tokens.insert_type(
                &WordStemTokenizer::new(&ctx.output.subject_thread_lc),
                token,
                false,
            );
        }

        // Tokenize the text parts
        let body_idx = ctx
            .input
            .message
            .html_body
            .first()
            .or_else(|| ctx.input.message.text_body.first())
            .map(|idx| *idx as usize);
        let mut alt_tokens = Tokens::default();
        for (idx, part) in ctx.output.text_parts.iter().enumerate() {
            let is_body = Some(idx) == body_idx;
            if is_body
                || (!ctx.input.message.text_body.contains(&(idx as u32))
                    && !ctx.input.message.html_body.contains(&(idx as u32)))
            {
                tokens.insert_text_part(part, is_body);
            } else {
                alt_tokens.insert_text_part(part, false);
            }
        }
        if !alt_tokens.0.is_empty() {
            for (token, count) in alt_tokens.0.into_iter() {
                if let Entry::Vacant(entry) = tokens.0.entry(token) {
                    entry.insert(count);
                }
            }
        }

        tokens
    }
}

struct FhTrainJob {
    samples: Vec<Sample<FhFeature>>,
    done: oneshot::Sender<()>,
}

struct CcfhTrainJob {
    samples: Vec<Sample<CcfhFeature>>,
    done: oneshot::Sender<()>,
}

enum TrainTask {
    Fh {
        batch_tx: mpsc::Sender<FhTrainJob>,
        trainer_rx: oneshot::Receiver<Box<FhTrainer<Ftrl>>>,
        builder: FhFeatureBuilder,
    },
    Ccfh {
        batch_tx: mpsc::Sender<CcfhTrainJob>,
        trainer_rx: oneshot::Receiver<Box<CcfhTrainer<Ftrl, Ftrl>>>,
        builder: CcfhFeatureBuilder,
    },
}

impl SpamTrainerClass {
    fn spawn(self, num_epochs: usize) -> trc::Result<TrainTask> {
        match self {
            SpamTrainerClass::FtrlFh(mut trainer) => {
                let builder = trainer.feature_builder();
                let (batch_tx, mut batch_rx) = mpsc::channel::<FhTrainJob>(1);
                let (trainer_tx, trainer_rx) = oneshot::channel();

                std::thread::Builder::new()
                    .name("FTRL Train Task".into())
                    .spawn(move || {
                        while let Some(mut job) = batch_rx.blocking_recv() {
                            trainer.fit(&mut job.samples, num_epochs);
                            let _ = job.done.send(());
                        }
                        // Send trainer back when done
                        let _ = trainer_tx.send(trainer);
                    })
                    .map_err(|err| {
                        trc::EventType::Server(trc::ServerEvent::ThreadError)
                            .reason(err)
                            .details("Failed to spawn spam train task")
                            .caused_by(trc::location!())
                    })?;

                Ok(TrainTask::Fh {
                    batch_tx,
                    trainer_rx,
                    builder,
                })
            }
            SpamTrainerClass::FtrlCfh(mut trainer) => {
                let builder = trainer.feature_builder();
                let (batch_tx, mut batch_rx) = mpsc::channel::<CcfhTrainJob>(1);
                let (trainer_tx, trainer_rx) = oneshot::channel();

                std::thread::Builder::new()
                    .name("FTRL Train Task".into())
                    .spawn(move || {
                        while let Some(mut job) = batch_rx.blocking_recv() {
                            trainer.fit(&mut job.samples, num_epochs);
                            let _ = job.done.send(());
                        }
                        // Send trainer back when done
                        let _ = trainer_tx.send(trainer);
                    })
                    .map_err(|err| {
                        trc::EventType::Server(trc::ServerEvent::ThreadError)
                            .reason(err)
                            .details("Failed to spawn spam train task")
                            .caused_by(trc::location!())
                    })?;

                Ok(TrainTask::Ccfh {
                    batch_tx,
                    trainer_rx,
                    builder,
                })
            }
        }
    }
}

const MAX_TOKEN_LENGTH: usize = 16;

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, PartialOrd, Ord,
)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Token<'x> {
    Word { value: Cow<'x, str> },
    Number { code: [u8; 2] },
    Alphanumeric { code: [u8; 4] },
    UnicodeCategory { value: &'x str },
    Sender { value: Cow<'x, str> },
    Asn { number: [u8; 4] },
    Url { value: Cow<'x, str> },
    Email { value: Cow<'x, str> },
    Hostname { value: Cow<'x, str> },
    Attachment { value: Cow<'x, str> },
    MimeType { value: String },
    HtmlImage { src: &'x str },
    HtmlAnchor { href: &'x str },
}

#[derive(Debug)]
pub struct Tokens<'x>(pub HashMap<Token<'x>, f32, RandomState>);

impl<'x> Tokens<'x> {
    fn insert_text_part(&mut self, part: &'x TextPart<'x>, is_body: bool) {
        match part {
            TextPart::Plain { text_body, tokens } => {
                let word_tokenizer = WordStemTokenizer::new(text_body);

                for token in tokens {
                    self.insert_type(&word_tokenizer, token, is_body);
                }

                if is_body
                    && (tokens.is_empty()
                        || !tokens.iter().any(|t| matches!(t, TokenType::Alphabetic(_))))
                {
                    self.insert(Token::Word {
                        value: "_null".into(),
                    });
                }
            }
            TextPart::Html {
                text_body,
                tokens,
                html_tokens,
            } => {
                let word_tokenizer = WordStemTokenizer::new(text_body);

                for token in tokens {
                    self.insert_type(&word_tokenizer, token, is_body);
                }

                if is_body {
                    if tokens.is_empty()
                        || !tokens.iter().any(|t| matches!(t, TokenType::Alphabetic(_)))
                    {
                        self.insert(Token::Word {
                            value: "_null".into(),
                        });
                    }

                    for token in html_tokens {
                        if let HtmlToken::StartTag {
                            name: A | IMG,
                            attributes,
                            ..
                        } = token
                        {
                            for (name, value) in attributes {
                                match (*name, value) {
                                    (ALT | TITLE, Some(value)) => {
                                        for token in TypesTokenizer::new(value) {
                                            self.insert_type(&word_tokenizer, &token.word, is_body);
                                        }
                                    }
                                    (SRC, Some(value)) => {
                                        self.insert(Token::HtmlImage {
                                            src: value.split_once(':').unwrap_or_default().0,
                                        });
                                    }
                                    (HREF, Some(value)) => {
                                        self.insert(Token::HtmlAnchor {
                                            href: value.split_once(':').unwrap_or_default().0,
                                        });
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            TextPart::None => (),
        }
    }

    fn insert_type<T: AsRef<str>, E, U, I>(
        &mut self,
        word_tokenizer: &WordStemTokenizer,
        token: &TokenType<T, E, U, I>,
        is_body: bool,
    ) {
        match token {
            TokenType::Alphabetic(word) => {
                let word = word.as_ref();
                let mut set: Option<AugmentedScriptSet> = None;
                let mut has_confusables = false;
                let mut upper_count = 0;
                for ch in word.chars() {
                    if ch.is_uppercase() {
                        upper_count += 1;
                    }

                    has_confusables |=
                        !ch.is_ascii() && !std::iter::once(ch).nfc().eq(std::iter::once(ch).nfkc());
                    set.get_or_insert_default().intersect_with(ch.into());
                }
                let is_mixed_script = set.is_some_and(|set| set.is_empty());

                if (is_mixed_script || has_confusables)
                    && let Ok(cured_word) = decancer::cure(word, decancer::Options::default())
                {
                    if word.len() > MAX_TOKEN_LENGTH {
                        self.insert(Token::Word {
                            value: truncate_word(cured_word.as_str(), MAX_TOKEN_LENGTH)
                                .to_string()
                                .into(),
                        });
                    } else {
                        self.insert(Token::Word {
                            value: String::from(cured_word).into(),
                        });
                    }
                } else {
                    let word = word.to_lowercase();
                    word_tokenizer.tokenize(&word, |token| {
                        self.insert(Token::Word {
                            value: truncate_word(token.as_ref(), MAX_TOKEN_LENGTH)
                                .to_string()
                                .into(),
                        });
                    });
                }

                if is_body && word.len() == upper_count && word.len() > 3 {
                    self.insert(Token::Word {
                        value: "_allcaps".into(),
                    });
                }
            }
            TokenType::Alphanumeric(word) => {
                self.insert(Token::from_alphanumeric(word.as_ref()));
            }
            TokenType::UrlNoHost(url) => {
                for token in url
                    .as_ref()
                    .to_lowercase()
                    .split(['/', '.', '_'])
                    .filter(|v| v.chars().all(|ch| ch.is_alphabetic()))
                {
                    if token.len() > 2 {
                        let token = truncate_word(token, MAX_TOKEN_LENGTH);
                        self.insert(Token::Url {
                            value: format!("_{token}").into(),
                        });
                    }
                }
            }
            TokenType::Other(ch) | TokenType::Punctuation(ch) => {
                let category = get_general_category(*ch);
                if !matches!(
                    category,
                    GeneralCategory::ClosePunctuation
                        | GeneralCategory::ConnectorPunctuation
                        | GeneralCategory::DashPunctuation
                        | GeneralCategory::FinalPunctuation
                        | GeneralCategory::InitialPunctuation
                        | GeneralCategory::OpenPunctuation
                        | GeneralCategory::OtherPunctuation
                        | GeneralCategory::SpaceSeparator
                ) {
                    self.insert(Token::UnicodeCategory {
                        value: category.abbreviation(),
                    });
                }
            }
            TokenType::Integer(word) => {
                self.insert(Token::from_number(false, word.as_ref()));
            }
            TokenType::Float(word) => {
                self.insert(Token::from_number(true, word.as_ref()));
            }
            TokenType::IpAddr(_) => {
                self.insert(Token::Url {
                    value: "!ip".into(),
                });
            }
            TokenType::Email(_)
            | TokenType::Url(_)
            | TokenType::UrlNoScheme(_)
            | TokenType::Space => {}
        }
    }

    fn insert(&mut self, token: Token<'x>) {
        *self.0.entry(token).or_insert(0.0) += 1.0;
    }

    fn insert_if_missing(&mut self, token: Token<'x>) {
        self.0.entry(token).or_insert(1.0);
    }

    fn insert_email(&mut self, email: &'x Email, is_sender: bool) {
        if !email.address.is_empty() {
            if is_sender {
                self.insert_if_missing(Token::Sender {
                    value: email.address.as_str().into(),
                });
                self.insert_if_missing(Token::Sender {
                    value: email.domain_part.fqdn.as_str().into(),
                });
                if let Some(sld) = &email.domain_part.sld
                    && sld != &email.domain_part.fqdn
                {
                    self.insert_if_missing(Token::Sender { value: sld.into() });
                }
            } else {
                self.insert_if_missing(Token::Email {
                    value: email.address.as_str().into(),
                });
                self.insert_if_missing(Token::Email {
                    value: email.domain_part.fqdn.as_str().into(),
                });
                if let Some(sld) = &email.domain_part.sld
                    && !sld.is_empty()
                    && sld != &email.domain_part.fqdn
                {
                    self.insert_if_missing(Token::Email { value: sld.into() });
                }
            }
        }
    }
}

impl Token<'static> {
    fn from_alphanumeric(s: &str) -> Self {
        let mut is_hex = true;
        let mut is_ascii = true;
        let mut digit_count = 0;

        for ch in s.chars() {
            match ch {
                'a'..='f' | 'A'..='F' => {}
                '0'..='9' => {
                    digit_count += 1;
                }
                _ => {
                    is_ascii &= ch.is_ascii();
                    is_hex = false;
                }
            }
        }

        if is_hex {
            Token::Number {
                code: [b'X', s.len().min(u8::MAX as usize) as u8],
            }
        } else if !is_ascii {
            let word: String = if let Ok(cured) = decancer::cure(s, decancer::Options::default()) {
                cured
                    .as_str()
                    .chars()
                    .filter(|ch| ch.is_alphabetic())
                    .take(MAX_TOKEN_LENGTH)
                    .collect()
            } else {
                s.chars()
                    .filter(|ch| ch.is_alphabetic())
                    .flat_map(|ch| ch.to_lowercase())
                    .take(MAX_TOKEN_LENGTH)
                    .collect()
            };

            Token::Word { value: word.into() }
        } else if s.len() > 3 && digit_count == 1 {
            let word: String = s
                .chars()
                .filter(|ch| ch.is_alphabetic())
                .flat_map(|ch| ch.to_lowercase())
                .take(MAX_TOKEN_LENGTH)
                .collect();
            Token::Word { value: word.into() }
        } else {
            // Character class counts
            let mut upper = 0u32;
            let mut lower = 0u32;
            let mut digit = 0u32;
            let mut len = 0;
            let mut char_types = Vec::with_capacity(len);
            for c in s.chars() {
                let char_type = CharType::from_char(c);
                char_types.push(char_type);
                match char_type {
                    CharType::Upper => upper += 1,
                    CharType::Lower => lower += 1,
                    CharType::Digit => digit += 1,
                    CharType::Other => (),
                }
                len += 1;
            }

            // Determine dominant composition
            let composition = match (upper > 0, lower > 0, digit > 0) {
                (true, false, false) => b'U',  // UPPERCASE only
                (false, true, false) => b'L',  // lowercase only
                (false, false, true) => b'D',  // digits only
                (true, true, false) => b'A',   // Alphabetic mixed case
                (true, false, true) => b'H',   // Upper + digits (common in codes)
                (false, true, true) => b'M',   // lower + digits (common in identifiers)
                (true, true, true) => b'X',    // eXtreme mix - all three
                (false, false, false) => b'E', // empty/invalid
            };

            // Length bucket (log-ish scale)
            let len_code = match len {
                1 => b'1',
                2 => b'2',
                3 => b'3',
                4 => b'4',
                5..=6 => b'5',
                7..=8 => b'6',
                9..=12 => b'7',
                13..=16 => b'8',
                17..=32 => b'9',
                _ => b'Z',
            };

            // Ratio encoding (which class dominates)
            let max_count = upper.max(lower).max(digit);
            let dominance = (max_count * 100) / len.min(1) as u32;
            let ratio = match dominance {
                0..=50 => b'B',  // Balanced
                51..=75 => b'P', // Partial dominance
                76..=99 => b'D', // Dominant
                _ => b'O',       // One class only (100%)
            };

            // Run code
            let mut run_count = 0;
            if len > 1 {
                let mut prev_type = char_types[0];
                for &current_type in char_types.iter().skip(1) {
                    if current_type != prev_type {
                        run_count += 1;
                        prev_type = current_type;
                    }
                }
            }
            let run_ratio = (run_count as f64) / ((len - 1) as f64);
            let run_code = match run_ratio {
                r if r <= 0.1 => b'0', // Very long runs (e.g., AAAABBBB)
                r if r <= 0.3 => b'1', // Moderate runs
                r if r <= 0.5 => b'2', // Balanced runs/alternation
                r if r <= 0.7 => b'3', // High alternation
                _ => b'4',             // Near maximum alternation (e.g., A1A1A1)
            };

            Token::Alphanumeric {
                code: [composition, len_code, ratio, run_code],
            }
        }
    }

    fn from_number(is_float: bool, num: &str) -> Self {
        Token::Number {
            code: [
                if num.starts_with("-") {
                    if is_float { b'F' } else { b'I' }
                } else if is_float {
                    b'f'
                } else {
                    b'i'
                },
                num.as_bytes()
                    .iter()
                    .filter(|c| c.is_ascii_digit())
                    .count()
                    .min(u8::MAX as usize) as u8,
            ],
        }
    }
}

fn lower_prefix(prefix: &str, value: &str) -> String {
    let mut result = String::with_capacity(prefix.len() + value.len());
    result.push_str(prefix);
    for ch in value.chars() {
        for lower_ch in ch.to_lowercase() {
            result.push(lower_ch);
        }
    }
    result
}

fn truncate_word(word: &str, max_len: usize) -> &str {
    if word.len() <= max_len {
        word
    } else {
        let mut pos = 0;
        for (count, (idx, _)) in word.char_indices().enumerate() {
            pos = idx;
            if count == max_len {
                break;
            }
        }
        &word[..pos]
    }
}

impl UnprocessedFeature for Token<'_> {
    fn prefix(&self) -> u16 {
        match self {
            Token::Word { .. } => 0,
            Token::Number { .. } => 1,
            Token::Alphanumeric { .. } => 2,
            Token::UnicodeCategory { .. } => 3,
            Token::Sender { .. } => 4,
            Token::Asn { .. } => 5,
            Token::Url { .. } => 6,
            Token::Email { .. } => 7,
            Token::Hostname { .. } => 8,
            Token::Attachment { .. } => 9,
            Token::MimeType { .. } => 10,
            Token::HtmlImage { .. } => 11,
            Token::HtmlAnchor { .. } => 12,
        }
    }

    fn value(&self) -> &[u8] {
        match self {
            Token::Word { value } => value.as_bytes(),
            Token::Number { code } => code,
            Token::Alphanumeric { code } => code,
            Token::UnicodeCategory { value } => value.as_bytes(),
            Token::Sender { value } => value.as_bytes(),
            Token::Asn { number } => number,
            Token::Url { value } => value.as_bytes(),
            Token::Email { value } => value.as_bytes(),
            Token::Hostname { value } => value.as_bytes(),
            Token::Attachment { value } => value.as_bytes(),
            Token::MimeType { value } => value.as_bytes(),
            Token::HtmlImage { src } => src.as_bytes(),
            Token::HtmlAnchor { href } => href.as_bytes(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum CharType {
    Upper,
    Lower,
    Digit,
    Other,
}

impl CharType {
    fn from_char(c: char) -> CharType {
        match c {
            'A'..='Z' => CharType::Upper,
            'a'..='z' => CharType::Lower,
            '0'..='9' => CharType::Digit,
            _ => CharType::Other,
        }
    }
}

impl<'x> Default for Tokens<'x> {
    fn default() -> Self {
        Tokens(HashMap::with_capacity(128))
    }
}
