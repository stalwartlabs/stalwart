/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::analysis::domain::SpamFilterAnalyzeDomain;
use crate::analysis::init::SpamFilterInit;
use crate::analysis::is_trusted_domain;
use crate::analysis::url::{SpamFilterAnalyzeUrl, UrlParsed};
use crate::modules::html::{A, ALT, HREF, HtmlToken, IMG, SRC, TITLE};
use crate::{Email, SpamFilterContext, TextPart};
use crate::{Hostname, SpamFilterInput};
use common::config::mailstore::spamfilter;
use common::manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY};
use common::{Server, config::mailstore::spamfilter::Location, ipc::BroadcastEvent};
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
use registry::schema::prelude::{ObjectType, Property};
use registry::schema::structs::SpamTrainingSample;
use registry::types::EnumImpl;
use std::time::Instant;
use std::{
    borrow::Cow,
    collections::{HashMap, hash_map::Entry},
    hash::{Hash, RandomState},
    sync::Arc,
};
use store::ahash::{AHashMap, AHashSet};
use store::rand::seq::SliceRandom;
use store::write::{ArchiveCompression, BlobLink, Compression, RegistryClass, now};
use store::{
    Deserialize, IterateParams, Serialize, ValueKey,
    write::{
        Archive, ArchiveBytes, Archiver, BatchBuilder, BlobOp, ValueClass,
        key::DeserializeBigEndian,
    },
};
use store::{SerializeInfallible, U16_LEN};
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

#[derive(
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    Clone,
    PartialEq,
    Eq,
    Debug,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct TrainingSample {
    hash: BlobHash,
    account_id: u32,
}

#[derive(Debug)]
struct TrainingTask {
    id: u64,
    sample: TrainingSample,
    is_spam: bool,
    is_replay: bool,
    remove: Option<u64>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug)]
pub struct SpamTrainer {
    pub trainer: SpamTrainerClass,
    pub reservoir: SampleReservoir<TrainingSample>,
    pub last_id: u64,
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
                    Some(archive) => <Archive<ArchiveBytes> as Deserialize>::deserialize(&archive)
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
                last_id: 0,
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
        let mut duplicate_samples = Vec::new();
        let mut remove_entries = false;
        let object_id = ObjectType::SpamTrainingSample.to_id();
        let from_key = ValueKey::from(ValueClass::Registry(RegistryClass::Item {
            object_id,
            item_id: trainer.last_id + 1,
        }));
        let to_key = ValueKey::from(ValueClass::Registry(RegistryClass::Item {
            object_id,
            item_id: u64::MAX,
        }));
        let mut seen_samples = AHashSet::new();
        let mut spam_count = 0;
        let mut ham_count = 0;
        self.store()
            .iterate(
                IterateParams::new(from_key, to_key).descending(),
                |key, value| {
                    let id = key.deserialize_be_u64(U16_LEN)?;
                    let sample = SpamTrainingSample::deserialize(value)?;

                    let until = sample.expires_at.timestamp() as u64;
                    let do_remove = sample.delete_after_use;
                    let is_spam = sample.is_spam;
                    let sample = TrainingSample {
                        hash: sample.blob_id.hash,
                        account_id: sample
                            .account_id
                            .map(|a| a.document_id())
                            .unwrap_or(u32::MAX),
                    };

                    if seen_samples.insert(sample.clone()) {
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
                            id,
                            sample,
                            is_spam,
                            is_replay: false,
                            remove: do_remove.then_some(until),
                        });

                        remove_entries |= do_remove;

                        // Update trainer stats
                        if is_spam {
                            spam_count += 1;
                        } else {
                            ham_count += 1;
                        }
                    } else {
                        duplicate_samples.push(TrainingTask {
                            id,
                            sample,
                            is_spam,
                            is_replay: false,
                            remove: Some(until),
                        });
                        remove_entries = true;
                    }

                    if trainer.last_id == 0 {
                        trainer.last_id = id;
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

            return if duplicate_samples.is_empty() {
                Ok(())
            } else {
                delete_samples(self, samples, duplicate_samples).await
            };
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

            return if duplicate_samples.is_empty() {
                Ok(())
            } else {
                delete_samples(self, samples, duplicate_samples).await
            };
        }

        // Balance classes if needed
        if spam_count > ham_count {
            // We have too much spam this time. We need to replay old HAM.
            samples.extend(
                trainer
                    .reservoir
                    .replay_samples((spam_count - ham_count) as usize, false)
                    .map(|sample| TrainingTask {
                        id: 0,
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
                        id: 0,
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
                let Some(message) = MessageParser::new().parse(&raw_message) else {
                    if sample.is_replay {
                        trainer
                            .reservoir
                            .remove_sample(&sample.sample, sample.is_spam);
                    }
                    trc::event!(
                        Spam(SpamEvent::TrainSampleNotFound),
                        Reason = "Failed to parse message",
                        AccountId = account_id,
                        BlobId = sample.sample.hash.to_hex(),
                    );
                    continue;
                };
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
        let (trainer_bytes, classifier_bytes, classifier) =
            tokio::task::spawn_blocking(move || {
                let trainer_bytes = Archiver::new(trainer).serialize();
                let classifier_bytes = classifier.serialize();
                (trainer_bytes, classifier_bytes, classifier)
            })
            .await
            .map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .details("Spam model serialization failed")
                    .caused_by(trc::location!())
            })?;

        self.blob_store()
            .put_blob(
                SPAM_TRAINER_KEY,
                &trainer_bytes.caused_by(trc::location!())?,
                self.core.email.compression,
            )
            .await
            .caused_by(trc::location!())?;
        self.blob_store()
            .put_blob(
                SPAM_CLASSIFIER_KEY,
                &classifier_bytes.caused_by(trc::location!())?,
                self.core.email.compression,
            )
            .await
            .caused_by(trc::location!())?;

        self.inner
            .data
            .spam_classifier
            .store(Arc::new(classifier.inner));
        self.cluster_broadcast(BroadcastEvent::reload(ObjectType::SpamClassifier))
            .await;

        trc::event!(
            Spam(SpamEvent::TrainCompleted),
            Total = num_samples,
            Details = vec![trc::Value::from(ham_count), trc::Value::from(spam_count)],
            Elapsed = started.elapsed()
        );

        // Remove samples marked for deletion
        if remove_entries {
            delete_samples(self, samples, duplicate_samples).await
        } else {
            Ok(())
        }
    }

    async fn spam_classify(&self, ctx: &mut SpamFilterContext<'_>) -> trc::Result<()> {
        let classifier = self.inner.data.spam_classifier.load_full();
        let Some(config) = &self.core.spam.classifier else {
            return Ok(());
        };

        let started = Instant::now();
        match classifier.as_ref() {
            spamfilter::SpamClassifier::FhClassifier { classifier, .. } => {
                let mut classifier_confidence =
                    Vec::with_capacity(ctx.input.env_rcpt_rewritten_to.len());
                let mut has_prediction = false;
                let mut tokens = self.spam_build_tokens(ctx).await.0;
                let feature_builder = classifier.feature_builder();
                if config.log_scale {
                    feature_builder.scale(&mut tokens);
                }

                for rcpt in &ctx.input.env_rcpt_rewritten_to {
                    let prediction = if let Some(account_id) = self
                        .account_id_from_email(rcpt, true)
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
                        vec![prediction.into(); ctx.input.env_rcpt_rewritten_to.len()];
                }
            }
            spamfilter::SpamClassifier::CcfhClassifier { classifier, .. } => {
                let mut classifier_confidence =
                    Vec::with_capacity(ctx.input.env_rcpt_rewritten_to.len());
                let mut has_prediction = false;
                let mut tokens = self.spam_build_tokens(ctx).await.0;
                let feature_builder = classifier.feature_builder();
                if config.log_scale {
                    feature_builder.scale(&mut tokens);
                }

                for rcpt in &ctx.input.env_rcpt_rewritten_to {
                    let prediction = if let Some(account_id) = self
                        .account_id_from_email(rcpt, true)
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
                        vec![prediction.into(); ctx.input.env_rcpt_rewritten_to.len()];
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
                .zip(ctx.input.env_rcpt_rewritten_to.iter())
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
        let builder = spam_collect_tokens(ctx);
        let mut checked = AHashSet::new();
        let mut trusted: AHashSet<String> = AHashSet::new();
        for domain in builder.trust_domains() {
            if checked.insert(domain) && is_trusted_domain(self, domain, ctx.input.span_id).await {
                trusted.insert(domain.to_string());
            }
        }
        drop(checked);

        builder.finish(|domain| trusted.contains(domain))
    }
}

pub struct TokenBuilder<'x> {
    tokens: Tokens<'x>,
    alt_tokens: Tokens<'x>,
    emails: Vec<&'x Email>,
    urls: Vec<&'x UrlParsed>,
    hosts: Vec<Hostname>,
}

impl<'x> TokenBuilder<'x> {
    pub fn trust_domains(&self) -> impl Iterator<Item = &str> {
        self.emails
            .iter()
            .map(|email| email.domain_part.sld_or_default())
            .chain(self.urls.iter().map(|url| url.host.sld_or_default()))
            .chain(self.hosts.iter().map(|host| host.sld_or_default()))
    }

    pub fn finish(self, is_trusted: impl Fn(&str) -> bool) -> Tokens<'x> {
        let TokenBuilder {
            mut tokens,
            alt_tokens,
            emails,
            urls,
            hosts,
        } = self;

        for email in emails {
            if !is_trusted(email.domain_part.sld_or_default()) {
                tokens.insert_email(email, false);
            }
        }

        for url in urls {
            if !is_trusted(url.host.sld_or_default()) {
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
                        tokens.insert(Token::Url {
                            value: concat_word("_", truncate_word(token, MAX_TOKEN_LENGTH)).into(),
                        });
                    }
                }
            }
        }

        for host in hosts {
            let host_sld = host.sld_or_default();

            if !is_trusted(host_sld) {
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

pub fn spam_collect_tokens<'x>(ctx: &'x SpamFilterContext<'_>) -> TokenBuilder<'x> {
    let mut tokens = Tokens::default();
    let mut emails = Vec::new();
    let mut urls = Vec::new();
    let mut hosts = Vec::new();

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

        if is_sender {
            tokens.insert_email(&email.element.email, true);
        } else {
            emails.push(&email.element.email);
        }
    }

    // Add URLs
    for url in &ctx.output.urls {
        if let Some(url) = &url.element.url_parsed {
            urls.push(url);
        }
    }

    // Add hostnames
    for domain in &ctx.output.domains {
        if matches!(
            domain.location,
            Location::HeaderReceived | Location::HeaderMid | Location::Ehlo | Location::Tcp
        ) {
            hosts.push(Hostname::new(&domain.element));
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
                            value: concat_word(
                                "_",
                                truncate_word(token.as_ref(), MAX_TOKEN_LENGTH),
                            )
                            .into(),
                        });
                    });
                }
            }
        }

        if let Some(ct) = part.content_type() {
            let mut ct_lower = String::with_capacity(
                ct.c_type.len() + ct.c_subtype.as_ref().map_or(0, |s| s.len() + 1),
            );
            ct_lower.push_str(ct.c_type.as_ref());
            if let Some(st) = &ct.c_subtype {
                ct_lower.push('/');
                ct_lower.push_str(st.as_ref());
            }
            ct_lower.make_ascii_lowercase();

            tokens.insert(Token::MimeType { value: ct_lower });
        }
    }

    // Tokenize the subject
    if !ctx.output.subject_tokens.is_empty() {
        let subject_tokenizer = WordStemTokenizer::new(&ctx.output.subject_thread_lc);
        for token in &ctx.output.subject_tokens {
            tokens.insert_type(&subject_tokenizer, token, false);
        }
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

    TokenBuilder {
        tokens,
        alt_tokens,
        emails,
        urls,
        hosts,
    }
}

async fn delete_samples(
    server: &Server,
    samples: Vec<TrainingTask>,
    duplicate_samples: Vec<TrainingTask>,
) -> trc::Result<()> {
    let object_id = ObjectType::SpamTrainingSample.to_id();
    let mut batch = BatchBuilder::new();
    for sample in samples.into_iter().chain(duplicate_samples) {
        if let Some(until) = sample.remove {
            batch
                .with_account_id(sample.sample.account_id)
                .clear(BlobOp::Link {
                    hash: sample.sample.hash,
                    to: BlobLink::Temporary { until },
                })
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id: sample.id,
                }))
                .clear(ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId.to_id(),
                    object_id,
                    item_id: sample.id,
                    key: (sample.sample.account_id as u64).serialize(),
                }));

            if batch.is_large_batch() {
                server
                    .store()
                    .write_batch(&mut batch)
                    .await
                    .caused_by(trc::location!())?;
                batch = BatchBuilder::new();
                batch.with_account_id(sample.sample.account_id);
            }
        }
    }
    if !batch.is_empty() {
        server
            .store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
    }
    Ok(())
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

pub const MAX_TOKEN_LENGTH: usize = 16;

const ASCII_CASE_BUF: usize = 64;

const EXACT_F32_INTEGERS: f64 = 16_777_216.0;

struct WordCounts<'x>(AHashMap<&'x str, u32>);

impl<'x> WordCounts<'x> {
    fn with_capacity(tokens: usize) -> Self {
        WordCounts(AHashMap::with_capacity(tokens.div_ceil(8)))
    }

    #[inline(always)]
    fn push(&mut self, word: &'x str) {
        let count = self.0.entry(word).or_insert(0);
        *count = count.saturating_add(1);
    }
}

const ASCII_IGNORED_CATEGORY: u128 = ascii_ignored_category_mask();

const fn ascii_ignored_category_mask() -> u128 {
    let chars = b" !\"#%&'()*,-./:;?@[\\]_{}";
    let mut mask = 0u128;
    let mut idx = 0;
    while idx < chars.len() {
        mask |= 1u128 << chars[idx];
        idx += 1;
    }
    mask
}

#[inline(always)]
fn is_ascii_ignored_category(ch: char) -> bool {
    let code = ch as u32;
    code < 128 && ASCII_IGNORED_CATEGORY & (1u128 << code) != 0
}

#[inline(always)]
fn ascii_lowercase<'a>(word: &str, buf: &'a mut [u8; ASCII_CASE_BUF]) -> Cow<'a, str> {
    if let Some(slot) = buf.get_mut(..word.len()) {
        for (out, &byte) in slot.iter_mut().zip(word.as_bytes()) {
            *out = byte.to_ascii_lowercase();
        }
        if let Ok(text) = std::str::from_utf8(slot) {
            return Cow::Borrowed(text);
        }
    }
    Cow::Owned(word.to_ascii_lowercase())
}

fn lowercase(text: &str) -> Cow<'_, str> {
    if text.is_ascii() {
        if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(text.to_ascii_lowercase())
        } else {
            Cow::Borrowed(text)
        }
    } else {
        Cow::Owned(text.to_lowercase())
    }
}

fn concat_word(prefix: &str, word: &str) -> String {
    let mut value = String::with_capacity(prefix.len() + word.len());
    value.push_str(prefix);
    value.push_str(word);
    value
}

#[inline(always)]
fn stem_value(stem: Cow<'_, str>) -> Cow<'_, str> {
    match stem {
        Cow::Borrowed(text) => Cow::Borrowed(truncate_word(text, MAX_TOKEN_LENGTH)),
        Cow::Owned(text) if text.len() <= MAX_TOKEN_LENGTH => Cow::Owned(text),
        Cow::Owned(text) => Cow::Owned(truncate_word(&text, MAX_TOKEN_LENGTH).to_string()),
    }
}

#[inline(always)]
fn owned_stem_value(stem: Cow<'_, str>) -> Cow<'static, str> {
    match stem {
        Cow::Owned(text) if text.len() <= MAX_TOKEN_LENGTH => Cow::Owned(text),
        other => Cow::Owned(truncate_word(other.as_ref(), MAX_TOKEN_LENGTH).to_string()),
    }
}

enum WordType<'x> {
    Alphabetic(&'x str),
    Alphanumeric(&'x str),
    UrlNoHost(&'x str),
    Integer(&'x str),
    Float(&'x str),
    Char(char),
    IpAddr,
}

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
    pub fn insert_text_part(&mut self, part: &'x TextPart<'x>, is_body: bool) {
        match part {
            TextPart::Plain { text_body, tokens } => {
                let word_tokenizer = WordStemTokenizer::new(text_body);
                let mut words = WordCounts::with_capacity(tokens.len());

                for token in tokens {
                    self.insert_counted(&word_tokenizer, &mut words, token, is_body);
                }

                if is_body
                    && (tokens.is_empty()
                        || !tokens.iter().any(|t| matches!(t, TokenType::Alphabetic(_))))
                {
                    self.insert(Token::Word {
                        value: "_null".into(),
                    });
                }

                self.flush_words(&word_tokenizer, words, is_body);
            }
            TextPart::Html {
                text_body,
                tokens,
                html_tokens,
            } => {
                let word_tokenizer = WordStemTokenizer::new(text_body);
                let mut words = WordCounts::with_capacity(tokens.len());

                for token in tokens {
                    self.insert_counted(&word_tokenizer, &mut words, token, is_body);
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
                                            if let TokenType::Alphabetic(word) = token.word {
                                                words.push(word);
                                            } else {
                                                self.insert_type_str(
                                                    &word_tokenizer,
                                                    &token.word,
                                                    is_body,
                                                );
                                            }
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

                self.flush_words(&word_tokenizer, words, is_body);
            }
            TextPart::None => (),
        }
    }

    fn insert_counted<T: AsRef<str>, E, U, I>(
        &mut self,
        word_tokenizer: &WordStemTokenizer,
        words: &mut WordCounts<'x>,
        token: &'x TokenType<T, E, U, I>,
        is_body: bool,
    ) {
        if let TokenType::Alphabetic(word) = token {
            words.push(word.as_ref());
        } else {
            self.insert_type(word_tokenizer, token, is_body);
        }
    }

    fn flush_words(
        &mut self,
        word_tokenizer: &WordStemTokenizer,
        words: WordCounts<'x>,
        is_body: bool,
    ) {
        self.0.reserve(words.0.len());
        for (word, count) in words.0 {
            self.insert_alphabetic(word_tokenizer, word, is_body, count);
        }
    }

    pub fn insert_type<T: AsRef<str>, E, U, I>(
        &mut self,
        word_tokenizer: &WordStemTokenizer,
        token: &'x TokenType<T, E, U, I>,
        is_body: bool,
    ) {
        let word = match token {
            TokenType::Alphabetic(word) => WordType::Alphabetic(word.as_ref()),
            TokenType::Alphanumeric(word) => WordType::Alphanumeric(word.as_ref()),
            TokenType::UrlNoHost(url) => WordType::UrlNoHost(url.as_ref()),
            TokenType::Integer(word) => WordType::Integer(word.as_ref()),
            TokenType::Float(word) => WordType::Float(word.as_ref()),
            TokenType::Other(ch) | TokenType::Punctuation(ch) => WordType::Char(*ch),
            TokenType::IpAddr(_) => WordType::IpAddr,
            TokenType::Email(_)
            | TokenType::Url(_)
            | TokenType::UrlNoScheme(_)
            | TokenType::Space => return,
        };
        self.insert_word_type(word_tokenizer, word, is_body);
    }

    pub fn insert_type_str<E, U, I>(
        &mut self,
        word_tokenizer: &WordStemTokenizer,
        token: &TokenType<&'x str, E, U, I>,
        is_body: bool,
    ) {
        let word = match token {
            TokenType::Alphabetic(word) => WordType::Alphabetic(word),
            TokenType::Alphanumeric(word) => WordType::Alphanumeric(word),
            TokenType::UrlNoHost(url) => WordType::UrlNoHost(url),
            TokenType::Integer(word) => WordType::Integer(word),
            TokenType::Float(word) => WordType::Float(word),
            TokenType::Other(ch) | TokenType::Punctuation(ch) => WordType::Char(*ch),
            TokenType::IpAddr(_) => WordType::IpAddr,
            TokenType::Email(_)
            | TokenType::Url(_)
            | TokenType::UrlNoScheme(_)
            | TokenType::Space => return,
        };
        self.insert_word_type(word_tokenizer, word, is_body);
    }

    fn insert_word_type(
        &mut self,
        word_tokenizer: &WordStemTokenizer,
        word: WordType<'x>,
        is_body: bool,
    ) {
        match word {
            WordType::Alphabetic(word) => {
                self.insert_alphabetic(word_tokenizer, word, is_body, 1);
            }
            WordType::Alphanumeric(word) => {
                self.insert(Token::from_alphanumeric(word));
            }
            WordType::UrlNoHost(url) => {
                for token in lowercase(url)
                    .split(['/', '.', '_'])
                    .filter(|v| v.chars().all(|ch| ch.is_alphabetic()))
                {
                    if token.len() > 2 {
                        self.insert(Token::Url {
                            value: concat_word("_", truncate_word(token, MAX_TOKEN_LENGTH)).into(),
                        });
                    }
                }
            }
            WordType::Char(ch) => {
                if is_ascii_ignored_category(ch) {
                    return;
                }
                let category = get_general_category(ch);
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
            WordType::Integer(word) => {
                self.insert(Token::from_number(false, word));
            }
            WordType::Float(word) => {
                self.insert(Token::from_number(true, word));
            }
            WordType::IpAddr => {
                self.insert(Token::Url {
                    value: "!ip".into(),
                });
            }
        }
    }

    fn insert_alphabetic(
        &mut self,
        word_tokenizer: &WordStemTokenizer,
        word: &'x str,
        is_body: bool,
        count: u32,
    ) {
        let bytes = word.as_bytes();
        let mut ascii_bits = 0u8;
        let mut upper_count = 0usize;
        for &byte in bytes {
            ascii_bits |= byte;
            upper_count += usize::from(byte.wrapping_sub(b'A') < 26);
        }

        if ascii_bits < 0x80 {
            if upper_count == 0 {
                word_tokenizer.tokenize(word, |stem| {
                    self.add(
                        Token::Word {
                            value: stem_value(stem),
                        },
                        count,
                    );
                });
                return;
            }

            let mut buf = [0u8; ASCII_CASE_BUF];
            let lower = ascii_lowercase(word, &mut buf);
            word_tokenizer.tokenize(lower.as_ref(), |stem| {
                self.add(
                    Token::Word {
                        value: owned_stem_value(stem),
                    },
                    count,
                );
            });

            if is_body && bytes.len() == upper_count && bytes.len() > 3 {
                self.add(
                    Token::Word {
                        value: "_allcaps".into(),
                    },
                    count,
                );
            }
            return;
        }

        let mut set: Option<AugmentedScriptSet> = None;
        let mut needs_cure = false;
        for ch in word.chars() {
            if !ch.is_ascii() && !std::iter::once(ch).nfc().eq(std::iter::once(ch).nfkc()) {
                needs_cure = true;
                break;
            }
            let set = set.get_or_insert_default();
            set.intersect_with(ch.into());
            if set.is_empty() {
                needs_cure = true;
                break;
            }
        }

        if needs_cure && let Ok(cured_word) = decancer::cure(word, decancer::Options::default()) {
            if word.len() > MAX_TOKEN_LENGTH {
                self.add(
                    Token::Word {
                        value: truncate_word(cured_word.as_str(), MAX_TOKEN_LENGTH)
                            .to_string()
                            .into(),
                    },
                    count,
                );
            } else {
                self.add(
                    Token::Word {
                        value: String::from(cured_word).into(),
                    },
                    count,
                );
            }
        } else {
            let lower = word.to_lowercase();
            word_tokenizer.tokenize(&lower, |stem| {
                self.add(
                    Token::Word {
                        value: owned_stem_value(stem),
                    },
                    count,
                );
            });
        }
    }

    fn add(&mut self, token: Token<'x>, count: u32) {
        let entry = self.0.entry(token).or_insert(0.0);
        if f64::from(*entry) + f64::from(count) <= EXACT_F32_INTEGERS {
            *entry += count as f32;
        } else {
            for _ in 0..count {
                let before = *entry;
                *entry += 1.0;
                if *entry == before {
                    break;
                }
            }
        }
    }

    pub fn insert(&mut self, token: Token<'x>) {
        *self.0.entry(token).or_insert(0.0) += 1.0;
    }

    pub fn insert_if_missing(&mut self, token: Token<'x>) {
        self.0.entry(token).or_insert(1.0);
    }

    pub fn insert_email(&mut self, email: &'x Email, is_sender: bool) {
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
    pub fn from_alphanumeric(s: &str) -> Self {
        let mut is_hex = true;
        let mut is_ascii = true;
        let mut digit_count = 0;

        for &byte in s.as_bytes() {
            match byte {
                b'a'..=b'f' | b'A'..=b'F' => {}
                b'0'..=b'9' => {
                    digit_count += 1;
                }
                _ => {
                    is_ascii &= byte.is_ascii();
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
            let mut word = String::with_capacity(MAX_TOKEN_LENGTH.min(s.len()));
            for &byte in s.as_bytes() {
                if byte.is_ascii_alphabetic() {
                    word.push(byte.to_ascii_lowercase() as char);
                    if word.len() == MAX_TOKEN_LENGTH {
                        break;
                    }
                }
            }
            Token::Word { value: word.into() }
        } else {
            // Character class counts
            let mut upper = 0u32;
            let mut lower = 0u32;
            let mut digit = 0u32;
            let mut run_count = 0u32;
            let mut previous = None;
            let bytes = s.as_bytes();
            let len = bytes.len();
            for &byte in bytes {
                let char_type = CharType::from_byte(byte);
                match char_type {
                    CharType::Upper => upper += 1,
                    CharType::Lower => lower += 1,
                    CharType::Digit => digit += 1,
                    CharType::Other => (),
                }
                if previous.is_some_and(|previous| previous != char_type) {
                    run_count += 1;
                }
                previous = Some(char_type);
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
            let dominance = max_count * 100;
            let ratio = match dominance {
                0..=50 => b'B',  // Balanced
                51..=75 => b'P', // Partial dominance
                76..=99 => b'D', // Dominant
                _ => b'O',       // One class only (100%)
            };

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

    pub fn from_number(is_float: bool, num: &str) -> Self {
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

pub fn lower_prefix(prefix: &str, value: &str) -> String {
    let mut result = String::with_capacity(prefix.len() + value.len());
    result.push_str(prefix);
    if value.is_ascii() {
        let start = result.len();
        result.push_str(value);
        result[start..].make_ascii_lowercase();
    } else {
        for ch in value.chars() {
            for lower_ch in ch.to_lowercase() {
                result.push(lower_ch);
            }
        }
    }
    result
}

#[inline(always)]
pub fn truncate_word(word: &str, max_len: usize) -> &str {
    if word.len() <= max_len {
        word
    } else {
        truncate_word_cold(word, max_len)
    }
}

#[inline(never)]
fn truncate_word_cold(word: &str, max_len: usize) -> &str {
    match word.char_indices().nth(max_len) {
        Some((idx, _)) => &word[..idx],
        None => {
            let last = word.char_indices().next_back().map_or(0, |(idx, _)| idx);
            &word[..last]
        }
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
    #[inline(always)]
    fn from_byte(byte: u8) -> CharType {
        match byte {
            b'A'..=b'Z' => CharType::Upper,
            b'a'..=b'z' => CharType::Lower,
            b'0'..=b'9' => CharType::Digit,
            _ => CharType::Other,
        }
    }
}

impl<'x> Default for Tokens<'x> {
    fn default() -> Self {
        Tokens(HashMap::with_capacity(128))
    }
}

impl ArchiveCompression for SpamTrainer {
    const COMPRESSION: Compression = Compression::Zstd(None);
}

#[cfg(test)]
mod tests {
    use super::{Token, truncate_word};

    #[test]
    fn alphanumeric_codes() {
        for (word, expected) in [
            ("a1", Token::Number { code: [b'X', 2] }),
            ("abc123", Token::Number { code: [b'X', 6] }),
            ("DEADBEEF00", Token::Number { code: [b'X', 10] }),
            ("x1", Token::Alphanumeric { code: *b"M2O4" }),
            ("x", Token::Alphanumeric { code: *b"L1O4" }),
            ("AAAABBBB1111", Token::Number { code: [b'X', 12] }),
            ("XXXXYYYY1111", Token::Alphanumeric { code: *b"H7O0" }),
            ("a1a1a1a1", Token::Number { code: [b'X', 8] }),
            ("x1x1x1x1", Token::Alphanumeric { code: *b"M6O4" }),
            ("abcd1", Token::Number { code: [b'X', 5] }),
            (
                "wxyz1",
                Token::Word {
                    value: "wxyz".into(),
                },
            ),
            ("Win10", Token::Alphanumeric { code: *b"X5O2" }),
        ] {
            assert_eq!(Token::from_alphanumeric(word), expected, "{word:?}");
        }
    }

    #[test]
    fn number_codes_and_truncation() {
        assert_eq!(
            Token::from_number(false, "42"),
            Token::Number { code: [b'i', 2] }
        );
        assert_eq!(
            Token::from_number(false, "-7"),
            Token::Number { code: [b'I', 1] }
        );
        assert_eq!(
            Token::from_number(true, "3.14"),
            Token::Number { code: [b'f', 3] }
        );
        assert_eq!(
            Token::from_number(true, "-0.5"),
            Token::Number { code: [b'F', 2] }
        );
        assert_eq!(
            Token::from_number(false, "1,000"),
            Token::Number { code: [b'i', 4] }
        );
        assert_eq!(truncate_word("abcdef", 16), "abcdef");
        assert_eq!(
            truncate_word("abcdefghijklmnopqrstu", 16),
            "abcdefghijklmnop"
        );
        assert_eq!(truncate_word("\u{e9}\u{e9}\u{e9}", 2), "\u{e9}\u{e9}");
        assert_eq!(truncate_word("\u{e9}\u{e9}\u{e9}", 6), "\u{e9}\u{e9}\u{e9}");
        assert_eq!(truncate_word("\u{e9}\u{e9}\u{e9}", 4), "\u{e9}\u{e9}");
    }
}
