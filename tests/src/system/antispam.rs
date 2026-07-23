/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{jmap::JmapUtils, server::TestServer};
use email::mailbox::{DRAFTS_ID, INBOX_ID, JUNK_ID};
use registry::{
    schema::{
        enums::{Permission, TaskSpamFilterMaintenanceType, TaskStoreMaintenanceType},
        prelude::{ObjectType, Property},
        structs::{
            Permissions, PermissionsList, SpamTrainingSample, Task, TaskSpamFilterMaintenance,
            TaskStatus, TaskStoreMaintenance,
        },
    },
    types::map::Map,
};
use serde_json::json;
use store::write::now;
use types::{id::Id, keyword::Keyword};

pub async fn test(test: &mut TestServer) {
    println!("Running Email Spam classifier tests...");

    // Create test accounts
    let admin = test.account("admin@example.org");
    let account = test
        .create_user_account(
            "admin@example.org",
            "jdoe@example.org",
            "this is a very strong password",
            &[],
            "jdoe@example.org",
        )
        .await;
    let other_account = test
        .create_user_account(
            "admin@example.org",
            "jane@example.org",
            "this is a very strong password",
            &[],
            "jane@example.org",
        )
        .await;
    let client = account.jmap_client().await;
    let account_id = account.id().document_id();

    // Make sure there are no spam training samples
    admin
        .registry_destroy_all(ObjectType::SpamTrainingSample)
        .await;
    assert!(
        admin
            .registry_query(
                ObjectType::SpamTrainingSample,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .ids()
            .next()
            .is_none()
    );

    // Import samples
    let mut spam_ids = vec![];
    let mut ham_ids = vec![];
    for (idx, samples) in [&SPAM, &HAM].into_iter().enumerate() {
        let is_spam = idx == 0;
        for (num, sample) in samples.iter().enumerate() {
            let mut mailbox_ids = vec![];
            let mut keywords = vec![];

            if num == 0 {
                if is_spam {
                    mailbox_ids.push(Id::from(JUNK_ID).to_string());
                    keywords.push(Keyword::Junk.to_string());
                } else {
                    mailbox_ids.push(Id::from(INBOX_ID).to_string());
                    keywords.push(Keyword::NotJunk.to_string());
                }
            } else {
                mailbox_ids.push(Id::from(DRAFTS_ID).to_string());
            }

            let mail_id = client
                .email_import(
                    sample.as_bytes().to_vec(),
                    &mailbox_ids,
                    Some(&keywords),
                    None,
                )
                .await
                .unwrap()
                .take_id();
            if is_spam {
                spam_ids.push(mail_id);
            } else {
                ham_ids.push(mail_id);
            }
        }
    }
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 1);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 1);

    // Other users should no see the training samples
    let samples = other_account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 0);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 0);

    // The admin user should see all training samples
    let samples = admin.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 1);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 1);

    // Train the classifier via JMAP
    for (ids, is_spam) in [(&spam_ids, true), (&ham_ids, false)] {
        for (idx, id) in ids.iter().skip(1).enumerate() {
            // Set keywords and mailboxes
            let mut request = client.build();
            let req = request.set_email().update(id);
            if idx < 5 || !is_spam {
                // Update via keywords
                let keyword = if is_spam {
                    Keyword::Junk
                } else {
                    Keyword::NotJunk
                }
                .to_string();
                req.keywords([&keyword]);
            } else {
                // Update via mailbox
                let mailbox_id = if is_spam { JUNK_ID } else { INBOX_ID };
                req.mailbox_ids([&Id::from(mailbox_id).to_string()]);
            }

            request.send_set_email().await.unwrap().updated(id).unwrap();
        }
    }
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 10);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 10);

    // Make sure the email details are available in the sample
    assert_eq!(samples[0].1.subject, "save up to = on life insurance");
    assert_eq!(samples[0].1.from, "spammy@mcspamface.net");

    // Reclassifying an email should not add a new sample
    let mut request = client.build();
    request
        .set_email()
        .update(&ham_ids[0])
        .keywords([Keyword::Junk.to_string()]);
    request
        .send_set_email()
        .await
        .unwrap()
        .updated(&ham_ids[0])
        .unwrap();

    admin
        .registry_create_object(Task::SpamFilterMaintenance(TaskSpamFilterMaintenance {
            maintenance_type: TaskSpamFilterMaintenanceType::Train,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;

    let samples = account.spam_training_samples().await;
    assert_eq!(samples.len(), 20);
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 9);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 11);
    let hold_for = test
        .server
        .core
        .spam
        .classifier
        .as_ref()
        .unwrap()
        .hold_samples_for;
    assert!(
        hold_for > 2 * 86400,
        "hold for {} should be greater than 2 days",
        hold_for
    );
    let hold_until = now() + hold_for;
    let hold_range = (hold_until - 86400)..=hold_until;

    assert!(samples.iter().all(|(_, s)| {
        s.blob_id.class.account_id() == account_id
            && !s.delete_after_use
            && hold_range.contains(&(s.expires_at.timestamp() as u64))
    }));

    // Purging blobs should not remove training samples
    admin
        .registry_create_object(Task::StoreMaintenance(TaskStoreMaintenance {
            maintenance_type: TaskStoreMaintenanceType::PurgeBlob,
            shard_index: None,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 9);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 11);
    assert_eq!(samples.len(), 20);

    // Adding a training sample without permissions should fail
    assert_eq!(
        account
            .registry_create_many(
                ObjectType::SpamTrainingSample,
                [json!({
                    Property::BlobId: samples[0].1.blob_id.clone(),
                })],
            )
            .await
            .method_response()
            .text_field("type"),
        "forbidden"
    );

    // Update permissions and try again
    admin
        .registry_update_object(
            ObjectType::Account,
            account.id(),
            json!({
                Property::Permissions: Permissions::Merge(PermissionsList {
                    disabled_permissions: Map::default(),
                    enabled_permissions: Map::new(vec![Permission::SysSpamTrainingSampleCreate]),
                })
            }),
        )
        .await;
    let sample_id = account
        .registry_create_many(
            ObjectType::SpamTrainingSample,
            [json!({
                Property::BlobId: samples[0].1.blob_id.clone(),
                Property::IsSpam: true,
            })],
        )
        .await
        .created_id(0);
    let sample = account.registry_get::<SpamTrainingSample>(sample_id).await;
    assert_eq!(sample.subject, "save up to = on life insurance");
    assert_eq!(sample.from, "spammy@mcspamface.net");
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 9);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 12);
    assert_eq!(samples.len(), 21);

    // Delete account
    test.destroy_all_mailboxes(&account).await;
    account
        .registry_destroy_all(ObjectType::SpamTrainingSample)
        .await;
    test.assert_is_empty().await;

    admin.destroy_account(account).await;
    admin.destroy_account(other_account).await;
    test.cleanup().await;
}

pub const SPAM: [&str; 10] = [
    concat!(
        "From: spammy@mcspamface.net\r\n",
        "Subject: save up to = on life insurance\r\n\r\n wh",
        "y spend more than you have to life quote savings e",
        "nsuring your family s financial security is very i",
        "mportant life quote savings makes buying life insu",
        "rance simple and affordable we provide free access",
        " to the very best companies and the lowest rates l",
        "ife quote savings is fast easy and saves you money",
        " let us help you get started with the best values ",
        "in the country on new coverage you can save hundre",
        "ds or even thousands of dollars by requesting a fr",
        "ee quote from lifequote savings our service will t",
        "ake you less than = minutes to complete shop ",
        "and compare save up to = on all types of life",
        " insurance hyperlink click here for your free quot",
        "e protecting your family is the best investment yo",
        "u ll ever make if you are in receipt of this email",
        " in error and or wish to be removed from our list ",
        "hyperlink please click here and type remove if you",
        " reside in any state which prohibits e mail solici",
        "tations for insurance please disregard this email\r\n",
        " \r\n"
    ),
    concat!(
        "Subject: a powerhouse gifting program\r\n\r\nyou don t ",
        "want to miss get in with the founders the major pl",
        "ayers are on this one for once be where the player",
        "s are this is your private invitation experts are ",
        "calling this the fastest way to huge cash flow eve",
        "r conceived leverage = = into = NUM",
        "BER over and over again the question here is you e",
        "ither want to be wealthy or you don t which one ar",
        "e you i am tossing you a financial lifeline and fo",
        "r your sake i hope you grab onto it and hold on ti",
        "ght for the ride of your life testimonials hear wh",
        "at average people are doing their first few days w",
        "e ve received = = in = day and we a",
        "re doing that over and over again q s in al i m a ",
        "single mother in fl and i ve received = NUMBE",
        "R in the last = days d s in fl i was not sure",
        " about this when i sent off my = = pledg",
        "e but i got back = = the very next day l",
        " l in ky i didn t have the money so i found myself",
        " a partner to work this with we have received NUMB",
        "ER = over the last = days i think i made",
        " the right decision don t you k c in fl i pick up ",
        "= = my first day and i they gave me free",
        " leads and all the training you can too j w in ca ",
        "announcing we will close your sales for you and he",
        "lp you get a fax blast immediately upon your entry",
        " you make the money free leads training don t wait",
        " call now fax back to = = = = ",
        "or call = = = = name__________",
        "________________________phone_____________________",
        "______________________ fax________________________",
        "_____________email________________________________",
        "____________ best time to call____________________",
        "_____time zone____________________________________",
        "____ this message is sent in compliance of the new",
        " e mail bill per section = paragraph a =",
        " c of s = further transmissions by the sender",
        " of this email may be stopped at no cost to you by",
        " sending a reply to this email address with the wo",
        "rd remove in the subject line errors omissions and",
        " exceptions excluded this is not spam i have compi",
        "led this list from our replicate database relative",
        " to seattle marketing group the gigt or turbo team",
        " for the sole purpose of these communications your",
        " continued inclusion is only by your gracious perm",
        "ission if you wish to not receive this mail from m",
        "e please send an email to tesrewinter  with rem",
        "ove in the subject and you will be deleted immedia",
        "tely\r\n\r\n"
    ),
    concat!(
        "Subject: help wanted \r\n\r\nwe are a = year old f",
        "ortune = company that is growing at a tremend",
        "ous rate we are looking for individuals who want t",
        "o work from home this is an opportunity to make an",
        " excellent income no experience is required we wil",
        "l train you so if you are looking to be employed f",
        "rom home with a career that has vast opportunities",
        " then go  we are looking for energetic and self",
        " motivated people if that is you than click on the",
        " link and fill out the form and one of our employe",
        "ment specialist will contact you to be removed fro",
        "m our link simple go to  \r\n\r\n"
    ),
    concat!(
        "Subject: tired of the bull out there\r\n\r\n want to st",
        "op losing money want a real money maker receive NU",
        "MBER = = = today experts are callin",
        "g this the fastest way to huge cash flow ever conc",
        "eived a powerhouse gifting program you don t want ",
        "to miss we work as a team this is your private inv",
        "itation get in with the founders this is where the",
        " big boys play the major players are on this one f",
        "or once be where the players are this is a system ",
        "that will drive = = s to your doorstep i",
        "n a short period of time leverage = = in",
        "to = = over and over again the question ",
        "here is you either want to be wealthy or you don t",
        " which one are you i am tossing you a financial li",
        "feline and for your sake i hope you grab onto it a",
        "nd hold on tight for the ride of your life testimo",
        "nials hear what average people are doing their fir",
        "st few days we ve received = = in =",
        " day and we are doing that over and over again q s",
        " in al i m a single mother in fl and i ve received",
        " = = in the last = days d s in fl i",
        " was not sure about this when i sent off my =",
        " = pledge but i got back = = the ve",
        "ry next day l l in ky i didn t have the money so i",
        " found myself a partner to work this with we have ",
        "received = = over the last = days i",
        " think i made the right decision don t you k c in ",
        "fl i pick up = = my first day and i they",
        " gave me free leads and all the training you can t",
        "oo j w in ca this will be the most important call ",
        "you make this year free leads training announcing ",
        "we will close your sales for you and help you get ",
        "a fax blast immediately upon your entry you make t",
        "he money free leads training don t wait call now N",
        "UMBER = = = print and fax to =",
        " = = = or send an email requesting ",
        "more information to successleads  please includ",
        "e your name and telephone number receive = NU",
        "MBER free leads just for responding a = NUMBE",
        "R value name___________________________________ ph",
        "one___________________________________ fax________",
        "_____________________________ email_______________",
        "____________________ this message is sent in compl",
        "iance of the new e mail bill per section = pa",
        "ragraph a = c of s = further transmissio",
        "ns by the sender of this email may be stopped at n",
        "o cost to you by sending a reply to this email add",
        "ress with the word remove in the subject line erro",
        "rs omissions and exceptions excluded this is not s",
        "pam i have compiled this list from our replicate d",
        "atabase relative to seattle marketing group the gi",
        "gt or turbo team for the sole purpose of these com",
        "munications your continued inclusion is only by yo",
        "ur gracious permission if you wish to not receive ",
        "this mail from me please send an email to tesrewin",
        "ter  with remove in the subject and you will be",
        " deleted immediately\r\n\r\n"
    ),
    concat!(
        "Subject: cellular phone accessories \r\n\r\n all at bel",
        "ow wholesale prices http = = = NUMB",
        "ER = sites merchant sales hands free ear buds",
        " = = phone holsters = = booste",
        "r antennas only = = phone cases = N",
        "UMBER car chargers = = face plates as lo",
        "w as = = lithium ion batteries as low as",
        " = = http = = = = NU",
        "MBER sites merchant sales click below for accessor",
        "ies on all nokia motorola lg nextel samsung qualco",
        "mm ericsson audiovox phones at below wholesale pri",
        "ces http = = = = = sites ",
        "merchant sales if you need assistance please call ",
        "us = = = to be removed from future ",
        "mailings please send your remove request to remove",
        " me now =  thank you and have a super day\r\n",
        " \r\n"
    ),
    concat!(
        "Subject: conferencing made easy\r\n\r\n only = cen",
        "ts per minute including long distance no setup fee",
        "s no contracts or monthly fees call anytime from a",
        "nywhere to anywhere connects up to = particip",
        "ants simplicity in set up and administration opera",
        "tor help available = = the highest quali",
        "ty service for the lowest rate in the industry fil",
        "l out the form below to find out how you can lower",
        " your phone bill every month required input field ",
        "name web address company name state business phone",
        " home phone email address type of business to be r",
        "emoved from our distribution lists please hyperlin",
        "k click here\r\n\r\n"
    ),
    concat!(
        "Subject: dear friend\r\n\r\n i am mrs sese seko widow o",
        "f late president mobutu sese seko of zaire now kno",
        "wn as democratic republic of congo drc i am moved ",
        "to write you this letter this was in confidence co",
        "nsidering my presentcircumstance and situation i e",
        "scaped along with my husband and two of our sons g",
        "eorge kongolo and basher out of democratic republi",
        "c of congo drc to abidjan cote d ivoire where my f",
        "amily and i settled while we later moved to settle",
        "d in morroco where my husband later died of cancer",
        " disease however due to this situation we decided ",
        "to changed most of my husband s billions of dollar",
        "s deposited in swiss bank and other countries into",
        " other forms of money coded for safe purpose becau",
        "se the new head of state of dr mr laurent kabila h",
        "as made arrangement with the swiss government and ",
        "other european countries to freeze all my late hus",
        "band s treasures deposited in some european countr",
        "ies hence my children and i decided laying low in ",
        "africa to study the situation till when things get",
        "s better like now that president kabila is dead an",
        "d the son taking over joseph kabila one of my late",
        " husband s chateaux in southern france was confisc",
        "ated by the french government and as such i had to",
        " change my identity so that my investment will not",
        " be traced and confiscated i have deposited the su",
        "m eighteen million united state dollars us = ",
        "= = = with a security company for s",
        "afekeeping the funds are security coded to prevent",
        " them from knowing the content what i want you to ",
        "do is to indicate your interest that you will assi",
        "st us by receiving the money on our behalf acknowl",
        "edge this message so that i can introduce you to m",
        "y son kongolo who has the out modalities for the c",
        "laim of the said funds i want you to assist in inv",
        "esting this money but i will not want my identity ",
        "revealed i will also want to buy properties and st",
        "ock in multi national companies and to engage in o",
        "ther safe and non speculative investments may i at",
        " this point emphasise the high level of confidenti",
        "ality which this business demands and hope you wil",
        "l not betray the trust and confidence which i repo",
        "se in you in conclusion if you want to assist us m",
        "y son shall put you in the picture of the business",
        " tell you where the funds are currently being main",
        "tained and also discuss other modalities including",
        " remunerationfor your services for this reason kin",
        "dly furnish us your contact information that is yo",
        "ur personal telephone and fax number for confident",
        "ial  regards mrs m sese seko\r\n\r\n"
    ),
    concat!(
        "Subject: lowest rates available for term life insu",
        "rance\r\n\r\n take a moment and fill out our online for",
        "m to see the low rate you qualify for save up to N",
        "UMBER from regular rates smokers accepted  repr",
        "esenting quality nationwide carriers act now to ea",
        "sily remove your address from the list go to  p",
        "lease allow = = hours for removal\r\n\r\n"
    ),
    concat!(
        "Subject: central bank of nigeria foreign remittanc",
        "e \r\n\r\n dept tinubu square lagos nigeria email smith",
        "_j  =th of august = attn president ce",
        "o strictly private business proposal i am mr johns",
        "on s abu the bills and exchange director at the fo",
        "reignremittance department of the central bank of ",
        "nigeria i am writingyou this letter to ask for you",
        "r support and cooperation to carrying thisbusiness",
        " opportunity in my department we discovered abando",
        "ned the sumof us = = = = thirt",
        "y seven million four hundred thousand unitedstates",
        " dollars in an account that belong to one of our f",
        "oreign customers an american late engr john creek ",
        "junior an oil merchant with the federal government",
        " of nigeria who died along with his entire family ",
        "of a wifeand two children in kenya airbus a= ",
        "= flight kq= in november= since we ",
        "heard of his death we have been expecting his next",
        " of kin tocome over and put claims for his money a",
        "s the heir because we cannotrelease the fund from ",
        "his account unless someone applies for claims asth",
        "e next of kin to the deceased as indicated in our ",
        "banking guidelines unfortunately neither their fam",
        "ily member nor distant relative hasappeared to cla",
        "im the said fund upon this discovery i and other o",
        "fficialsin my department have agreed to make busin",
        "ess with you release the totalamount into your acc",
        "ount as the heir of the fund since no one came for",
        "it or discovered either maintained account with ou",
        "r bank other wisethe fund will be returned to the ",
        "bank treasury as unclaimed fund we have agreed tha",
        "t our ratio of sharing will be as stated thus NUMB",
        "ER for you as foreign partner and = for us th",
        "e officials in my department upon the successful c",
        "ompletion of this transfer my colleague and i will",
        "come to your country and mind our share it is from",
        " our = we intendto import computer accessorie",
        "s into my country as way of recycling thefund to c",
        "ommence this transaction we require you to immedia",
        "tely indicateyour interest by calling me or sendin",
        "g me a fax immediately on the abovetelefax and enc",
        "lose your private contact telephone fax full namea",
        "nd address and your designated banking co ordinate",
        "s to enable us fileletter of claim to the appropri",
        "ate department for necessary approvalsbefore the t",
        "ransfer can be made note also this transaction mus",
        "t be kept strictly confidential becauseof its natu",
        "re nb please remember to give me your phone and fa",
        "x no mr johnson smith abu irish linux users group ",
        "ilug   for un subscription information list ",
        "maintainer listmaster \r\n\r\n"
    ),
    concat!(
        "Subject: dear stuart\r\n\r\n are you tired of searching",
        " for love in all the wrong places find love now at",
        "   browse through thousands of personals in ",
        "your area join for free  search e mail chat use",
        "  to meet cool guys and hot girls go = on ",
        "= or use our private chat rooms click on the ",
        "link to get started  find love now you have rec",
        "eived this email because you have registerd with e",
        "mailrewardz or subscribed through one of our marke",
        "ting partners if you have received this message in",
        " error or wish to stop receiving these great offer",
        "s please click the remove link above to unsubscrib",
        "e from these mailings please click here \r\n\r\n"
    ),
];

pub const HAM: [&str; 10] = [
    concat!(
        "Message-ID: <mid1@foobar.org>\r\nSubject: i have been",
        " trying to research via sa mirrors and search engi",
        "nes\r\n\r\nif a canned script exists giving clients acce",
        "ss to their user_prefs options via a web based cgi",
        " interface numerous isps provide this feature to c",
        "lients but so far i can find nothing our configura",
        "tion uses amavis postfix and clamav for virus filt",
        "ering and procmail with spamassassin for spam filt",
        "ering i would prefer not to have to write a script",
        " myself but will appreciate any suggestions this U",
        "RL email is sponsored by osdn tired of that same o",
        "ld cell phone get a new here for free  ________",
        "_______________________________________ spamassass",
        "in talk mailing list spamassassin talk  \r\n\r\n"
    ),
    concat!(
        "Message-ID: mid2@foobar.org\r\nSubject: hello\r\n\r\nhave y",
        "ou seen and discussed this article and his approac",
        "h thank you  hell there are no rules here we re",
        " trying to accomplish something thomas alva edison",
        " this  email is sponsored by osdn tired of that",
        " same old cell phone get a new here for free  _",
        "______________________________________________ spa",
        "massassin devel mailing list spamassassin devel UR",
        "L  \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid3@foobar.org>\r\nSubject: hi all apol",
        "ogies for the possible silly question\r\n\r\ni don t thi",
        "nk it is but but is eircom s adsl service nat ed a",
        "nd what implications would that have for voip i kn",
        "ow there are difficulties with voip or connecting ",
        "to clients connected to a nat ed network from the ",
        "internet wild i e machines with static real ips an",
        "y help pointers would be helpful cheers rgrds bern",
        "ard bernard tyers national centre for sensor resea",
        "rch p = = = = e bernard tyers ",
        " w  l n= ______________________________",
        "_________________ iiu mailing list iiu   \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid4@foobar.org>\r\nSubject: can someone",
        " explain\r\n\r\nwhat type of operating system solaris is",
        " as ive never seen or used it i dont know wheather",
        " to get a server from sun or from dell i would pre",
        "fer a linux based server and sun seems to be the o",
        "ne for that but im not sure if solaris is a distro",
        " of linux or a completely different operating syst",
        "em can someone explain kiall mac innes irish linux",
        " users group ilug   for un subscription info",
        "rmation list maintainer listmaster  \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid5@foobar.org>\r\nSubject: folks my fi",
        "rst time posting\r\n\r\nhave a bit of unix experience bu",
        "t am new to linux just got a new pc at home dell b",
        "ox with windows xp added a second hard disk for li",
        "nux partitioned the disk and have installed suse N",
        "UMBER = from cd which went fine except it did",
        "n t pick up my monitor i have a dell branded eNUMB",
        "ERfpp = lcd flat panel monitor and a nvidia g",
        "eforce= ti= video card both of which are",
        " probably too new to feature in suse s default set",
        " i downloaded a driver from the nvidia website and",
        " installed it using rpm then i ran sax= as wa",
        "s recommended in some postings i found on the net ",
        "but it still doesn t feature my video card in the ",
        "available list what next another problem i have a ",
        "dell branded keyboard and if i hit caps lock twice",
        " the whole machine crashes in linux not windows ev",
        "en the on off switch is inactive leaving me to rea",
        "ch for the power cable instead if anyone can help ",
        "me in any way with these probs i d be really grate",
        "ful i ve searched the net but have run out of idea",
        "s or should i be going for a different version of ",
        "linux such as redhat opinions welcome thanks a lot",
        " peter irish linux users group ilug   for un",
        " subscription information list maintainer listmast",
        "er \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid6@foobar.org>\r\nSubject: has anyone\r\n",
        "\r\nseen heard of used some package that would let a ",
        "random person go to a webpage create a mailing lis",
        "t then administer that list also of course let ppl",
        " sign up for the lists and manage their subscripti",
        "ons similar to the old  but i d like to have it",
        " running on my server not someone elses chris  ",
        "\r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid7@foobar.org>\r\nSubject: hi thank yo",
        "u for the useful replies\r\n\r\ni have found some intere",
        "sting tutorials in the ibm developer connection UR",
        "L and  registration is needed i will post the s",
        "ame message on the web application security list a",
        "s suggested by someone for now i thing i will use ",
        "md= for password checking i will use the appr",
        "oach described in secure programmin fo linux and u",
        "nix how to i will separate the authentication modu",
        "le so i can change its implementation at anytime t",
        "hank you again mario torre please avoid sending me",
        " word or powerpoint attachments see  \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid8@foobar.org>\r\nSubject: hehe sorry\r\n",
        "\r\nbut if you hit caps lock twice the computer crash",
        "es theres one ive never heard before have you trye",
        "d dell support yet i think dell computers prefer r",
        "edhat dell provide some computers pre loaded with ",
        "red hat i dont know for sure tho so get someone el",
        "ses opnion as well as mine original message from i",
        "lug admin  mailto ilug admin  on behalf of p",
        "eter staunton sent = august = = NUM",
        "BER to ilug  subject ilug newbie seeks advice s",
        "use = = folks my first time posting have",
        " a bit of unix experience but am new to linux just",
        " got a new pc at home dell box with windows xp add",
        "ed a second hard disk for linux partitioned the di",
        "sk and have installed suse = = from cd w",
        "hich went fine except it didn t pick up my monitor",
        " i have a dell branded e=fpp = lcd flat ",
        "panel monitor and a nvidia geforce= ti= ",
        "video card both of which are probably too new to f",
        "eature in suse s default set i downloaded a driver",
        " from the nvidia website and installed it using rp",
        "m then i ran sax= as was recommended in some ",
        "postings i found on the net but it still doesn t f",
        "eature my video card in the available list what ne",
        "xt another problem i have a dell branded keyboard ",
        "and if i hit caps lock twice the whole machine cra",
        "shes in linux not windows even the on off switch i",
        "s inactive leaving me to reach for the power cable",
        " instead if anyone can help me in any way with the",
        "se probs i d be really grateful i ve searched the ",
        "net but have run out of ideas or should i be going",
        " for a different version of linux such as redhat o",
        "pinions welcome thanks a lot peter irish linux use",
        "rs group ilug   for un subscription informat",
        "ion list maintainer listmaster  irish linux use",
        "rs group ilug   for un subscription informat",
        "ion list maintainer listmaster \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid9@foobar.org>\r\nSubject: it will fun",
        "ction as a router\r\n\r\nif that is what you wish it eve",
        "n looks like the modem s embedded os is some kind ",
        "of linux being that it has interesting interfaces ",
        "like eth= i don t use it as a router though i",
        " just have it do the absolute minimum dsl stuff an",
        "d do all the really fun stuff like pppoe on my lin",
        "ux box also the manual tells you what the default ",
        "password is don t forget to run pppoe over the alc",
        "atel speedtouch =i as in my case you have to ",
        "have a bridge configured in the router modem s sof",
        "tware this lists your vci values etc also does any",
        "one know if the high end speedtouch with = et",
        "hernet ports can act as a full router or do i stil",
        "l need to run a pppoe stack on the linux box regar",
        "ds vin irish linux users group ilug   for un",
        " subscription information list maintainer listmast",
        "er  irish linux users group ilug   for un",
        " subscription information list maintainer listmast",
        "er  \r\n\r\n"
    ),
    concat!(
        "Message-ID: <mid10@foobar.org>\r\nSubject: all is it ",
        "just me\r\n\r\nor has there been a massive increase in t",
        "he amount of email being falsely bounced around th",
        "e place i ve already received email from a number ",
        "of people i don t know asking why i am sending the",
        "m email these can be explained by servers from rus",
        "sia and elsewhere coupled with the false emails i ",
        "received myself it s really starting to annoy me a",
        "m i the only one seeing an increase in recent week",
        "s martin martin whelan déise design  tel NUMBE",
        "R = our core product déiseditor allows organ",
        "isations to publish information to their web site ",
        "in a fast and cost effective manner there is no ne",
        "ed for a full time web developer as the site can b",
        "e easily updated by the organisations own staff in",
        "stant updates to keep site information fresh sites",
        " which are updated regularly bring users back visi",
        "t  for a demonstration déiseditor managing you",
        "r information ____________________________________",
        "___________ iiu mailing list iiu   ,0\r\n"
    ),
];

pub const TEST: [&str; 3] = [
    concat!(
        "From: spammy@mcspamface.net\r\n",
        "Subject: save up to = on life insurance\r\n\r\nwhy ",
        "spend more than you have to life quote savings ens",
        "uring your family s financial security is very imp",
        "ortant life quote savings makes buying life insura",
        "nce simple and affordable we provide free access t",
        "o the very best companies and the lowest rates lif",
        "e quote savings is fast easy and saves you money l",
        "et us help you get started with the best values in",
        " the country on new coverage you can save hundreds",
        " or even thousands of dollars by requesting a free",
        " quote from lifequote savings our service will tak",
        "e you less than = minutes to complete shop an",
        "d compare save up to = on all types of life i",
        "nsurance hyperlink click here for your free quote ",
        "protecting your family is the best investment you ",
        "ll ever make if you are in receipt of this email i",
        "n error and or wish to be removed from our list hy",
        "perlink please click here and type remove if you r",
        "eside in any state which prohibits e mail solicita",
        "tions for insurance please disregard this email\r\n"
    ),
    concat!(
        "Subject: can someone explain\r\n\r\nwhat type of operati",
        "ng system solaris is as ive never seen or used it ",
        "i dont know wheather to get a server from sun or f",
        "rom dell i would prefer a linux based server and s",
        "un seems to be the one for that but im not sure if",
        " solaris is a distro of linux or a completely diff",
        "erent operating system can someone explain kiall m",
        "ac innes irish linux users group ilug   for ",
        "un subscription information list maintainer listma",
        "ster  \r\n"
    ),
    concat!(
        "Subject: classifier test\r\n\r\nthis is a novel text tha",
        "t the sgd classifier has never seen before, it s",
        "hould be classified as ham or non-ham\r\n"
    ),
];
