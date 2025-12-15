/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{ChangeType, IntoJmapSet, JMAPTest, JmapUtils, wait_for_index},
    webdav::DummyWebDavClient,
};
use ahash::AHashSet;
use calcard::jscontact::JSContactProperty;
use groupware::cache::GroupwareCache;
use hyper::StatusCode;
use jmap_proto::request::method::MethodObject;
use serde_json::{Value, json};
use types::{collection::SyncCollection, id::Id};

pub async fn test(params: &mut JMAPTest) {
    println!("Running Contact Card tests...");
    let account = params.account("jdoe@example.com");

    // Create test address books
    let response = account
        .jmap_create(
            MethodObject::AddressBook,
            [
                json!({
                    "name": "Test #1",
                }),
                json!({
                    "name": "Test #2",
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let book1_id = response.created(0).id().to_string();
    let book2_id = response.created(1).id().to_string();

    // Obtain state
    let change_id = account
        .jmap_get(
            MethodObject::ContactCard,
            Vec::<&str>::new(),
            Vec::<&str>::new(),
        )
        .await
        .state()
        .to_string();

    // Create test contacts
    let sarah_contact = test_jscontact_1().with_property(
        JSContactProperty::<Id>::AddressBookIds,
        [book1_id.as_str()].into_jmap_set(),
    );
    let carlos_contact = test_jscontact_2().with_property(
        JSContactProperty::<Id>::AddressBookIds,
        [book2_id.as_str()].into_jmap_set(),
    );
    let acme_contact = test_jscontact_3().with_property(
        JSContactProperty::<Id>::AddressBookIds,
        [book1_id.as_str(), book2_id.as_str()].into_jmap_set(),
    );
    let tmp_contact = test_jscontact_4().with_property(
        JSContactProperty::<Id>::AddressBookIds,
        [book2_id.as_str()].into_jmap_set(),
    );
    let response = account
        .jmap_create(
            MethodObject::ContactCard,
            [
                sarah_contact.clone(),
                carlos_contact.clone(),
                acme_contact.clone(),
                tmp_contact,
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let sarah_contact_id = response.created(0).id().to_string();
    let carlos_contact_id = response.created(1).id().to_string();
    let acme_contact_id = response.created(2).id().to_string();
    let tmp_contact_id = response.created(3).id().to_string();

    // Destroy tmp contact
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::ContactCard,
                [tmp_contact_id.as_str()],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .destroyed()
            .next(),
        Some(tmp_contact_id.as_str())
    );

    // Validate changes
    assert_eq!(
        account
            .jmap_changes(MethodObject::ContactCard, &change_id)
            .await
            .changes()
            .collect::<AHashSet<_>>(),
        [
            ChangeType::Created(&sarah_contact_id),
            ChangeType::Created(&carlos_contact_id),
            ChangeType::Created(&acme_contact_id)
        ]
        .into_iter()
        .collect::<AHashSet<_>>(),
    );

    // Fetch contacts and verify
    let response = account
        .jmap_get(
            MethodObject::ContactCard,
            Vec::<&str>::new(),
            [&sarah_contact_id, &carlos_contact_id, &acme_contact_id],
        )
        .await;
    response.list()[0].assert_is_equal(
        sarah_contact.with_property(JSContactProperty::<Id>::Id, sarah_contact_id.as_str()),
    );
    response.list()[1].assert_is_equal(
        carlos_contact.with_property(JSContactProperty::<Id>::Id, carlos_contact_id.as_str()),
    );
    response.list()[2].assert_is_equal(
        acme_contact.with_property(JSContactProperty::<Id>::Id, acme_contact_id.as_str()),
    );

    // Creating a contact without address book should fail
    assert_eq!(
        account
            .jmap_create(
                MethodObject::ContactCard,
                [json!({
                    "name": {
                        "full": "Simple Contact",
                    },
                    "addressBookIds": {},
                }),],
                Vec::<(&str, &str)>::new()
            )
            .await
            .not_created(0)
            .description(),
        "Contact has to belong to at least one address book."
    );

    // Creating a contact with a duplicate UID should fail
    assert!(
        account
            .jmap_create(
                MethodObject::ContactCard,
                [json!({
                    "uid": "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                    "name": {
                        "full": "Simple Contact",
                    },
                    "addressBookIds": {
                        &book1_id: true
                    },
                }),],
                Vec::<(&str, &str)>::new()
            )
            .await
            .not_created(0)
            .description()
            .contains(
                "Contact with UID urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6 already exists"
            ),
    );

    // Patching tests
    let response = account
        .jmap_update(
            MethodObject::ContactCard,
            [
                (
                    &sarah_contact_id,
                    json!({
                        "name/full": "Sarah O'Connor",
                        "name/components/0/value": "O'Connor",
                        format!("addressBookIds/{book2_id}"): true
                    }),
                ),
                (
                    &carlos_contact_id,
                    json!({
                        "addressBookIds": {
                            &book1_id: true,
                            &book2_id: true
                        },
                        "nicknames/k1": (),
                        "nicknames/k2": {
                            "name": "Carlitos"
                        },
                    }),
                ),
                (
                    &acme_contact_id,
                    json!({
                        format!("addressBookIds/{book2_id}"): false,
                        "keywords/B2B": false,
                        "keywords/B2C": true,
                    }),
                ),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response.updated(&sarah_contact_id);
    response.updated(&carlos_contact_id);
    response.updated(&acme_contact_id);

    // Verify patches
    let response = account
        .jmap_get(
            MethodObject::ContactCard,
            [
                JSContactProperty::<Id>::Id,
                JSContactProperty::AddressBookIds,
                JSContactProperty::Name,
                JSContactProperty::Keywords,
                JSContactProperty::Nicknames,
            ],
            [&sarah_contact_id, &carlos_contact_id, &acme_contact_id],
        )
        .await;

    response.list()[0].assert_is_equal(json!({
      "id": &sarah_contact_id,
      "name": {
        "full": "Sarah O'Connor",
        "components": [
          {
            "kind": "surname",
            "value": "O'Connor"
          },
          {
            "kind": "given",
            "value": "Sarah"
          },
          {
            "kind": "given2",
            "value": "Marie"
          },
          {
            "kind": "title",
            "value": "Dr."
          },
          {
            "kind": "credential",
            "value": "Ph.D."
          }
        ],
        "isOrdered": true
      },
      "nicknames": {
        "k1": {
            "name": "Sadie"
         }
      },
      "keywords": {
        "Work": true,
        "Research": true,
        "VIP": true
      },
      "addressBookIds":  {
        &book1_id: true,
        &book2_id: true
      },
    }));

    response.list()[1].assert_is_equal(json!({
      "id": &carlos_contact_id,
      "name": {
        "components": [
          {
            "kind": "surname",
            "value": "Rodriguez-Martinez"
          },
          {
            "kind": "given",
            "value": "Carlos"
          },
          {
            "kind": "given2",
            "value": "Alberto"
          },
          {
            "kind": "title",
            "value": "Mr."
          },
          {
            "kind": "credential",
            "value": "Jr."
          }
        ],
        "isOrdered": true,
        "full": "Carlos Rodriguez-Martinez"
      },
      "keywords": {
        "Marketing": true,
        "Management": true,
        "International": true
      },
      "nicknames": {
        "k2": {
        "name": "Carlitos"
        }
      },
      "addressBookIds": {
        &book1_id: true,
        &book2_id: true
      },
    }));

    response.list()[2].assert_is_equal(json!({
        "id": acme_contact_id,
        "addressBookIds": {
            &book1_id: true,
        },
        "name": {
            "full": "Acme Business Solutions Ltd."
        },
        "keywords": {
            "Technology": true,
            "B2C": true,
            "Solutions": true,
            "Services": true
        }
    }));

    // Query tests
    wait_for_index(&params.server).await;
    let email = if !params.server.search_store().is_mysql() {
        "sarah.johnson@example.com"
    } else {
        "sarah.johnson@example"
    };
    assert_eq!(
        account
            .jmap_query(
                MethodObject::ContactCard,
                [
                    ("text", "Sarah"),
                    ("inAddressBook", book1_id.as_str()),
                    ("uid", "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6"),
                    ("email", email),
                ],
                ["created"],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .ids()
            .collect::<AHashSet<_>>(),
        [sarah_contact_id.as_str()]
            .into_iter()
            .collect::<AHashSet<_>>()
    );

    // Parse tests
    account
        .jmap_method_calls(json!([
         [
          "Blob/upload",
          {
           "create": {
            "vcard": {
             "data": [
              {
               "data:asText": r#"BEGIN:VCARD
VERSION:4.0
KIND:individual
FN:Jane Doe
ORG:ABC\, Inc.;North American Division;Marketing
END:VCARD"#
              }
            ]
           }
          }
         },
         "S4"
        ],
        [
          "ContactCard/parse",
          {
           "blobIds": [
             "#vcard"
           ]
          },
          "G4"
         ]
        ]))
        .await
        .pointer("/methodResponses/1/1/parsed")
        .unwrap()
        .as_object()
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .1
        .assert_is_equal(json!({
          "name": {
            "full": "Jane Doe"
          },
          "version": "1.0",
          "vCard": {
            "properties": [
              [
                "version",
                {},
                "unknown",
                "4.0"
              ]
            ]
          },
          "organizations": {
            "k1": {
              "name": "ABC, Inc.",
              "units": [
                {
                  "name": "North American Division"
                },
                {
                  "name": "Marketing"
                }
              ]
            }
          },
          "@type": "Card",
          "kind": "individual"
        }));

    // Deletion tests
    assert_eq!(
        account
            .jmap_destroy(
                MethodObject::ContactCard,
                [carlos_contact_id.as_str(), acme_contact_id.as_str()],
                Vec::<(&str, &str)>::new()
            )
            .await
            .destroyed()
            .collect::<AHashSet<_>>(),
        [carlos_contact_id.as_str(), acme_contact_id.as_str()]
            .into_iter()
            .collect::<AHashSet<_>>()
    );

    // CardDAV compatibility tests
    let account_id = account.id().document_id();
    let dav_client = DummyWebDavClient::new(
        u32::MAX,
        account.name(),
        account.secret(),
        account.emails()[0],
    );
    let resources = params
        .server
        .fetch_dav_resources(
            &params.server.get_access_token(account_id).await.unwrap(),
            account_id,
            SyncCollection::AddressBook,
        )
        .await
        .unwrap();
    let path = format!(
        "{}{}",
        resources.base_path,
        resources
            .paths
            .iter()
            .find(|v| v.parent_id.is_some())
            .unwrap()
            .path
    );
    let vcard = dav_client
        .request("GET", &path, "")
        .await
        .with_status(StatusCode::OK)
        .expect_body()
        .lines()
        .map(String::from)
        .collect::<AHashSet<_>>();
    let expected_vcard = TEST_VCARD_1
        .lines()
        .map(String::from)
        .collect::<AHashSet<_>>();
    assert_eq!(vcard, expected_vcard);

    // Clean up
    account.destroy_all_addressbooks().await;
    params.assert_is_empty().await;
}

fn test_jscontact_1() -> Value {
    json!({
      "uid": "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
      "@type": "Card",
      "preferredLanguages": {
        "k1": {
          "language": "en",
          "contexts": {
            "work": true
          },
          "pref": 1
        },
        "k2": {
          "language": "fr",
          "contexts": {
            "work": true
          },
          "pref": 2
        }
      },
      "name": {
        "full": "Sarah Johnson",
        "components": [
          {
            "kind": "surname",
            "value": "Johnson"
          },
          {
            "kind": "given",
            "value": "Sarah"
          },
          {
            "kind": "given2",
            "value": "Marie"
          },
          {
            "kind": "title",
            "value": "Dr."
          },
          {
            "kind": "credential",
            "value": "Ph.D."
          }
        ],
        "isOrdered": true
      },
      "cryptoKeys": {
        "k1": {
          "uri": "https://pgp.example.com/pks/lookup?op=get&search=sarah.johnson@example.com",
          "contexts": {
            "pgp": true
          }
        }
      },
      "keywords": {
        "Work": true,
        "Research": true,
        "VIP": true
      },
      "anniversaries": {
        "k1": {
          "date": {
            "@type": "PartialDate",
            "year": 1985,
            "month": 4,
            "day": 15
          },
          "kind": "birth"
        },
        "k2": {
          "date": {
            "@type": "PartialDate",
            "year": 2010,
            "month": 6,
            "day": 10
          },
          "kind": "wedding"
        }
      },
      "links": {
        "k1": {
          "uri": "https://www.example.com/staff/sjohnson",
          "contexts": {
            "work": true
          }
        },
        "k2": {
          "uri": "https://www.sarahjohnson.example.com",
          "contexts": {
            "private": true
          }
        }
      },
      "organizations": {
        "k1": {
          "name": "Acme Technologies Inc.",
          "units": [
            {
              "name": "Research Department"
            }
          ]
        }
      },
      "emails": {
        "k1": {
          "address": "sarah.johnson@example.com",
          "contexts": {
            "work": true
          }
        },
        "k2": {
          "address": "sarahjpersonal@example.com",
          "contexts": {
            "private": true,
            "pref": true
          }
        }
      },
      "phones": {
        "k1": {
          "number": "+1-555-123-4567",
          "contexts": {
            "pref": true
          },
          "features": {
            "mobile": true,
            "voice": true
          }
        },
        "k2": {
          "number": "+1-555-987-6543",
          "contexts": {
            "work": true
          },
          "features": {
            "voice": true
          }
        },
        "k3": {
          "number": "+1-555-456-7890",
          "contexts": {
            "private": true
          },
          "features": {
            "voice": true
          }
        }
      },
      "version": "1.0",
      "addresses": {
        "k1": {
          "contexts": {
            "work": true
          },
          "full": "123 Business Ave\nSuite 400\nNew York, NY 10001\nUSA",
          "components": [
            {
              "kind": "name",
              "value": "123 Business Ave"
            },
            {
              "kind": "locality",
              "value": "New York"
            },
            {
              "kind": "region",
              "value": "NY"
            },
            {
              "kind": "postcode",
              "value": "10001"
            },
            {
              "kind": "country",
              "value": "USA"
            }
          ],
          "timeZone": "Etc/GMT+5",
          "coordinates": "40.7128;-74.0060",
          "isOrdered": true
        },
        "k2": {
          "contexts": {
            "private": true,
            "pref": true
          },
          "full": "456 Residential St\nApt 7B\nBrooklyn, NY 11201\nUSA",
          "components": [
            {
              "kind": "name",
              "value": "456 Residential St"
            },
            {
              "kind": "locality",
              "value": "Brooklyn"
            },
            {
              "kind": "region",
              "value": "NY"
            },
            {
              "kind": "postcode",
              "value": "11201"
            },
            {
              "kind": "country",
              "value": "USA"
            }
          ],
          "isOrdered": true
        }
      },
      "titles": {
        "k1": {
          "name": "Senior Research Scientist",
          "kind": "title"
        },
        "k2": {
          "name": "Team Lead",
          "kind": "role",
          "organizationId": "k1"
        }
      },
      "nicknames": {
        "k1": {
          "name": "Sadie"
        }
      },
      "notes": {
        "k1": {
          "note": "Sarah prefers video calls over phone calls. Available Mon-Thu 9-5 EST."
        }
      },
      "updated": "2022-03-15T13:30:00Z"
    })
}

fn test_jscontact_2() -> Value {
    json!({
      "phones": {
        "k1": {
          "number": "+34-611-234-567",
          "contexts": {
            "pref": true
          },
          "features": {
            "mobile": true,
            "voice": true
          }
        },
        "k2": {
          "number": "+34-911-876-543",
          "contexts": {
            "work": true
          },
          "features": {
            "voice": true
          }
        },
        "k3": {
          "number": "+34-644-321-987",
          "contexts": {
            "private": true
          },
          "features": {
            "voice": true
          }
        },
        "k4": {
          "number": "+34-911-876-544",
          "features": {
            "fax": true
          }
        }
      },
      "keywords": {
        "Marketing": true,
        "Management": true,
        "International": true
      },
      "kind": "individual",
      "anniversaries": {
        "k1": {
          "date": {
            "@type": "PartialDate",
            "month": 6,
            "day": 23
          },
          "kind": "birth"
        },
        "k2": {
          "date": {
            "@type": "PartialDate",
            "year": 2015,
            "month": 8,
            "day": 9
          },
          "kind": "wedding"
        }
      },
      "members": {
        "urn:uuid:03a0e51f-d1aa-4385-8a53-e29025acd8af": true
      },
      "uid": "urn:uuid:e1ee798b-3d4c-41b0-b217-b9c918e4686a",
      "name": {
        "components": [
          {
            "kind": "surname",
            "value": "Rodriguez-Martinez"
          },
          {
            "kind": "given",
            "value": "Carlos"
          },
          {
            "kind": "given2",
            "value": "Alberto"
          },
          {
            "kind": "title",
            "value": "Mr."
          },
          {
            "kind": "credential",
            "value": "Jr."
          }
        ],
        "full": "Carlos Rodriguez-Martinez",
        "isOrdered": true
      },
      "nicknames": {
        "k1": {
          "name": "Charlie"
        }
      },
      "relatedTo": {
        "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6": {
          "relation": {
            "friend": true
          }
        }
      },
      "emails": {
        "k1": {
          "address": "carlos.rodriguez@example-corp.com",
          "contexts": {
            "work": true,
            "pref": true
          }
        },
        "k2": {
          "address": "carlosrm@personalmail.example",
          "contexts": {
            "private": true
          }
        }
      },
      "directories": {
        "k1": {
          "uri": "https://contacts.example.com/carlosrodriguez.vcf",
          "kind": "entry"
        }
      },
      "cryptoKeys": {
        "k1": {
          "uri": "https://pgp.example.com/pks/lookup?op=get&search=carlos.rodriguez@example-corp.com",
          "contexts": {
            "pgp": true
          }
        }
      },
      "version": "1.0",
      "notes": {
        "k1": {
          "note": "Carlos speaks English, Spanish, and Portuguese fluently. Prefers communication via email. Do not contact after 7PM CET."
        }
      },
      "updated": "2023-07-12T09:21:35Z",
      "links": {
        "k1": {
          "uri": "https://www.example-corp.com/team/carlos",
          "contexts": {
            "work": true
          }
        },
        "k2": {
          "uri": "https://www.carlosrodriguez.example",
          "contexts": {
            "private": true
          }
        },
        "k3": {
          "uri": "https://linkedin.com/in/carlosrodriguezm",
          "contexts": {
            "social": true
          }
        }
      },
      "@type": "Card",
      "titles": {
        "k1": {
          "name": "Digital Marketing Director",
          "kind": "title"
        },
        "k2": {
          "name": "Department Head",
          "kind": "role",
          "organizationId": "k1"
        }
      },
      "preferredLanguages": {
        "k1": {
          "language": "es",
          "contexts": {
            "work": true
          },
          "pref": 1
        },
        "k2": {
          "language": "en",
          "contexts": {
            "work": true
          },
          "pref": 2
        },
        "k3": {
          "language": "pt",
          "contexts": {
            "work": true
          },
          "pref": 3
        }
      },
      "addresses": {
        "k1": {
          "contexts": {
            "work": true
          },
          "full": "Calle Empresarial 42\nPlanta 3\nMadrid, 28001\nSpain",
          "components": [
            {
              "kind": "name",
              "value": "Calle Empresarial 42"
            },
            {
              "kind": "locality",
              "value": "Madrid"
            },
            {
              "kind": "postcode",
              "value": "28001"
            },
            {
              "kind": "country",
              "value": "Spain"
            }
          ],
          "timeZone": "Etc/GMT-1",
          "coordinates": "40.4168;-3.7038",
          "isOrdered": true
        },
        "k2": {
          "contexts": {
            "private": true,
            "pref": true
          },
          "full": "Avenida Residencial 15\nPiso 7, Puerta C\nMadrid, 28045\nSpain",
          "components": [
            {
              "kind": "name",
              "value": "Avenida Residencial 15"
            },
            {
              "kind": "locality",
              "value": "Madrid"
            },
            {
              "kind": "postcode",
              "value": "28045"
            },
            {
              "kind": "country",
              "value": "Spain"
            }
          ],
          "isOrdered": true
        }
      },
      "organizations": {
        "k1": {
          "name": "Global Solutions S.L.",
          "units": [
            {
              "name": "Marketing Division"
            }
          ]
        }
      }
    })
}

fn test_jscontact_3() -> Value {
    json!({
      "kind": "org",
      "organizations": {
        "k1": {
          "name": "Acme Business Solutions Ltd.",
          "units": [
            {
              "name": "Technology Division"
            }
          ]
        }
      },
      "preferredLanguages": {
        "k1": {
          "language": "en",
          "contexts": {
            "work": true
          },
          "pref": 1
        },
        "k2": {
          "language": "de",
          "contexts": {
            "work": true
          },
          "pref": 2
        },
        "k3": {
          "language": "fr",
          "contexts": {
            "work": true
          },
          "pref": 3
        }
      },
      "directories": {
        "k1": {
          "uri": "https://directory.example.com/acme.vcf",
          "kind": "entry"
        }
      },
      "cryptoKeys": {
        "k1": {
          "uri": "https://pgp.example.com/pks/lookup?op=get&search=info@acme-solutions.example",
          "contexts": {
            "pgp": true
          }
        }
      },
      "links": {
        "k1": {
          "uri": "https://www.acme-solutions.example",
          "contexts": {
            "work": true
          }
        },
        "k2": {
          "uri": "https://support.acme-solutions.example",
          "contexts": {
            "support": true
          }
        }
      },
      "name": {
        "full": "Acme Business Solutions Ltd."
      },
      "notes": {
        "k1": {
          "note": "Business hours: Mon-Fri 9:00-17:30 GMT. Closed on UK bank holidays. VAT Reg: GB123456789"
        }
      },
      "uid": "urn:uuid:a9e95948-7b1c-46e8-bd85-c729a9e910f2",
      "@type": "Card",
      "prodId": "-//Example Corp.//Contact Manager 3.0//EN",
      "version": "1.0",
      "emails": {
        "k1": {
          "address": "info@acme-solutions.example",
          "contexts": {
            "work": true,
            "pref": true
          }
        },
        "k2": {
          "address": "support@acme-solutions.example",
          "contexts": {
            "support": true
          }
        },
        "k3": {
          "address": "sales@acme-solutions.example",
          "contexts": {
            "sales": true
          }
        }
      },
      "phones": {
        "k1": {
          "number": "+44-20-1234-5678",
          "contexts": {
            "work": true,
            "pref": true
          },
          "features": {
            "voice": true
          }
        },
        "k2": {
          "number": "+44-20-1234-5679",
          "features": {
            "fax": true
          }
        },
        "k3": {
          "number": "+44-800-987-6543",
          "contexts": {
            "support": true
          }
        }
      },
      "addresses": {
        "k1": {
          "contexts": {
            "work": true
          },
          "full": "10 Enterprise Way\nTech Park\nLondon, EC1A 1BB\nUnited Kingdom",
          "components": [
            {
              "kind": "name",
              "value": "10 Enterprise Way, Tech Park"
            },
            {
              "kind": "locality",
              "value": "London"
            },
            {
              "kind": "postcode",
              "value": "EC1A 1BB"
            },
            {
              "kind": "country",
              "value": "United Kingdom"
            }
          ],
          "timeZone": "Etc/UTC",
          "coordinates": "51.5074;-0.1278",
          "isOrdered": true
        },
        "k2": {
          "contexts": {
            "branch": true
          },
          "full": "25 Innovation Street\nManchester, M1 5QF\nUnited Kingdom",
          "components": [
            {
              "kind": "name",
              "value": "25 Innovation Street"
            },
            {
              "kind": "locality",
              "value": "Manchester"
            },
            {
              "kind": "postcode",
              "value": "M1 5QF"
            },
            {
              "kind": "country",
              "value": "United Kingdom"
            }
          ],
          "isOrdered": true
        }
      },
      "updated": "2023-04-15T15:30:00Z",
      "keywords": {
        "Technology": true,
        "B2B": true,
        "Solutions": true,
        "Services": true
      },
      "relatedTo": {
        "urn:uuid:b9e93fdb-4d34-45fa-a1e2-47da0428c4a1": {
          "relation": {
            "contact": true
          }
        },
        "urn:uuid:c8e74dfe-6b34-45fa-b1e2-47ea0428c4b2": {
          "relation": {
            "contact": true
          }
        }
      }
    })
}

fn test_jscontact_4() -> Value {
    json!({
    "@type": "Card",
    "version": "1.0",
    "kind": "individual",
    "name": {
      "@type": "Name",
      "full": "Temporary Contact"
    }})
}

const TEST_VCARD_1: &str = r#"BEGIN:VCARD
VERSION:4.0
UID:urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6
LANG;TYPE=WORK;PREF=1;PROP-ID=k1:en
LANG;TYPE=WORK;PREF=2;PROP-ID=k2:fr
FN:Sarah O'Connor
N;JSCOMPS=";0;1;2;3;4":O'Connor;Sarah;Marie;Dr.;Ph.D.;;
KEY;TYPE=PGP;PROP-ID=k1:https://pgp.example.com/pks/lookup?op=get&search=sar
 ah.johnson@example.com
CATEGORIES:Work,Research,VIP
BDAY;PROP-ID=k1:19850415
ANNIVERSARY;PROP-ID=k2:20100610
URL;TYPE=WORK;PROP-ID=k1:https://www.example.com/staff/sjohnson
URL;TYPE=HOME;PROP-ID=k2:https://www.sarahjohnson.example.com
ORG;PROP-ID=k1:Acme Technologies Inc.;Research Department
EMAIL;TYPE=WORK;PROP-ID=k1:sarah.johnson@example.com
EMAIL;TYPE=HOME,PREF;PROP-ID=k2:sarahjpersonal@example.com
TEL;TYPE=PREF,CELL,VOICE;PROP-ID=k1:+1-555-123-4567
TEL;TYPE=WORK,VOICE;PROP-ID=k2:+1-555-987-6543
TEL;TYPE=HOME,VOICE;PROP-ID=k3:+1-555-456-7890
ADR;TYPE=WORK;LABEL="123 Business Ave\nSuite 400\nNew York, NY 10001\nUSA";
 TZ=Etc/GMT+5;GEO="40.7128;-74.0060";PROP-ID=k1;JSCOMPS=";11;3;4;5;6":;;123 B
 usiness Ave;New York;NY;10001;USA;;;;;123 Business Ave;;;;;;
ADR;TYPE=HOME,PREF;LABEL="456 Residential St\nApt 7B\nBrooklyn, NY 11201\nU
 SA";PROP-ID=k2;JSCOMPS=";11;3;4;5;6":;;456 Residential St;Brooklyn;NY;11201;
 USA;;;;;456 Residential St;;;;;;
TITLE;PROP-ID=k1:Senior Research Scientist
JSPROP;JSPTR=titles/k2/organizationId:"k1"
ROLE;PROP-ID=k2:Team Lead
NICKNAME;PROP-ID=k1:Sadie
NOTE;PROP-ID=k1:Sarah prefers video calls over phone calls. Available Mon-Th
 u 9-5 EST.
REV:20220315T133000Z
END:VCARD
"#;
