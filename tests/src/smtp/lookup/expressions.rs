/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{dns::DnsCache, server::TestServerBuilder};
use common::{
    Server,
    expr::{
        Bump, Expression, Variable,
        functions::ResolveVariable,
        if_block::{IfBlock, IfThen},
        tokenizer::TokenMap,
    },
};
use mail_auth::{DnssecStatus, Mx};
use registry::schema::{
    enums::{ExpressionConstant, ExpressionVariable},
    prelude::{ObjectType, Property},
    structs::{LookupStore, SqliteStore, StoreLookup},
};
use smtp::queue::RecipientDomain;
use std::{
    mem::size_of_val,
    time::{Duration, Instant},
};

const MAX_EVAL_FUTURE: usize = 72;
const SET_ITEMS: usize = 12;

const TESTS: &[(&str, &str)] = &[
    ("dns_query(rcpt_domain, 'mx')[0]", "mx.foobar.org"),
    (
        "key_get('sql', 'hello') + '-' + key_exists('sql', 'hello') + '-' + key_set('sql', 'hello', 'world') + '-' + key_get('sql', 'hello') + '-' + key_exists('sql', 'hello')",
        "-0-1-world-1",
    ),
    (
        "counter_get('sql', 'county') + '-' + counter_incr('sql', 'county', 1) + '-' + counter_incr('sql', 'county', 1) + '-' + counter_get('sql', 'county')",
        "0-1-2-2",
    ),
    (
        "sql_query('sql', 'SELECT description FROM domains WHERE name = ?', 'foobar.org')",
        "Main domain",
    ),
    (
        "is_local_domain('foobar.org') + '-' + is_local_domain('unknown.org')  + '-' + is_local_address('john@foobar.org') + '-' + is_local_address('unknown@foobar.org')",
        "1-0-1-0",
    ),
    (
        "is_local_domain('FooBar.org') + '-' + is_local_address('John@FooBar.org') + '-' + is_local_address('JOHN@FOOBAR.ORG')",
        "1-1-1",
    ),
    (
        "bit_and(254, 16) + '-' + bit_and(254, 1) + '-' + bit_and(80, 64) + '-' + bit_and(255, 128)",
        "16-0-64-128",
    ),
    (
        "split_n('a,b,c', ',', 1)[1] + '|' + split_n('a,b,c', ',', 5)[2] + '|' + count(split_n('abc', '', -1)) + '|' + count(split_n('abc', '', 1))",
        "b,c|c|5|2",
    ),
    (
        "to_lowercase('HELLO \u{39f}\u{394}\u{39f}\u{3a3}') + '|' + to_lowercase('\u{3a3}\u{391}') + '|' + to_uppercase('stra\u{df}e')",
        "hello \u{3bf}\u{3b4}\u{3bf}\u{3c2}|\u{3c3}\u{3b1}|STRASSE",
    ),
    (
        "contains_ignore_case('Absolute \u{212a}ELVIN', 'kelvin') + '-' + contains_ignore_case('kelvin', '\u{212a}ELVIN') + '-' + contains_ignore_case(rcpt_domain, 'TEST.ORG') + '-' + contains_ignore_case('kelvin', 'celsius')",
        "1-1-1-0",
    ),
    (
        "if_then(matches('^([a-z]+)@([a-z.]+)$', 'john@foobar.org'), $1 + '|' + $2, 'none') + '-' + if_then(matches('^([0-9]+)$', 'john'), $1, 'none')",
        "john|foobar.org-none",
    ),
    (
        "if_then(rcpt_domain == 'test.org', 'yes', 'no') + '-' + if_then(is_local_domain(rcpt_domain), 'local', 'remote')",
        "yes-remote",
    ),
];

type Branches = &'static [(&'static str, &'static str)];

const IF_THEN_TESTS: &[(Branches, &str, &str)] = &[
    (
        &[
            ("rcpt_domain == 'other.org'", "'wrong'"),
            ("rcpt_domain == 'test.org'", "'right'"),
        ],
        "'default'",
        "right",
    ),
    (
        &[("rcpt_domain == 'other.org'", "'wrong'")],
        "'default'",
        "default",
    ),
    (
        &[(
            "matches('^([a-z]+)@([a-z.]+)$', 'john@foobar.org')",
            "$2 + '/' + $1",
        )],
        "'none'",
        "foobar.org/john",
    ),
    (&[("matches('^([0-9]+)$', 'john')", "$1")], "'none'", "none"),
    (
        &[
            ("key_exists('sql', 'missing')", "'found'"),
            ("!is_local_domain(rcpt_domain)", "'remote'"),
        ],
        "'default'",
        "remote",
    ),
];

const PROBES: [Variable<'static>; 10] = [
    Variable::String("item1"),
    Variable::String("item11"),
    Variable::String("item"),
    Variable::String("3"),
    Variable::String(""),
    Variable::Integer(3),
    Variable::Float(3.0),
    Variable::Integer(4),
    Variable::Array(&[Variable::String("item1")]),
    Variable::Constant(ExpressionConstant::Relaxed),
];

const BORROWED_TESTS: &[&str] = &[
    "'zone.' + rcpt_domain",
    "key_exists('sql', 'abc') || 'fallback'",
    "false && key_exists('sql', 'abc')",
    "matches('^([a-z]+)$', 'abc') && $1",
    "split('a,b', ',')",
];

struct ValueResolver(Variable<'static>);

impl ResolveVariable for ValueResolver {
    fn resolve_variable<'a>(&'a self, variable: ExpressionVariable, _: &'a Bump) -> Variable<'a> {
        match variable {
            ExpressionVariable::Value => self.0,
            ExpressionVariable::RcptDomain => Variable::String("test.org"),
            _ => Variable::default(),
        }
    }
}

fn compile(token_map: &TokenMap, branches: &[(&str, &str)], default: &str) -> IfBlock {
    let parse = |expr: &str| {
        Expression::parse(token_map, expr).unwrap_or_else(|err| panic!("{expr}: {err}"))
    };
    IfBlock::new(
        ObjectType::Account.singleton(),
        Property::AccountName,
        branches
            .iter()
            .map(|(expr, then)| IfThen {
                expr: parse(expr),
                then: parse(then),
            })
            .collect(),
        parse(default),
    )
}

async fn eval_string(
    server: &Server,
    block: &IfBlock,
    resolver: &impl ResolveVariable,
    arena: &mut Bump,
) -> Option<String> {
    server.eval_if::<String, _>(block, resolver, arena, 0).await
}

#[tokio::test]
async fn expressions() {
    let mut test = TestServerBuilder::new("smtp_lookup_test")
        .await
        .with_http_listener(19017)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    // Create test data
    let admin = test.account("admin");
    for (name, secret, description, aliases) in [
        ("john@foobar.org", "12345 + extra safety", "John Doe", &[]),
        ("jane@domain.net", "abcde + extra safety", "Jane Smith", &[]),
    ] {
        admin
            .create_user_account(name, secret, description, aliases, vec![])
            .await;
    }
    admin
        .registry_create_object(StoreLookup {
            namespace: "sql".into(),
            store: LookupStore::Sqlite(SqliteStore {
                path: format!("{}/smtp_sql.db", test.tmp_dir()),
                pool_max_connections: 10,
                pool_workers: None,
            }),
        })
        .await;
    admin.reload_lookup_stores().await;
    test.reload_core();

    test.server.mx_add(
        "test.org",
        vec![Mx {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        Instant::now() + Duration::from_secs(10),
    );

    let sql = test
        .server
        .get_lookup_store("sql")
        .unwrap()
        .into_store()
        .unwrap();
    sql.create_tables().await.unwrap();
    for query in [
        "CREATE TABLE domains (name TEXT PRIMARY KEY, description TEXT);",
        "INSERT INTO domains (name, description) VALUES ('foobar.org', 'Main domain');",
        "INSERT INTO domains (name, description) VALUES ('foobar.net', 'Secondary domain');",
        "CREATE TABLE allowed_ips (addr TEXT PRIMARY KEY);",
        "INSERT INTO allowed_ips (addr) VALUES ('10.0.0.50');",
    ] {
        sql.sql_query::<usize>(query, Vec::new()).await.unwrap();
    }

    // Test expression functions
    let token_map = TokenMap::default().with_variables(&[
        ExpressionVariable::Rcpt,
        ExpressionVariable::RcptDomain,
        ExpressionVariable::Sender,
        ExpressionVariable::SenderDomain,
        ExpressionVariable::Mx,
        ExpressionVariable::HeloDomain,
        ExpressionVariable::AuthenticatedAs,
        ExpressionVariable::Listener,
        ExpressionVariable::RemoteIp,
        ExpressionVariable::LocalIp,
        ExpressionVariable::Priority,
        ExpressionVariable::Value,
    ]);
    let server = &test.server;
    let domain = RecipientDomain::new("test.org");
    let mut arena = Bump::new();
    for (expr, expected) in TESTS {
        let block = compile(&token_map, &[], expr);
        assert_eq!(
            eval_string(server, &block, &domain, &mut arena)
                .await
                .unwrap(),
            *expected,
            "failed for '{}'",
            expr
        );
    }

    for (branches, default, expected) in IF_THEN_TESTS {
        let block = compile(&token_map, branches, default);
        assert_eq!(
            eval_string(server, &block, &domain, &mut arena)
                .await
                .unwrap(),
            *expected,
            "failed for {branches:?} else '{default}'"
        );
    }

    for expr in ["rcpt_domain + '!'", "key_exists('sql', rcpt_domain)"] {
        let block = compile(&token_map, &[], expr);
        let future = server.eval_if::<String, _>(&block, &domain, &mut arena, 0);
        let size = size_of_val(&future);
        println!("eval_if future for '{expr}': {size} bytes");
        assert!(
            size <= MAX_EVAL_FUTURE,
            "eval_if future for '{expr}' is {size} bytes"
        );
        future.await;
    }

    let items = (0..SET_ITEMS)
        .map(|index| format!("'item{index}'"))
        .collect::<Vec<_>>();
    for len in [2, 8, SET_ITEMS] {
        let list = items[..len].join(", ");
        let fused = compile(&token_map, &[], &format!("contains([{list}, '3'], value)"));
        let generic = compile(
            &token_map,
            &[],
            &format!("contains([{list}, '3'], value + '')"),
        );
        for probe in PROBES {
            let resolver = ValueResolver(probe);
            assert_eq!(
                server
                    .eval_if::<bool, _>(&fused, &resolver, &mut arena, 0)
                    .await,
                server
                    .eval_if::<bool, _>(&generic, &resolver, &mut arena, 0)
                    .await,
                "{len} items, probe {probe:?}"
            );
        }
    }

    for expr in BORROWED_TESTS {
        let block = compile(&token_map, &[], expr);
        let owned = eval_string(server, &block, &domain, &mut arena).await;
        let borrowed = server
            .eval_if_with(&block, &domain, &mut arena, 0, |value| match value {
                Variable::String(text) => Some(text.len()),
                _ => None,
            })
            .await;
        assert_eq!(
            borrowed.flatten(),
            owned.as_deref().map(str::len),
            "failed for '{expr}'"
        );
    }
}
