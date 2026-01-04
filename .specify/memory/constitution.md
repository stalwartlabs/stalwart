<!--
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         SYNC IMPACT REPORT                                     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Version Change: N/A → 1.0.0 (Initial constitution)                           ║
║                                                                                ║
║  Added Principles:                                                             ║
║    • I. Security First                                                         ║
║    • II. Standards Compliance                                                  ║
║    • III. Memory Safety & Performance                                          ║
║    • IV. Testing & Quality Assurance                                           ║
║    • V. Observability & Traceability                                           ║
║                                                                                ║
║  Added Sections:                                                               ║
║    • Technology Standards                                                      ║
║    • Contribution & Licensing                                                  ║
║    • Governance                                                                ║
║                                                                                ║
║  Templates Requiring Updates:                                                  ║
║    • .specify/templates/plan-template.md ✅ (Constitution Check section ready) ║
║    • .specify/templates/spec-template.md ✅ (Compatible - no changes needed)   ║
║    • .specify/templates/tasks-template.md ✅ (Compatible - no changes needed)  ║
║                                                                                ║
║  Deferred Items: None                                                          ║
╚═══════════════════════════════════════════════════════════════════════════════╝
-->

# Stalwart Mail Server Constitution

## Core Principles

### I. Security First

All development decisions MUST prioritize security. This is non-negotiable for a
mail server handling sensitive communications.

**Requirements:**
- All code MUST undergo security review before merge to production branches
- Cryptographic operations MUST use well-audited, established libraries
- Authentication mechanisms MUST follow OAuth 2.0, OpenID Connect, or equivalent
  industry standards
- Encryption at rest MUST be supported via S/MIME or OpenPGP
- Vulnerabilities MUST be reported through coordinated disclosure (security@stalw.art)
- Security patches MUST be prioritized over feature development

**Rationale:** Stalwart handles email, calendars, contacts, and file storage—all
highly sensitive data. A security breach would catastrophically impact users' trust
and privacy.

### II. Standards Compliance

All protocol implementations MUST adhere strictly to published RFCs and IETF
specifications.

**Requirements:**
- IMAP implementation MUST comply with RFC 9051 (IMAP4rev2) and RFC 3501 (IMAP4rev1)
- JMAP implementation MUST comply with RFC 8621 and related specifications
- SMTP implementation MUST comply with authentication RFCs (DMARC, DKIM, SPF, ARC)
- CalDAV MUST comply with RFC 4791; CardDAV with RFC 6352; WebDAV with RFC 4918
- New features MUST NOT violate existing RFC compliance
- Deviation from standards MUST be documented with justification and flagged for review

**Rationale:** Interoperability with email clients, calendar applications, and other
mail servers depends on strict standards compliance. Non-compliant behavior causes
user frustration and support burden.

### III. Memory Safety & Performance

Stalwart is written in Rust to ensure memory safety while achieving high performance.

**Requirements:**
- `unsafe` code blocks MUST be minimized and thoroughly documented with safety invariants
- All `unsafe` code MUST be reviewed by at least one additional maintainer
- Performance-critical paths MUST be benchmarked before and after changes
- Memory allocations in hot paths SHOULD be avoided or pooled
- Code MUST compile without warnings on stable Rust (deny warnings in CI)
- Dependencies MUST be vetted for memory safety and actively maintained

**Rationale:** Memory safety prevents entire classes of vulnerabilities (buffer
overflows, use-after-free). Performance is critical for mail servers handling
thousands of concurrent connections.

### IV. Testing & Quality Assurance

Code quality MUST be verifiable through comprehensive testing.

**Requirements:**
- All new features MUST include unit tests covering core logic
- Protocol implementations MUST have integration tests against reference clients
- CI pipeline MUST pass before any merge to main branch
- Test coverage SHOULD NOT decrease with new changes
- Flaky tests MUST be fixed or quarantined immediately
- Manual QA MUST be performed for user-facing changes

**Rationale:** A mail server must be reliable. Untested code paths lead to data
loss, delivery failures, and security vulnerabilities that erode user trust.

### V. Observability & Traceability

Operations teams MUST have visibility into server behavior for troubleshooting
and monitoring.

**Requirements:**
- All significant operations MUST emit structured log events
- OpenTelemetry integration MUST be maintained for tracing and metrics
- Error conditions MUST include actionable context in logs
- Performance metrics MUST be exposed via Prometheus-compatible endpoints
- Webhook support MUST exist for event-driven automation
- Log verbosity MUST be configurable without server restart

**Rationale:** Production mail servers require real-time visibility. Operators
cannot debug delivery issues without proper observability tooling.

## Technology Standards

**Language**: Rust (stable toolchain, latest stable or N-1)
**Build System**: Cargo with workspace-level dependency management
**Database Backends**: RocksDB, FoundationDB, PostgreSQL, MySQL, SQLite, S3, Azure, Redis
**Search Backends**: Built-in, Meilisearch, Elasticsearch, OpenSearch
**Container Runtime**: Docker (multi-platform builds: linux/amd64, linux/arm64)
**Orchestration**: Kubernetes, Docker Swarm, Apache Mesos
**Observability**: OpenTelemetry, Prometheus, journald
**TLS**: ACME automatic provisioning (TLS-ALPN-01, DNS-01, HTTP-01)
**Cluster Coordination**: Peer-to-peer, Kafka, Redpanda, NATS, Redis

**Constraints:**
- All dependencies MUST be compatible with AGPL-3.0 or SEL licensing
- External service integrations MUST be optional (fail gracefully if unavailable)
- Configuration MUST be hot-reloadable where feasible

## Contribution & Licensing

**Current Status**: Stalwart is approaching version 1.0 and is currently limiting
external contributions to bug fixes and small, well-scoped changes.

**Requirements:**
- All contributions MUST be signed off with a Fiduciary License Agreement (FLA)
- Code MUST be dual-licensed under AGPL-3.0 OR SEL (Stalwart Enterprise License v1)
- Each source file MUST include SPDX license headers per REUSE guidelines
- Contributors MUST NOT introduce code with incompatible licenses
- Third-party code MUST be audited for license compatibility before inclusion

**Pull Request Process:**
1. Bug reports MUST include reproduction steps and relevant logs
2. PRs MUST pass CI (build, lint, test)
3. PRs MUST be reviewed by at least one maintainer
4. Version numbers MUST follow SemVer (MAJOR.MINOR.PATCH)

## Governance

This constitution supersedes all other development practices and guidelines.

**Amendment Process:**
1. Proposed amendments MUST be documented in a GitHub issue or discussion
2. Amendments MUST be reviewed by project maintainers
3. Breaking changes to principles require migration plan documentation
4. Version increments follow semantic rules:
   - MAJOR: Backward-incompatible governance changes
   - MINOR: New principles or materially expanded guidance
   - PATCH: Clarifications, wording improvements, typo fixes

**Compliance:**
- All PRs and code reviews MUST verify compliance with this constitution
- Deviations MUST be explicitly justified and documented
- Runtime development guidance is available in project documentation at stalw.art/docs

**Version**: 1.0.0 | **Ratified**: 2025-12-31 | **Last Amended**: 2025-12-31
