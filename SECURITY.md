# Security Policy for Stalwart

## Supported Versions

We provide security updates for the following versions of Stalwart:

| Version | Supported          | End of Support |
| ------- | ------------------ | -------------- |
| 0.15.x  | :white_check_mark: | TBD            |
| 0.14.x  | :white_check_mark: | 2026-06-08     |
| 0.13.x  | :white_check_mark: | 2026-03-31     |
| < 0.13  | :x:                | Ended          |

**Note**: We typically support the current major version and one previous major version. Users are strongly encouraged to upgrade to the latest version for the best security posture.

## Reporting a Vulnerability

We take the security of Stalwart very seriously. If you believe you've found a security vulnerability, we encourage you to inform us responsibly through coordinated disclosure.

### How to Report

**Do not report security vulnerabilities through public GitHub issues, discussions, or social media.**

Instead, please use one of these secure channels:

1. **Email** (preferred): Send details to `security@stalw.art`
2. **GitHub Security Advisories**: Use the "Report a vulnerability" button in the Security tab
3. **Backup contact**: If no response within 48 hours, email `hello@stalw.art`

### What to Include

To help us understand and address the issue quickly, please include:

**Required Information:**
- Brief description of the vulnerability type
- Affected version(s) and components
- Steps to reproduce the issue
- Impact assessment (what could an attacker achieve?)

**Helpful Additional Details:**
- Full paths of affected source files
- Specific commit/branch where the issue exists
- Required configuration to reproduce
- Proof-of-concept code (if available)
- Suggested mitigation or fix (if you have ideas)

### Our Response Process

**Timeline Commitments:**
- **Initial acknowledgment**: Within 24 hours
- **Detailed response**: Within 72 hours
- **Status updates**: Every 7 days until resolved
- **Resolution target**: 90 days for most issues

**What We'll Do:**
1. Acknowledge your report and assign a tracking ID
2. Assess the vulnerability and determine severity
3. Develop and test a fix
4. Coordinate disclosure timeline with you
5. Release security update and publish advisory
6. Credit you in our security advisory (if desired)

## Disclosure Policy

We follow responsible disclosure principles:

- **Coordinated disclosure**: We'll work with you to determine appropriate disclosure timing
- **Typical timeline**: 90 days from report to public disclosure
- **Early disclosure**: May occur if issue is being actively exploited
- **Delayed disclosure**: May be necessary for complex issues requiring significant changes

## Scope

This security policy applies to:

**In Scope:**
- Stalwart (all supported versions)
- Official Docker images
- Documentation that could lead to insecure configurations
- Dependencies with security implications

**Out of Scope:**
- Third-party integrations or plugins
- Issues requiring physical access to the server
- Social engineering attacks
- Attacks requiring compromised credentials (unless the vulnerability enables credential compromise)
- Theoretical vulnerabilities without practical exploitation

## Security Measures

**Our Commitments:**
- Regular security audits of dependencies using `cargo audit`
- Automated security scanning in CI/CD pipeline
- Following Rust security best practices
- Prompt security updates for critical dependencies
- Security-focused code review process

**User Responsibilities:**
- Keep Stalwart updated to supported versions
- Follow security configuration guidelines
- Implement proper network security (firewalls, TLS, etc.)
- Regular security monitoring and logging
- Secure credential management

## Legal Safe Harbor

We support security research conducted in good faith. If you follow these guidelines:

**We will NOT:**
- Initiate legal action against you
- Contact law enforcement about your research
- Suspend or terminate your access to Stalwart services

**You must:**
- Only test against your own Stalwart installations
- Not access, modify, or delete user data
- Not perform testing that could degrade service availability
- Not publicly disclose the issue before coordinated disclosure
- Act in good faith and not for malicious purposes

## Recognition

We believe in recognizing security researchers who help keep Stalwart secure:

- **Security Advisory Credits**: We'll credit you in our GitHub Security Advisories (unless you prefer to remain anonymous)
- **Hall of Fame**: Significant contributors may be listed in our security acknowledgments
- **Swag**: We may send Stalwart merchandise for notable contributions

## Security Updates

**Stay Informed:**
- Subscribe to our [GitHub releases](https://github.com/stalwartlabs/stalwart/releases) for security updates
- Join our community channels for security announcements
- Enable GitHub notifications for security advisories

**Update Process:**
- Security updates are published as patch releases (e.g., 0.12.1 → 0.12.2)
- Critical vulnerabilities may receive out-of-band releases
- Docker images are updated simultaneously with releases
- Security advisories are published through GitHub Security Advisories

## Contact Information

- **Security reports**: security@stalw.art
- **General inquiries**: hello@stalw.art
- **PGP Key**: Available upon request for sensitive communications

## Additional Resources

- [Stalwart Security Incident Response Process](SECURITY_PROCESS.md)
- [Security Configuration Guide](https://stalw.art/docs/install/security)
- [Rust Security Advisory Database](https://rustsec.org/)

*This security policy is effective as of June 20, 2025 and may be updated periodically. Check back regularly for updates.*

