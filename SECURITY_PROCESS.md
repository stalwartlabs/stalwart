# Stalwart Security Incident Response Checklist

## Phase 1 : Initial Assessment & Validation

### Updates

<< Use this section to detail the report received, initial assessment, and validation results >>

Example:

I've reviewed the security report and confirmed this vulnerability exists in Stalwart version X.Y.Z.

Assessment of exploitability:

- Attack complexity: [High/Medium/Low]
- Prerequisites: [Authentication required/Network access/Specific configuration/etc.]
- User interaction required: [Yes/No]

Potential impact:
- Email data confidentiality: [At risk/Not affected]
- Server integrity: [At risk/Not affected] 
- Service availability: [At risk/Not affected]
- Estimated affected installations: [Number/Percentage]

### Resources

- [Stalwart Security Policy](https://github.com/stalwartlabs/stalwart/blob/main/SECURITY.md)
- [CVE Scoring Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
- [Rust Security Advisory Database](https://rustsec.org/)

### Tasks

- [ ] Reproduce the vulnerability in test environment
- [ ] Assess CVSS score and severity level
- [ ] Check if vulnerability affects current stable version
- [ ] Check if vulnerability affects LTS versions (if applicable)
- [ ] Determine if this requires immediate action or can wait for next release cycle
- [ ] Document technical details and root cause

### Assessment Summary

- **Severity Level**: `Critical|High|Medium|Low`
- **CVSS Score**: `X.X`
- **Affects versions**: `X.Y.Z to X.Y.Z`
- **Root cause**: Brief technical explanation
- **Introduced in commit/version**: `commit-hash` or `vX.Y.Z`
- **Attack vector**: `Network|Local|Physical`
- **Estimated timeline for fix**: `X days/weeks`

## Phase 2: Immediate Response & Mitigation

### Updates

<< Document immediate actions taken and mitigation strategies >>

Example:

Working on hotfix for version X.Y.Z. Temporary workaround available by disabling [feature] in configuration.

### Tasks

- [ ] Implement immediate workaround if possible
- [ ] Update security advisory draft
- [ ] Prepare patch/hotfix
- [ ] Test fix thoroughly in development environment
- [ ] Prepare updated Docker images and binaries
- [ ] Draft security advisory for GitHub Security Advisories
- [ ] Consider if coordinated disclosure timeline needs adjustment

### Mitigation Details

- **Workaround available**: `Yes|No` - If yes, describe briefly
- **Fix implemented on**: `YYYY-MM-DD`
- **Patch/hotfix version**: `vX.Y.Z`
- **GitHub Security Advisory ID**: `GHSA-XXXX-XXXX-XXXX`

## Phase 3: Impact Assessment & User Analysis

### Updates

<< Analysis of potential impact on the Stalwart deployments >>

Based on telemetry data and version statistics, approximately X installations may be affected.

### Tasks

- [ ] Analyze version adoption from update checks (if available)
- [ ] Estimate number of vulnerable installations
- [ ] Assess if default configurations are vulnerable
- [ ] Review if vulnerability has been exploited (check logs, reports)
- [ ] Determine if any user data may have been compromised
- [ ] Check for indicators of active exploitation in the wild

### Analysis Notes

_Document your impact assessment process and findings_

### Impact Summary

- **Estimated vulnerable installations**: `~X out of Y`
- **Default configuration vulnerable**: `Yes|No`
- **Evidence of exploitation**: `Found|Not found|Unknown`
- **User data potentially at risk**: `Email content|Credentials|Configuration|None`
- **Confidence in assessment**: `High|Medium|Low`

## Phase 4: Communication & Release

### Updates

<< Communication strategy and release timeline >>

Security release vX.Y.Z will be published on YYYY-MM-DD with coordinated disclosure.

### Tasks

**Pre-release preparation:**

- [ ] Finalize security patch
- [ ] Prepare release notes with security details
- [ ] Update documentation if needed
- [ ] Test automated update mechanisms
- [ ] Prepare GitHub Security Advisory

**Communication channels:**

- [ ] Draft announcement for Stalwart community forum/Discord
- [ ] Prepare release announcement for GitHub
- [ ] Draft security advisory content
- [ ] Consider notification to major distributors/packagers

**Release execution:**

- [ ] Publish patched version to GitHub releases
- [ ] Update Docker images on Docker Hub
- [ ] Publish GitHub Security Advisory
- [ ] Post to community channels (Discord/forum)
- [ ] Update project website/documentation
- [ ] Submit CVE request if warranted (CVSS ≥ 4.0)

**Post-release:**

- [ ] Monitor community channels for questions
- [ ] Track adoption of security update
- [ ] Follow up on any additional reports
- [ ] Document lessons learned

### Communication Record

- **Security release published**: `YYYY-MM-DD HH:MM UTC`
- **GitHub Security Advisory**: `GHSA-XXXX-XXXX-XXXX`
- **CVE ID** (if applicable): `CVE-YYYY-XXXXX`
- **Community announcement**: [Link to forum/Discord post]
- **Estimated time to 50% adoption**: `X days/weeks`

## Post-Incident Review

### What went well?
- 

### What could be improved?
- 

### Action items for future incidents:
- [ ] 
- [ ] 
- [ ] 

### Process improvements:
- [ ] 
- [ ] 

## Emergency Contacts
- **Primary maintainer**: hello@stalw.art
