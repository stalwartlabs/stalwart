# Security Audit Report - Stalwart Mail Server
**Date:** 2025-10-21
**Version Audited:** 0.13.4
**Auditor:** Claude (AI Security Analyst)
**Repository:** https://github.com/stalwartlabs/stalwart

---

## Executive Summary

This security audit of Stalwart Mail Server identified several vulnerabilities and security concerns ranging from **MEDIUM** to **LOW** severity. The codebase demonstrates strong security practices overall, with Rust's memory safety guarantees and modern cryptographic implementations. However, several areas require attention to improve the security posture.

**Key Statistics:**
- **Total lines of Rust code:** ~223,000
- **Unsafe code blocks:** 8 files (minimal, acceptable)
- **Potential panic points:** 2,486+ unwrap()/expect() calls
- **Unreachable statements:** 29+ in production code

**Severity Distribution:**
- 🔴 **CRITICAL:** 0
- 🟠 **HIGH:** 0
- 🟡 **MEDIUM:** 5
- 🔵 **LOW:** 7
- ℹ️ **INFORMATIONAL:** 4

---

## Critical & High Severity Findings

**None identified.** The codebase demonstrates strong security fundamentals.

---

## Medium Severity Findings

### M1: TOCTOU Race Condition in Quota Enforcement (Partially Fixed)

**Severity:** MEDIUM
**Status:** PARTIALLY MITIGATED
**Location:** `/crates/dav/src/calendar/update.rs`, `/crates/dav/src/card/update.rs`

**Description:**
A Time-of-Check Time-of-Use (TOCTOU) race condition exists in quota enforcement for WebDAV calendar and contact operations. While commit `2f6cfbb` reduced the TOCTOU window, a gap still exists between quota validation and actual write operations.

**Affected Code:**
```rust
// Lines 270-279 in calendar/update.rs (after the fix)
// Validate quota
let extra_bytes =
    (bytes.len() as u64).saturating_sub(u32::from(event.inner.size) as u64);
if extra_bytes > 0 {
    self.has_available_quota(
        &self.get_resource_token(access_token, account_id).await?,
        extra_bytes,
    )
    .await?;
}
// ... later ...
// Prepare write batch (potential race window here)
```

**Exploitation Scenario:**
1. Attacker makes concurrent requests to upload large files
2. Quota check passes for both requests simultaneously
3. Both requests write to storage, exceeding quota limits
4. User storage quota is bypassed

**Recommended Fix:**
- Implement atomic quota reservation using database transactions
- Use `SELECT ... FOR UPDATE` or equivalent locking mechanism
- Reserve quota before operation, release on failure, commit on success

**Git Evidence:**
```
commit 2f6cfbb6e6fdb43544a4925cd87bd8f28c58d657
Author: mdecimus <mauro@stalw.art>
Date:   Tue Sep 30 11:36:25 2025 +0200

    WebDAV: Reduce quota excess risk with lower TOCTOU window
```

---

### M2: Plain Text Password Storage Support

**Severity:** MEDIUM
**Status:** VULNERABLE (by design for legacy support)
**Location:** `/crates/directory/src/core/secret.rs:257`

**Description:**
The authentication system supports plain text password storage through the `{PLAIN}` and `{CLEAR}` password formats. While this is for legacy compatibility, it poses a significant risk if administrators inadvertently use this feature.

**Affected Code:**
```rust
// Line 257
"PLAIN" | "plain" | "CLEAR" | "clear" => Ok(hashed_secret == secret),
```

**Risk:**
- Database compromise exposes all user passwords immediately
- No protection against insider threats
- Violates security best practices

**Recommended Fix:**
1. Add configuration option to disable plain text password support
2. Log WARNING when plain text passwords are detected
3. Add migration tool to convert plain text to hashed passwords
4. Document security implications clearly

**Mitigation:**
Add to configuration:
```toml
[directory]
allow-plaintext-passwords = false  # Default to false
```

---

### M3: Weak Legacy Hash Algorithm Support

**Severity:** MEDIUM
**Status:** VULNERABLE (legacy compatibility)
**Location:** `/crates/directory/src/core/secret.rs` (various lines)

**Description:**
The system supports cryptographically weak hash algorithms for password verification:
- **MD5** (line 241-247): Broken since 2004, collision attacks trivial
- **SHA-1** (line 150-152, 175-186): Deprecated by NIST in 2011
- **Unix crypt** (line 254): Uses DES, extremely weak

**Affected Code:**
```rust
// Line 241-247: MD5 support
"MD5" => {
    let digest = md5::compute(secret.as_bytes());
    Ok(String::from_utf8(base64_encode(&digest[..]).unwrap_or_default()).unwrap()
        == hashed_secret)
}

// Line 175-186: SHA-1 support
"SHA" => {
    let mut hasher = Sha1::new();
    hasher.update(secret.as_bytes());
    // ... comparison
}
```

**Risk:**
- Pre-computed rainbow tables available for MD5/SHA-1
- Fast brute-force attacks possible (billions of hashes/second on GPU)
- No salt in some configurations increases vulnerability

**Recommended Fix:**
1. Add deprecation warnings when weak algorithms are detected
2. Implement automatic migration to modern algorithms (Argon2)
3. Configuration option to reject weak algorithms
4. Document upgrade path in migration guide

---

### M4: Potential Panic from Double Unwrap in OAuth Token Encoding

**Severity:** MEDIUM
**Status:** VULNERABLE
**Location:** `/crates/common/src/auth/oauth/token.rs:105`

**Description:**
OAuth token encoding contains a double `unwrap()` on base64 encoding operations without error handling, which could cause a panic and denial of service.

**Affected Code:**
```rust
// Line 105
Ok(String::from_utf8(base64_encode(&token).unwrap_or_default()).unwrap())
```

**Exploitation Scenario:**
1. Attacker triggers token generation with malformed data
2. First `unwrap()` succeeds but produces invalid UTF-8
3. Second `unwrap()` panics, crashing the server thread
4. Repeated requests cause denial of service

**Recommended Fix:**
```rust
Ok(String::from_utf8(base64_encode(&token).unwrap_or_default())
    .unwrap_or_else(|_| {
        trc::AuthEvent::Error
            .into_err()
            .ctx(trc::Key::Reason, "Failed to encode token")
            .caused_by(trc::location!())
    }))
```

---

### M5: Missing Authenticated Associated Data (AAD) in Encryption

**Severity:** MEDIUM
**Status:** IMPROVEMENT NEEDED
**Location:** `/crates/common/src/auth/oauth/crypto.rs:32`

**Description:**
AES-GCM-SIV encryption is used with empty Additional Authenticated Data (AAD), missing an opportunity to bind context to the ciphertext and prevent token substitution attacks.

**Affected Code:**
```rust
// Line 32
self.aes
    .encrypt_in_place(Nonce::from_slice(nonce), b"", bytes) // Empty AAD
    .map_err(|e| e.to_string())
```

**Risk:**
- Tokens could potentially be used in different contexts
- No cryptographic binding between token and its intended use
- Defense-in-depth opportunity missed

**Recommended Fix:**
```rust
// Include context as AAD
let aad = format!("{}:{}", grant_type.as_str(), account_id);
self.aes
    .encrypt_in_place(Nonce::from_slice(nonce), aad.as_bytes(), bytes)
    .map_err(|e| e.to_string())
```

---

## Low Severity Findings

### L1: Excessive Use of unwrap() in Production Code

**Severity:** LOW
**Status:** CODE QUALITY ISSUE
**Locations:** 2,486+ occurrences across 342 files

**Description:**
Extensive use of `.unwrap()` and `.expect()` throughout the codebase creates potential panic points that could lead to denial of service.

**Examples:**
- `/crates/imap/src/core/client.rs`: Multiple unreachable!() statements
- `/crates/jmap/src/email/set.rs`: unreachable!() in production paths
- Various files: `.unwrap()` on operations that could fail

**Risk:**
- Server crashes on unexpected input
- Denial of service through crafted requests
- Poor error messages for debugging

**Recommended Fix:**
1. Audit all unwrap() calls in non-test code
2. Replace with proper error handling using `?` operator
3. Add fuzzing tests to discover panic conditions
4. Use `#![forbid(unwrap_used)]` in new modules

---

### L2: X-Forwarded-For Header Parsing Complexity

**Severity:** LOW
**Status:** POTENTIAL BUG
**Location:** `/crates/http/src/request.rs:679-754`

**Description:**
Complex manual parsing of X-Forwarded-For header could lead to IP spoofing or parsing errors.

**Affected Code:**
```rust
// Lines 688-714: Complex manual parsing
let forwarded_for = req
    .headers()
    .get(header::FORWARDED)
    .and_then(|h| h.to_str().ok())
    .and_then(|h| {
        let h = h.to_ascii_lowercase();
        h.split_once("for=").and_then(|(_, rest)| {
            // Complex character-by-character parsing
            // ...
        })
    })
```

**Risk:**
- IP spoofing if parsing is incorrect
- Bypass of IP-based access controls
- Incorrect logging of client IPs

**Recommended Fix:**
- Use a well-tested library for parsing Forwarded header (RFC 7239)
- Add comprehensive tests for edge cases
- Document trusted proxy configuration clearly

---

### L3: No Rate Limiting on Failed Token Decryption

**Severity:** LOW
**Status:** MISSING CONTROL
**Location:** `/crates/common/src/auth/oauth/token.rs:108-216`

**Description:**
Failed OAuth token validation attempts are not rate-limited, allowing unlimited decryption attempts.

**Risk:**
- Brute force attacks on encrypted tokens
- Server resource exhaustion
- Timing attacks to differentiate valid vs invalid tokens

**Recommended Fix:**
```rust
// Add rate limiting before decryption attempt
self.is_auth_fail2banned(remote_ip, None).await?;

// Then attempt decryption
let token_info = self.validate_access_token(...).await?;
```

---

### L4: Information Disclosure in Error Messages

**Severity:** LOW
**Status:** INFORMATION LEAK
**Locations:** Various authentication error paths

**Description:**
Some error messages reveal too much information about system internals.

**Examples:**
```rust
// /crates/directory/src/core/secret.rs:259
_ => Err(trc::AuthEvent::Error
    .ctx(trc::Key::Reason, "Unsupported algorithm")
    .details(hashed_secret.to_string())),  // Leaks password hash
```

**Risk:**
- Reveals password hash formats
- Aids attacker reconnaissance
- May leak internal paths or configuration

**Recommended Fix:**
- Generic error messages for external users
- Detailed errors only in server logs
- Sanitize all user-facing error messages

---

### L5: Deterministic Nonce Generation

**Severity:** LOW
**Status:** DESIGN CONCERN
**Location:** `/crates/common/src/auth/oauth/token.rs:75-88`

**Description:**
OAuth token nonces are derived deterministically from password hash + grant type + timestamp, rather than using random nonces.

**Affected Code:**
```rust
// Lines 75-88
let mut hasher = blake3::Hasher::new();
if !password_hash.is_empty() {
    hasher.update(password_hash.as_bytes());
}
hasher.update(grant_type.as_str().as_bytes());
hasher.update(issued_at.to_be_bytes().as_slice());
hasher.update(expiry.to_be_bytes().as_slice());
let nonce = hasher.finalize().as_bytes()
    .iter()
    .take(SymmetricEncrypt::NONCE_LEN)
    .copied()
    .collect::<Vec<_>>();
```

**Risk:**
- Nonce reuse if timestamp collides (unlikely but possible)
- Reduces defense-in-depth for AES-GCM-SIV
- Not following best practices for authenticated encryption

**Note:** AES-GCM-SIV is specifically designed to be nonce-misuse resistant, so this is lower severity than with standard AES-GCM.

**Recommended Improvement:**
Use random nonces and include them in the token, or document why deterministic nonces are acceptable with GCM-SIV.

---

### L6: No CSRF Protection for State-Changing Operations

**Severity:** LOW
**Status:** MISSING CONTROL (if web UI exists)
**Location:** HTTP endpoints

**Description:**
No evidence of CSRF tokens in the codebase for state-changing operations in the web interface.

**Risk:**
- Cross-site request forgery attacks
- Unauthorized actions performed by authenticated users
- Account compromise through malicious links

**Recommended Fix:**
1. Implement CSRF tokens for all state-changing operations
2. Use SameSite cookie attribute
3. Validate Origin/Referer headers

**Note:** May not apply if all access is API-based with proper authentication.

---

### L7: Potential Integer Truncation in Bayes Classifier

**Severity:** LOW
**Status:** POTENTIAL BUG
**Location:** `/crates/spam-filter/src/modules/bayes.rs:509`

**Description:**
Number length is cast to `u8` without bounds checking.

**Affected Code:**
```rust
// Line 509
BayesInputToken::Raw([t, num.len() as u8].to_vec())
```

**Risk:**
- If `num.len() > 255`, value wraps around
- Could cause incorrect spam classification
- Potential for training data poisoning

**Recommended Fix:**
```rust
BayesInputToken::Raw([t, num.len().min(255) as u8].to_vec())
```

---

## Informational Findings

### I1: Minimal Use of Unsafe Code

**Status:** GOOD PRACTICE
**Finding:** Only 8 files contain `unsafe` blocks, primarily in low-level FFI and serialization code. This is excellent for a Rust project of this size.

**Locations:**
- `/crates/trc/src/ipc/channel.rs`
- `/crates/store/src/write/serialize.rs`
- `/crates/common/src/telemetry/tracers/journald.rs`
- And 5 others

**Recommendation:** Continue limiting unsafe code and ensure all unsafe blocks have safety comments.

---

### I2: Strong Cryptographic Choices

**Status:** GOOD PRACTICE
**Finding:** Modern cryptographic algorithms are preferred:
- **AES-256-GCM-SIV** for authenticated encryption (excellent choice)
- **BLAKE3** for key derivation (modern and fast)
- **Argon2** for password hashing (recommended by OWASP)
- **Rustls** for TLS (memory-safe alternative to OpenSSL)

**Recommendation:** Continue using these modern algorithms and deprecate legacy support.

---

### I3: Comprehensive Rate Limiting

**Status:** GOOD PRACTICE
**Finding:** Extensive rate limiting and fail2ban-style blocking:
- Authentication failures: 100/day default
- SMTP abuse: 35/day default
- Loitering: 150/day default
- Scanner detection: 30/day default
- HTTP path scanning detection

**Location:** `/crates/common/src/listener/blocked.rs`

**Recommendation:** Ensure these defaults are documented and tunable.

---

### I4: Security Policy Present

**Status:** GOOD PRACTICE
**Finding:** Comprehensive SECURITY.md file exists with:
- Clear vulnerability reporting process
- Response timelines (24h acknowledgment, 72h detailed response)
- Coordinated disclosure policy
- Legal safe harbor for researchers

**Location:** `/SECURITY.md`

**Recommendation:** Excellent. Continue maintaining this policy.

---

## Security Strengths

1. ✅ **Memory Safety:** Rust's ownership system prevents entire classes of vulnerabilities
2. ✅ **Modern Cryptography:** AES-256-GCM-SIV, BLAKE3, Argon2
3. ✅ **Defense in Depth:** Multiple layers of security (TLS, authentication, rate limiting)
4. ✅ **Minimal Unsafe Code:** Only 8 files use unsafe blocks
5. ✅ **Comprehensive Logging:** OpenTelemetry integration for audit trails
6. ✅ **Input Validation:** Size limits enforced on uploads, messages, requests
7. ✅ **Email Security:** DKIM, DMARC, SPF, ARC, DANE all supported
8. ✅ **Security Policy:** Clear vulnerability disclosure process
9. ✅ **Type Safety:** Strong typing prevents many injection attacks
10. ✅ **Fail2ban Integration:** Automatic blocking of abusive IPs

---

## Security Weaknesses

1. ❌ **Legacy Password Support:** Plain text and weak hashes (MD5, SHA-1, DES)
2. ❌ **TOCTOU Race Condition:** Quota enforcement still has narrow window
3. ❌ **Excessive unwrap():** 2,486+ potential panic points
4. ❌ **Missing AAD:** Authenticated encryption not using additional data
5. ❌ **Error Information Leakage:** Some errors reveal internal details
6. ❌ **Complex Manual Parsing:** X-Forwarded-For parsing could have bugs

---

## Recommendations by Priority

### Immediate Actions (Next Release)

1. **Fix M4:** Replace double unwrap in OAuth token encoding
2. **Fix L7:** Add bounds check in Bayes integer truncation
3. **Add M2 mitigation:** Configuration option to disable plain text passwords
4. **Add warnings:** Log when weak hash algorithms are detected

### Short Term (1-2 Months)

1. **Fix M1:** Implement atomic quota reservation with database transactions
2. **Fix M5:** Add AAD to authenticated encryption
3. **Fix L3:** Add rate limiting to token decryption attempts
4. **Audit L1:** Review and reduce unwrap() usage in critical paths

### Medium Term (3-6 Months)

1. **Fix M3:** Implement hash algorithm deprecation path
2. **Fix L2:** Replace manual X-Forwarded-For parsing with library
3. **Fix L4:** Sanitize all error messages
4. **Fix L6:** Add CSRF protection if web UI exists

### Long Term

1. Add fuzzing tests to discover panic conditions
2. Implement automatic password hash migration
3. Consider formal security audit by external firm
4. Add security regression tests for all findings

---

## Testing Recommendations

### Recommended Security Tests

1. **Fuzzing:**
   - Protocol parsers (IMAP, SMTP, HTTP)
   - Email message parsing
   - OAuth token validation
   - WebDAV request handling

2. **Penetration Testing:**
   - Authentication bypass attempts
   - Privilege escalation
   - Rate limit bypass
   - TOCTOU race condition exploitation

3. **Load Testing:**
   - Concurrent quota enforcement
   - Rate limit effectiveness
   - Denial of service resilience

4. **Regression Tests:**
   - All vulnerabilities found in this audit
   - Previous security fixes (TOCTOU, quota checks)

---

## Conclusion

Stalwart Mail Server demonstrates **strong security fundamentals** with its use of Rust for memory safety and modern cryptographic algorithms. The codebase shows evidence of security-conscious design with comprehensive rate limiting, fail2ban integration, and support for modern email security protocols.

However, **several areas need improvement:**
- Legacy password support creates unnecessary risk
- TOCTOU race condition needs complete fix
- Excessive unwrap() usage could lead to DoS
- Missing defense-in-depth opportunities (AAD, rate limiting)

**Overall Security Rating:** **B+ (Good)**
- Strong foundation with room for improvement
- No critical vulnerabilities identified
- Most issues are medium or low severity
- Following security best practices in most areas

**Recommended Next Steps:**
1. Address all MEDIUM severity findings in next release
2. Develop migration path away from legacy crypto
3. Implement comprehensive fuzzing test suite
4. Consider external security audit for compliance requirements

---

## Appendix A: Vulnerability Summary Table

| ID | Severity | Title | Status | Priority |
|----|----------|-------|--------|----------|
| M1 | MEDIUM | TOCTOU Race in Quota | Partial | HIGH |
| M2 | MEDIUM | Plain Text Passwords | Vulnerable | HIGH |
| M3 | MEDIUM | Weak Hash Algorithms | Vulnerable | MEDIUM |
| M4 | MEDIUM | Double Unwrap Panic | Vulnerable | HIGH |
| M5 | MEDIUM | Missing AAD in Encryption | Improvement | MEDIUM |
| L1 | LOW | Excessive unwrap() | Quality | MEDIUM |
| L2 | LOW | X-Forwarded-For Parsing | Potential | LOW |
| L3 | LOW | No Token Decrypt Rate Limit | Missing | MEDIUM |
| L4 | LOW | Error Info Disclosure | Leak | LOW |
| L5 | LOW | Deterministic Nonce | Design | LOW |
| L6 | LOW | No CSRF Protection | Missing | LOW |
| L7 | LOW | Integer Truncation | Potential | MEDIUM |

---

## Appendix B: Files Reviewed

### Key Security Files Analyzed

- `/crates/directory/src/core/secret.rs` (272 lines) - Password verification
- `/crates/common/src/listener/blocked.rs` (335 lines) - Rate limiting
- `/crates/http/src/request.rs` (856 lines) - HTTP request handling
- `/crates/common/src/auth/oauth/token.rs` (250 lines) - OAuth tokens
- `/crates/common/src/auth/oauth/crypto.rs` (48 lines) - Encryption
- `/crates/spam-filter/src/modules/bayes.rs` (529 lines) - Spam filter
- `/crates/dav/src/calendar/update.rs` - TOCTOU fix
- `/crates/dav/src/card/update.rs` - TOCTOU fix

### Total Code Reviewed

- **Lines analyzed:** ~5,000+ lines in security-critical paths
- **Files examined:** 50+ files across all crates
- **Git commits reviewed:** 5 security-relevant commits

---

**Report End**

*This audit was performed by AI analysis and should be complemented with manual code review and penetration testing for production deployments.*
