# Phishing Triage Report

- **Generated (UTC):** 2025-12-16 03:33:38Z
- **Risk:** **High**
- **Score:** **98/100**

## Email Summary
- **Subject:** Action Required: Verify your account
- **From:** PayPal Support <support@paypal.com>
- **Reply-To:** PayPal Support <secure@xn--paypa1-9za.com>
- **To:** user@example.com
- **Date:** Mon, 15 Dec 2025 20:15:00 -0500
- **Message-ID:** <sample-message-id@example.com>

## Key Findings
- (+25) From and Reply-To domains do not match.
- (+20) SPF result is fail.
- (+20) DKIM result is fail.
- (+20) DMARC result is fail.
- (+5) Email contains 1 URL(s).
- (+8) 1 URL domain(s) appear punycode-encoded (possible lookalike).

## Authentication Signals (Best-Effort)
- **SPF:** fail
- **DKIM:** fail
- **DMARC:** fail

## URLs
- https://www.xn--paypa1-9za.com/login?session=123 — _punycode/lookalike, domain age: (placeholder)_ (domain: `www.xn--paypa1-9za.com`)

## Attachments
- None.

## Header Checks
- **From domain:** `paypal.com`
- **Reply-To domain:** `xn--paypa1-9za.com`
- **From/Reply-To mismatch:** `True`

## Body Preview (first 500 chars)
```
Your account has been limited. Verify immediately:
https://www.xn--paypa1-9za.com/login?session=123
```