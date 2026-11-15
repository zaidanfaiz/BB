# BB — Android APK static security review

**Date:** 2026-11-15
**Scope:** Extracted APK snapshot committed to zaidanfaiz/BB; static, read-only examination. No application instance, account, leaderboard, or service was attacked or instrumented.
**CI evidence:** https://github.com/zaidanfaiz/BB/actions/runs/43668621431
**Machine-readable attachments:** audit.json, deep-audit.json, policy-review.json, osv-findings.json and bb-dependencies.cdx.json in the CI artifact.

## Priority findings

| Priority | Observation | Evidence | Status |
| --- | --- | --- | --- |
| Priority review — provider packaging | CrossPromotionDataProvider is declared exported, with normal read permission c.R and signature write permission c.W. A follow-up DEX audit did **not** find its class definition in the 14 packaged DEX files. | AndroidManifest.xml; policy-review.json; provider-review.json | Configuration confirmed; runtime provider instantiation and information disclosure **not demonstrated** |
| Medium — transport hardening | Network base-config and a domain-config both specify cleartextTrafficPermitted=true. Actual HTTP usage and sensitive payload exposure were not observed. | res/xml/network_security_config.xml; deep-audit.json | Confirmed configuration, impact unverified |
| Medium — dependency review | OSV scanner matched com.google.guava:guava 33.3.1-android to GHSA-xxph-c9ww-hj94 / CVE-2026-102554 (highest reported severity 8.2). Runtime use of the affected code path is unknown. | res/raw/aboutlibraries.json; osv-findings.json | Version match, not confirmed application exploit |
| Medium — backup data review | Manifest enables allowBackup. The generic backup/data extraction rules in the APK include no explicit include/exclude entries. Effective manifest resource mapping, platform versions, and stored data still require verification. | AndroidManifest.xml; res/xml/backup_rules.xml; res/xml/data_extraction_rules.xml | Confirmed config, confidentiality risk unverified |
| Low / review | 11 Unity Ads domain entries in the network configuration contain a trailing slash, unlike the hostname-only domain syntax documented by Android. | res/xml/network_security_config.xml; policy-review.json | Static syntax concern only |
| Low / review | Two native libraries have no detectable full RELRO: lib/arm64-v8a/libnesec.so and lib/arm64-v8a/libnesec-x86.so. None of 31 inspected libraries request an executable GNU_STACK. | deep-audit.json | Hardening observation, no exploitability claim |

The provider follow-up checked 14 of 14 DEX files without parse errors. The named exported provider class was **not defined** in those files. This is a packaging/runtime verification item, not evidence of a working data-exposure path. See [BB_PROVIDER_REVIEW.md](BB_PROVIDER_REVIEW.md).\n\n## Android component inventory

- 23 exported activities, aliases, receivers, services or providers.
- 6 use declared component permission attributes (including read/write permission attributes).
- 5 are launcher-related aliases.
- 4 involve VIEW deep-link or authentication intents.
- A special concern is the *strength* of c.R, not merely whether a permission is present.
- Two permission references owned by Google integration components were not declared *by this app*. This does not prove those permissions are unresolved at runtime; other installed packages or platform conventions may supply them.

## Score integrity research limits

- 135 file paths match score/combo/high-score/leaderboard naming criteria, but names alone do not identify the authoritative scoring state.
- 6,782 files have HEK-prefixed content, preventing direct JavaScript/JSON data-flow analysis without an authorized decrypted source build.
- No live test has established a reliable Game Guardian memory address, local save schema, authoritative server-side score validation rule, or leaderboard acceptance flow.
- Therefore, **no score manipulation exploit has been confirmed** and this report is not a cheat-script specification.

## Suggested authorized verification

1. First confirm that the CrossPromotionDataProvider class is packaged or dynamically loaded in the real installable app; only then inspect any returned data and enforce least-privilege export/permissions.
2. Restrict cleartext traffic to an explicitly justified set of hosts; review app behavior before changing legacy SDK requirements.
3. Compare embedded Guava version with the patched release and confirm whether affected API code paths are reachable; remediate by updating the dependency where appropriate.
4. Trace which backup rules the manifest actually references and remove sensitive information from backup.
5. Correct hostname-only network config domain declarations and verify app startup/connectivity on supported Android versions.
6. In a first-party test game, instrument scoring events and persistence to establish the difference between UI score and authoritative score.

## Evidence and interpretation constraints

This repository contains unpacked APK artifacts, not the complete original Android source project. Static flags and dependency version matches are **audit findings**, not a list of working exploits. All further dynamic testing needs authorization from the application's owner.

References:
- Android custom permission risk: https://developer.android.com/privacy-and-security/risks/custom-permissions
- Android protection level constants: https://developer.android.com/reference/android/content/pm/PermissionInfo
- Android network security config: https://developer.android.com/privacy-and-security/security-config
