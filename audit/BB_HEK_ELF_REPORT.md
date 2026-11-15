# BB — HEK asset format and native JavaScript runtime audit

**Date:** 2026-11-15  
**Method:** Offline, read-only static inspection of repository files.  
**Passing CI run:** https://github.com/zaidanfaiz/BB/actions/runs/43669931246

## HEK inventory

| Metric | Observed |
| --- | ---: |
| Candidate .js/.json/.jsc/.bin/.dbbin assets | 6,930 |
| Assets with HEK prefix | 6,817 |
| HEK .json | 6,339 |
| HEK .js | 443 |
| HEK .bin | 24 |
| HEK .dbbin | 11 |
| Non-HEK .js | 14 |
| Non-HEK .json | 86 |
| Non-HEK .jsc | 13 |
| HEK assets with score/combo/rank-like filenames | 137 |
| Distinct SHA-256 hashes of first 64 bytes among HEK assets | 3,398 |
| Median HEK file size | 206 bytes |

All HEK-prefixed assets examined begin with one of two *observed* eight-byte sequences:

- `48 45 4b 3a 01 00 01 02` — 443 assets, all JavaScript.
- `48 45 4b 3a 03 00 01 02` — 6,374 assets, JSON/bin/dbbin.

**Interpretation:** The data exhibits a common binary wrapper with a byte strongly correlated with asset type. The inspection does not establish whether the payload is encrypted, compressed, or encoded with a proprietary scheme. Entropy sampling is non-diagnostic for many very small files and must not be presented as proof of encryption.

## Native library metadata

| Library | Size | Architecture | Full `.symtab` | Dynamic function symbol rows | Key observations |
| --- | ---: | --- | --- | ---: | --- |
| `libcocos2djs.so` | 35,074,752 B | ELF64 AArch64 | No | 8,203 | Static markers: Cocos2d, ScriptEngine, runScript, evalString, JavaScript, V8, JNI and AES-related name |
| `libtask.so` | 6,824,872 B | ELF64 AArch64 | No | 3,742 | Depends on `libcocos2djs.so`; Cocos2d marker |
| `libmmkv.so` | 597,000 B | ELF64 AArch64 | No | 439 | MMKV and JNI markers, consistent with a native key-value store component |

**Negative observation:** The literal byte sequence `HEK:` was not present in any of these three scanned ELF binaries. Likewise the static scan did not detect the string `xxtea` in them. This does **not** rule out dynamically resolved functions, other native libraries, obfuscation or a loader implemented elsewhere.

## Score research conclusion

These findings strengthen the evidence for a Cocos2d JavaScript runtime, but **do not locate a trusted score calculation or persistent high-score record**. File names with score/combo are not function-call evidence, and a static runtime marker is not proof of actual execution.

No Game Guardian address, in-memory score modification, score submission manipulation, or third-party leaderboard exploit was demonstrated.

## Next authorized tests

1. Compare identical versions of assets from a developer-owned test build to determine when and where packaging is applied, without deriving bypass code for a third-party game.
2. Add source-level logging to a controlled Cocos2d-JS sample that records scoring events, save state and UI refreshes.
3. Validate that the sandbox's authoritative score state is distinct from displayed text.
4. Use read-only instrumentation and report reproducible behavior; avoid changing production accounts or external leaderboards.

Raw evidence is in GitHub Actions artifact `bb-static-security-report`: `hek-inventory.json` and `elf-runtime-inventory.json`. Note the report is a **partial static audit**, not an exhaustive security assessment.
