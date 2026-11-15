# BB — Exported ContentProvider / DEX declaration review

**Date:** 2026-11-15  
**CI evidence:** https://github.com/zaidanfaiz/BB/actions/runs/43673783061  
**Scope:** APK manifest and 14 packaged `classes*.dex` files; read-only analysis. No provider was invoked.

## Verified metadata

| Item | Observation |
| --- | --- |
| Provider declarations in manifest | 14 |
| Explicitly exported providers | 1 |
| Packaged standard DEX files parsed | 14 / 14 |
| DEX parsing errors | 0 |
| Exported provider | `org.cocos2dx.javascript.cross.CrossPromotionDataProvider` |
| Read permission | `c.R` — declared `normal` |
| Write permission | `c.W` — declared `signature` |
| Class definition for exported provider in packaged DEX | **Not found** |
| Other 13 providers | Explicitly non-exported; matching class definitions found |

## Interpretation

The manifest requests an exported provider with weak read-permission protection. However, the packaged 14 DEX files do **not** define the named `CrossPromotionDataProvider` class. This raises a **packaging / runtime class-loading question**, not a demonstrated read-data exposure.

Possible explanations include incomplete APK extraction, deferred class loading from a separately packaged component, a stale manifest declaration, or a packaging defect. This offline inspection does not select among them. An exported manifest entry does not establish that a provider can instantiate and return any data.

The 13 other explicitly non-exported providers have DEX class definitions; this does not assess any internal logic or privacy of those components.

## Next steps for an authorized application owner

1. Confirm whether the sample represents the complete, installable APK or is missing split/dynamic modules.
2. Check app startup and provider initialization exceptions from an authorized development device, without querying application data.
3. Inspect the original Java/Kotlin source and merged manifest for the provider class declaration.
4. If it is intentionally exported, assess the actual returned data and tighten access according to minimum privileges; if unused, remove the stale declaration.
5. Keep runtime and score-integrity claims separate: **this finding does not identify a score variable, memory address, leaderboard validation weakness, or cheat path.**

## Reproducibility

The script `tools/bb_provider_review.py` decodes the binary manifest and checks class definitions + declared ContentProvider entry-point method metadata. The CI artifact includes `provider-review.json` and the step summary. It does not disassemble method bodies, invoke providers, access private app data or patch gameplay.
