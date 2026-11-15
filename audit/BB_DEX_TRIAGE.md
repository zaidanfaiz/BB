# BB — Multidex feasibility assessment

**Date:** 2026-11-15  
**CI run:** https://github.com/zaidanfaiz/BB/actions/runs/43669188060

## What was examined

Read-only enumeration of standard DEX string IDs, class definitions, and method IDs in the 14 `classes*.dex` files committed to this repository. This is *not* a call-graph, native library disassembly, runtime tracing, or a score exploit demonstration.

| Statistic | Result |
| --- | ---: |
| DEX files parsed | 14 / 14 |
| Class definitions | 76,018 |
| Method IDs | 710,628 |
| String IDs | 739,523 |
| Classes with score/combo/leaderboard-related names | 49 |
| Method IDs with score/combo/leaderboard-related names | 218 |
| Score-named methods under identified first-party prefixes | 0 |

### Interpretation

Most visible matching methods are in **third-party dependencies**, for example:

- `com.google.android.gms.games.leaderboard.Leaderboard` — `getLeaderboardId`, `getScoreOrder`
- `com.facebook.gamingservices.TournamentShareDialog` — `getScore`, `setScore`
- `com.facebook.gamingservices.cloudgaming.GameFeaturesLibrary` — `postSessionScore`, `postSessionScoreAsync`
- `androidx.media3.exoplayer.mediacodec.MediaCodecUtil` — `sortByScore` / codec preference scoring
- `com.google.firebase.messaging.Metadata` — `isGmscorePresent` (Google Play services name, unrelated to game scores)

The observed string tables include **references to Cocos2d**, but the triage did not identify class definitions under the conventional `org.cocos2dx.javascript` prefix. This does not prove these classes are absent at runtime: different namespaces, obfuscation, alternate loaders, or an incomplete extracted artifact may explain it.

## Outcome

**Not demonstrated:** No stable Game Guardian address, in-game score variable, score persistence field, or authoritative server acceptance rule has been found in DEX metadata.

**Feasibility assessment:** DEX string/class/method inspection alone is **unlikely to be sufficient** to implement a reliable in-game score change. The native `libcocos2djs.so` runtime and HEK-wrapped `assets/assets/main/index.8349a.js` are important architectural components, but their role in score authority is not confirmed by this scan.

The exact 14-file evidence is exported as `dex-triage.json` in the CI artifact. For a permitted first-party test game, build source-level score instrumentation and compare display state, persistence state, and server-accepted values without targeting third-party game services.
