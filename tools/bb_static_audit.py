#!/usr/bin/env python3
"""Read-only static security inventory for an extracted Android APK.

No network calls, payload generation, or changes to game files are performed.
Findings are hypotheses until confirmed with authorized runtime testing.
"""
import collections
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "audit-output"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
TEXT_EXT = {".js", ".json", ".xml", ".txt", ".properties", ".yaml", ".yml", ".md", ".cfg", ".ini"}
SCORE_NAME = re.compile(r"score|combo|leaderboard|rank|high.?score|save.?data|score.?settlement", re.I)
SUSPICIOUS_VALUE = re.compile(
    r"""(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token|private[_-]?key|password)\s*[:=]\s*["']([^"'\r\n]{8,})"""
)
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")

def git_files():
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [ROOT / os.fsdecode(x) for x in raw.split(b"\0") if x]

def finding(items, priority, category, detail, evidence=None):
    obj = {"priority": priority, "category": category, "detail": detail, "certainty": "needs_manual_review"}
    if evidence is not None:
        obj["evidence"] = evidence
    items.append(obj)

def analyze_manifest(path, items):
    result = {"parsed": False, "components": [], "error": None, "app_flags": {}}
    if not path.exists():
        result["error"] = "AndroidManifest.xml not found"
        return result
    try:
        from androguard.core.axml import AXMLPrinter
        root = AXMLPrinter(path.read_bytes()).get_xml_obj()
        if root is None:
            raise ValueError("AXML returned no root")
        result["parsed"] = True
        app = root.find("application")
        if app is None:
            raise ValueError("application element missing")
        attr = lambda node, key: node.get(ANDROID_NS + key)
        for key in ("debuggable", "allowBackup", "usesCleartextTraffic", "testOnly", "networkSecurityConfig"):
            result["app_flags"][key] = attr(app, key)
        if attr(app, "debuggable") == "true":
            finding(items, "high", "android_debuggable", "Application declares android:debuggable=true")
        if attr(app, "allowBackup") == "true":
            finding(items, "medium", "android_backup", "Application explicitly enables Android backup; review data exclusions")
        if attr(app, "usesCleartextTraffic") == "true":
            finding(items, "medium", "android_cleartext", "Application explicitly allows cleartext network traffic")
        for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
            for elem in app.findall(kind):
                exported = attr(elem, "exported")
                inferred = exported == "true" or (exported is None and elem.find("intent-filter") is not None)
                if not inferred:
                    continue
                name = attr(elem, "name") or "(unnamed)"
                permission = attr(elem, "permission") or attr(app, "permission")
                summary = {"type": kind, "name": name, "exported": exported, "permission": permission}
                result["components"].append(summary)
                if permission is None:
                    finding(items, "review", "exported_component",
                            f"Exported {kind} without an explicit component/application permission; inspect its behavior",
                            name)
        return result
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
        finding(items, "review", "manifest_unparsed",
                "AndroidManifest.xml could not be decoded; component/permission audit is incomplete")
        return result

def main():
    OUTPUT.mkdir(exist_ok=True)
    paths = git_files()
    findings = []
    extensions = collections.Counter()
    encrypted = collections.Counter()
    large = []
    score_related = []
    secrets_review = []
    processed = 0
    for path in paths:
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        ext = path.suffix.lower()
        extensions[ext or "(none)"] += 1
        try:
            size = path.stat().st_size
            if size >= 5_000_000:
                large.append({"path": rel, "bytes": size})
            if SCORE_NAME.search(rel) and ext in {".js", ".json", ".jsc", ".dbbin"}:
                score_related.append(rel)
            if ext not in TEXT_EXT:
                continue
            with path.open("rb") as stream:
                head = stream.read(4)
                if head == b"HEK:":
                    encrypted[ext] += 1
                    continue
                if size > 3_000_000:
                    continue
                stream.seek(0)
                data = stream.read()
            if b"\x00" in data[:256]:
                continue
            processed += 1
            if PRIVATE_KEY.search(data):
                secrets_review.append({"file": rel, "type": "private_key_marker", "value_redacted": True})
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if SUSPICIOUS_VALUE.search(text):
                secrets_review.append({"file": rel, "type": "possible_embedded_credential", "value_redacted": True})
        except (OSError, ValueError):
            continue
    if secrets_review:
        finding(findings, "high", "embedded_credentials",
                f"{len(secrets_review)} potential credential markers in plaintext assets; verify and rotate genuine secrets")
    if encrypted:
        finding(findings, "review", "encrypted_assets",
                "HEK-prefixed assets prevent full JavaScript/JSON data-flow review. This is an audit limitation, not proof of a flaw")
    manifest = analyze_manifest(ROOT / "AndroidManifest.xml", findings)
    report = {
        "scope": "Repository static inventory only; NOT a penetration test or live score exploit",
        "files": len(paths),
        "text_files_inspected": processed,
        "extension_counts": dict(extensions.most_common()),
        "hek_files_by_extension": dict(encrypted),
        "large_files": sorted(large, key=lambda x: x["bytes"], reverse=True)[:40],
        "score_named_assets": sorted(set(score_related))[:150],
        "credential_markers_redacted": secrets_review[:100],
        "manifest": manifest,
        "findings": findings,
        "unverified": [
            "Where the authoritative score is calculated and stored",
            "Whether high score/leaderboards require server-side validation",
            "Whether session, replay, or anti-tamper checks are enforced",
            "All vulnerabilities and CVEs in native and bundled third-party libraries",
        ],
    }
    (OUTPUT / "audit.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# BB extracted-APK static security audit", "",
        f"- Tracked entries: **{len(paths)}**",
        f"- Plaintext assets inspected: **{processed}**",
        f"- HEK-prefixed JS/JSON assets: **{sum(encrypted.values())}**",
        f"- Score/leaderboard-named assets: **{len(score_related)}**",
        f"- Manifest parsed: **{manifest['parsed']}**",
        f"- Potential credential markers (values redacted): **{len(secrets_review)}**", "",
        "## Preliminary findings",
        "These are review flags, **not confirmed exploits**.", "",
    ]
    for item in findings[:100]:
        lines.append(f"- **{item['priority'].upper()} / {item['category']}**: {item['detail']}")
        if item.get("evidence"):
            lines.append(f"  - Evidence: \`{item['evidence']}\`")
    lines += ["", "## Unverified controls"]
    lines += [f"- {item}" for item in report["unverified"]]
    lines += ["", "## Notes", "- Do not use this inventory as proof that scores can be altered.",
              "- Dynamic verification requires an authorized instrumented test build.",
              "- Keep the repository and reports free of credentials and personal data."]
    markdown = "\n".join(lines) + "\n"
    (OUTPUT / "audit.md").write_text(markdown, encoding="utf-8")
    print(markdown[:12000])
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(markdown[:18000])

if __name__ == "__main__":
    main()
