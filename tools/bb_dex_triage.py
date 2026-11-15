#!/usr/bin/env python3
"""Read-only multidex metadata triage.

Examines DEX headers, string/type/class/method ID tables without loading,
patching, decrypting, or executing application code. Symbol names may be
obfuscated; findings do not prove control of gameplay scores.
"""
import collections
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "audit-output"
SCORE = re.compile(r"(?i)(?:high.?score|leader.?board|ranking|score|combo|settle|game.?over|achieve)")
GAME = re.compile(r"(?i)(?:game|board|cocos|score|level|puzzle|block|juggle)")
MAX_IDENTIFIERS = 2_000_000

def read_u32(buf, at):
    if at < 0 or at + 4 > len(buf):
        raise ValueError("Invalid DEX offset")
    return struct.unpack_from("<I", buf, at)[0]

def block(buf, off, count, size):
    if count > MAX_IDENTIFIERS or off < 0 or off + count * size > len(buf):
        raise ValueError("DEX ID section bounds invalid")
    return range(off, off + count * size, size)

def uleb128(buf, at):
    v = 0
    for shift in (0, 7, 14, 21, 28):
        if at >= len(buf):
            raise ValueError("Invalid DEX ULEB128")
        c = buf[at]
        at += 1
        v |= (c & 0x7f) << shift
        if c < 128:
            return v, at
    raise ValueError("Overlong DEX ULEB128")

def dex_strings(buf):
    count, off = read_u32(buf, 0x38), read_u32(buf, 0x3c)
    strings = []
    for pos in block(buf, off, count, 4):
        dataoff = read_u32(buf, pos)
        _, start = uleb128(buf, dataoff)
        stop = buf.find(b"\0", start, min(len(buf), start + 65536))
        if stop < 0:
            raise ValueError("Invalid DEX string_data_item")
        strings.append(buf[start:min(stop, start + 1024)].decode("utf-8", errors="replace"))
    return strings

def read_dex(path):
    data = path.read_bytes()
    if len(data) < 0x70 or not data.startswith(b"dex\n"):
        raise ValueError("Not a standard DEX header")
    strings = dex_strings(data)
    ntypes, otypes = read_u32(data, 0x40), read_u32(data, 0x44)
    types = [strings[read_u32(data, off)] for off in block(data, otypes, ntypes, 4)]
    nclasses, oclasses = read_u32(data, 0x60), read_u32(data, 0x64)
    classes = [types[read_u32(data, off)] for off in block(data, oclasses, nclasses, 32)]
    nmethods, omethods = read_u32(data, 0x58), read_u32(data, 0x5c)
    methods = []
    for offset in block(data, omethods, nmethods, 8):
        typeindex, _protoindex, stringindex = struct.unpack_from("<HHI", data, offset)
        if typeindex >= len(types) or stringindex >= len(strings):
            raise ValueError("Invalid method ID")
        methods.append((types[typeindex], strings[stringindex]))
    return strings, classes, methods

def category(owner):
    if owner.startswith(("Lorg/cocos2dx/javascript/", "Lcom/block/juggle/")):
        return "application"
    if owner.startswith("Lorg/cocos2dx/"):
        return "engine"
    return "dependencies_or_unknown"

def namespace(s):
    if not s.startswith("L") or "/" not in s:
        return "(other)"
    return "/".join(s[1:].split("/")[:3])

def scan():
    OUT.mkdir(exist_ok=True)
    report = {"scope": "Read-only static DEX symbol metadata, not proof of a score exploit",
              "files": [], "limitations": [
                  "Score-related symbols may belong to SDKs rather than gameplay logic.",
                  "Unrecognizable obfuscated names cannot prove absence of logic.",
                  "Cocos2d JS may run in encrypted HEK assets or in native libcocos2djs.so.",
                  "No memory locations, save formats, server score validation or Game Guardian behaviors were tested."
              ]}
    for path in sorted(ROOT.glob("classes*.dex"), key=lambda p: int(p.stem[7:] or 1)):
        entry = {"file": path.name, "bytes": path.stat().st_size}
        try:
            strings, classes, methods = read_dex(path)
            count = collections.Counter(category(c) for c in classes)
            top = collections.Counter(namespace(c) for c in classes)
            relevant_classes = [c for c in classes if SCORE.search(c)]
            app_classes = [c for c in classes if category(c) == "application"]
            app_score_classes = [c for c in app_classes if SCORE.search(c)]
            relevant_methods = [(c, n) for c, n in methods if SCORE.search(n)]
            app_score_methods = [(c, n) for c, n in relevant_methods if category(c) == "application"]
            app_game_methods = [(c, n) for c, n in methods if category(c) == "application" and GAME.search(n)]
            entry.update({
                "status": "parsed", "string_ids": len(strings), "class_defs": len(classes),
                "method_ids": len(methods), "class_origins": dict(count),
                "top_namespaces": top.most_common(12),
                "score_named_classes_all_count": len(relevant_classes),
                "score_named_methods_all_count": len(relevant_methods),
                "score_named_classes_application": app_score_classes[:50],
                "score_named_methods_application": [
                    {"class": c, "name": n} for c, n in app_score_methods[:70]],
                "score_named_methods_application_count": len(app_score_methods),
                "game_named_methods_application_count": len(app_game_methods),
                "application_class_examples": app_classes[:30],
                "class_names_matching_cocos_or_game": [c for c in classes if re.search(r"(?i)cocos2dx|block|juggle|appactivity|crosspromotiondataprovider", c)][:100],
                "string_id_mentions_cocos": sum("cocos2dx" in t.lower() for t in strings),
                "string_id_mentions_app_activity": sum("appactivity" in t.lower() for t in strings),
                "all_score_named_method_samples": [{"class": c, "name": n, "origin": category(c)} for c, n in relevant_methods[:45]],
            })
        except (OSError, ValueError, IndexError) as exc:
            entry["status"] = "unparsed"
            entry["reason"] = str(exc)[:160]
        report["files"].append(entry)
    (OUT / "dex-triage.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    parsed = [e for e in report["files"] if e["status"] == "parsed"]
    lines = ["\n## Multidex class/method triage",
             f"- DEX files found: **{len(report['files'])}**, parsed: **{len(parsed)}**.",
             f"- Declared classes in DEX: **{sum(x['class_defs'] for x in parsed)}**.",
             f"- Application-namespace classes: **{sum(x['class_origins'].get('application',0) for x in parsed)}**.",
             f"- App-namespace score-named methods: **{sum(x['score_named_methods_application_count'] for x in parsed)}**.",
             f"- App-namespace game-named methods: **{sum(x['game_named_methods_application_count'] for x in parsed)}**.",
             "- Per-file evidence in dex-triage.json.",
             "- Names/strings are not proof of score authority or an exploitable state."]
    for e in report["files"]:
        lines.append(f"- {e['file']}: {e['status']}; {e.get('class_defs','?')} classes, {e.get('class_origins',{}).get('application','?')} app-namespace classes, {e.get('score_named_methods_application_count','?')} app score-named methods.")
    rendered = "\n".join(lines) + "\n"
    (OUT / "audit.md").open("a", encoding="utf-8").write(rendered)
    import os
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(rendered[:18000])
    print(rendered)

if __name__ == "__main__":
    scan()
