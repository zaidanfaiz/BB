#!/usr/bin/env python3
"""Read-only ELF metadata and runtime-marker inventory for native Cocos2d.

This script does not disassemble, decrypt, patch, hook or execute any game code.
"""
from pathlib import Path
import json
import os
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "audit-output"
TARGETS = [
    "lib/arm64-v8a/libcocos2djs.so",
    "lib/arm64-v8a/libtask.so",
    "lib/arm64-v8a/libmmkv.so",
]
MARKERS = {
    "hek_literal": rb"HEK:",
    "cocos2d": rb"(?i)cocos2d",
    "script_engine": rb"(?i)scriptengine|script_engine",
    "run_script": rb"(?i)runscript|run_script",
    "eval_string": rb"(?i)evalstring|eval_string",
    "javascript": rb"(?i)javascript",
    "spidermonkey": rb"(?i)spidermonkey",
    "quickjs": rb"(?i)quickjs",
    "v8_namespace": rb"v8::",
    "jni_on_load": rb"JNI_OnLoad",
    "jni_class_bridge": rb"Java_org_cocos2dx",
    "xxtea_name": rb"(?i)xxtea",
    "aes_name": rb"(?i)\bAES[_-]",
    "mmkv_name": rb"(?i)\bMMKV\b",
}

def run_readelf(path, *options):
    result = subprocess.run(["readelf", "-W", *options, str(path)], capture_output=True,
                            text=True, timeout=35, check=False)
    return result.stdout if result.returncode == 0 else ""

def analyze(path):
    result = {"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size}
    with path.open("rb") as f:
        head = f.read(64)
    if not head.startswith(b"\x7fELF"):
        return {**result, "error": "Not ELF"}
    header = run_readelf(path, "-h")
    dyn = run_readelf(path, "-d")
    sections = run_readelf(path, "-S")
    symbols = run_readelf(path, "-s")
    result["machine"] = (re.search(r"Machine:\s*(.+)", header) or [None, None])[1]
    result["elf_class"] = (re.search(r"Class:\s*(.+)", header) or [None, None])[1]
    result["needed_libraries"] = re.findall(r"\(NEEDED\).*?Shared library: \[([^\]]+)\]", dyn)
    result["has_symbol_table"] = ".symtab" in sections
    result["has_dynamic_symbol_table"] = ".dynsym" in sections
    result["dynamic_function_symbol_rows"] = sum(
        bool(re.search(r"\bFUNC\b", line)) for line in symbols.splitlines())
    result["jni_symbol_samples"] = [
        line.strip().split()[-1] for line in symbols.splitlines()
        if re.search(r"\b(?:Java_|JNI_OnLoad)", line)
    ][:35]
    payload = path.read_bytes()
    result["static_marker_presence"] = {
        k: bool(re.search(pattern, payload)) for k, pattern in MARKERS.items()
    }
    result["limitations"] = (
        "String/symbol marker presence is not proof of call graph, decoder logic, or score authority."
    )
    return result

def main():
    OUT.mkdir(exist_ok=True)
    records = []
    for name in TARGETS:
        path = ROOT / name
        if path.exists():
            records.append(analyze(path))
        else:
            records.append({"path": name, "error": "Not in repository"})
    report = {
        "scope": "Static ELF format, dependencies, symbol and marker inventory only",
        "libraries": records,
        "cautions": [
            "Names in ELF sections do not establish how game score is calculated",
            "An HEK literal inside an ELF does not establish that this binary decrypts HEK",
            "No crypto routines were reverse-engineered or decrypted",
            "The application was not run and no live game or leaderboard was tested",
        ],
    }
    (OUT / "elf-runtime-inventory.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["\n## Native Cocos2d / JS runtime inventory"]
    for entry in records:
        present = [k for k, v in entry.get("static_marker_presence", {}).items() if v]
        lines += [
            "- " + entry["path"] + ": " +
            (entry["error"] if "error" in entry else
             "machine=" + str(entry["machine"]) +
             ", symtab=" + str(entry["has_symbol_table"]) +
             ", NEEDED=" + ", ".join(entry["needed_libraries"]) +
             ", static markers=" + ", ".join(present))
        ]
    lines += [
        "- Markers do not demonstrate function execution or identify a decoder.",
        "- Evidence in elf-runtime-inventory.json.",
    ]
    md = "\n".join(lines) + "\n"
    with (OUT / "audit.md").open("a", encoding="utf-8") as f:
        f.write(md)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(md)
    print(md)

if __name__ == "__main__":
    main()
