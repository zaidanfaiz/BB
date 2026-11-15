#!/usr/bin/env python3
"""Read-only Android configuration/ELF audit. No active tests or score modifications."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "audit-output"
NS = "{http://schemas.android.com/apk/res/android}"
CONFIG_FILES = (
    "res/xml/network_security_config.xml",
    "res/xml/backup_rules.xml",
    "res/xml/data_extraction_rules.xml",
    "res/xml/appsflyer_backup_rules.xml",
    "res/xml/appsflyer_data_extraction_rules.xml",
)

def a(node, attr):
    return node.get(NS + attr)

def xml(path):
    from androguard.core.axml import AXMLPrinter
    try:
        return AXMLPrinter(path.read_bytes()).get_xml_obj(), None
    except Exception as error:
        return None, f"{type(error).__name__}: {str(error)[:200]}"

def intent_filters(node):
    out = []
    for fil in node.findall("intent-filter"):
        out.append({
            "actions": [a(n, "name") for n in fil.findall("action")],
            "categories": [a(n, "name") for n in fil.findall("category")],
            "data": [{key: a(n, key) for key in ("scheme", "host", "path", "pathPrefix", "mimeType")
                      if a(n, key)} for n in fil.findall("data")],
            "autoVerify": a(fil, "autoVerify"),
        })
    return out

def manifest(root):
    app = root.find("application")
    if app is None:
        return {"error": "Missing application element"}
    flags = {key: a(app, key) for key in
             ("debuggable", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig",
              "fullBackupContent", "dataExtractionRules", "permission")}
    exported = []
    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        for node in app.findall(kind):
            flag = a(node, "exported")
            is_exported = flag == "true" or (flag is None and kind != "provider" and bool(node.findall("intent-filter")))
            if not is_exported:
                continue
            record = {
                "type": kind, "name": a(node, "name"), "permission": a(node, "permission"),
                "readPermission": a(node, "readPermission"), "writePermission": a(node, "writePermission"),
                "grantUriPermissions": a(node, "grantUriPermissions"), "authorities": a(node, "authorities"),
                "path_permissions": len(node.findall("path-permission")),
                "filters": intent_filters(node),
            }
            protected = any(record[k] for k in ("permission", "readPermission", "writePermission")) or flags["permission"]
            is_launcher = any("android.intent.action.MAIN" in f["actions"] for f in record["filters"])
            is_link = any("android.intent.action.VIEW" in f["actions"] for f in record["filters"])
            record["review_category"] = ("declared_permission" if protected else
                "launcher_expected" if is_launcher else
                "provider_path_and_read_write_review" if kind == "provider" else
                "deep_link_callback_review" if is_link else "external_entry_review")
            exported.append(record)
    return {"application_flags": flags, "exported_components": exported,
            "counts": {
                "exported_total": len(exported),
                "declared_permission": sum(c["review_category"] == "declared_permission" for c in exported),
                "launcher_expected": sum(c["review_category"] == "launcher_expected" for c in exported),
                "deep_link_callback_review": sum(c["review_category"] == "deep_link_callback_review" for c in exported),
                "provider_path_and_read_write_review": sum(c["review_category"] == "provider_path_and_read_write_review" for c in exported),
            }}

def inspect_xml(path, root):
    result = {"path": str(path.relative_to(ROOT)), "root_tag": root.tag}
    if path.name == "network_security_config.xml":
        configs = []
        for node in root.iter():
            if node.tag not in ("base-config", "domain-config", "debug-overrides"):
                continue
            configs.append({
                "type": node.tag, "cleartextTrafficPermitted": node.get("cleartextTrafficPermitted"),
                "domains": [d.text for d in node.findall("domain")],
                "cert_sources": [c.get("src") for c in node.findall("./trust-anchors/certificates")],
                "pins": [len(p.findall("pin")) for p in node.findall("pin-set")],
            })
        result["configs"] = configs
    else:
        result["backup_rules"] = [{"action": n.tag, "domain": n.get("domain"), "path": n.get("path")}
                                  for n in root.iter() if n.tag in ("include", "exclude")]
    return result

def native_hardening():
    data = []
    for path in sorted((ROOT / "lib").glob("**/*.so")):
        try:
            seg = subprocess.run(["readelf", "-W", "-l", str(path)], text=True, capture_output=True, check=True, timeout=15).stdout
            dyn = subprocess.run(["readelf", "-W", "-d", str(path)], text=True, capture_output=True, check=True, timeout=15).stdout
            stack = [line for line in seg.splitlines() if "GNU_STACK" in line]
            relro = "GNU_RELRO" in seg
            now = bool(re.search(r"\bBIND_NOW\b|\(FLAGS(?:_1)?\).*\bNOW\b", dyn))
            data.append({"file": str(path.relative_to(ROOT)), "gnu_relro": relro,
                         "bind_now": now, "full_relro_estimate": relro and now,
                         "executable_stack": any(re.search(r"\bRWE\b", line) for line in stack)})
        except (OSError, subprocess.SubprocessError) as exc:
            data.append({"file": str(path.relative_to(ROOT)), "error": str(exc)[:160]})
    return data

def main():
    OUT.mkdir(exist_ok=True)
    root, err = xml(ROOT / "AndroidManifest.xml")
    report = {"scope": "Read-only configuration and ELF metadata, not a live penetration test",
              "manifest_error": err, "manifest": manifest(root) if root is not None else None,
              "network_and_backup_xml": [], "native": native_hardening(),
              "limitations": [
                  "Exported components and hardening flags are not evidence of working exploits",
                  "networkSecurityConfig may override usesCleartextTraffic on supported Android versions",
                  "No game score, leaderboard, running app, or remote endpoint was tested",
              ]}
    for pathstr in CONFIG_FILES:
        path = ROOT / pathstr
        if not path.is_file():
            continue
        node, error = xml(path)
        report["network_and_backup_xml"].append(inspect_xml(path, node) if node is not None
                                                 else {"path": pathstr, "error": error})
    (OUT / "deep-audit.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf8")
    counts = (report["manifest"] or {}).get("counts", {})
    lib = report["native"]
    network = next((x for x in report["network_and_backup_xml"] if x["path"].endswith("network_security_config.xml")), {})
    lines = [
        "\n## Deep static follow-up: Android and ELF",
        f"- Exported component total: **{counts.get('exported_total', 'unavailable')}**.",
        f"- Components with declared permission: **{counts.get('declared_permission', 'unavailable')}**.",
        f"- Expected launcher components: **{counts.get('launcher_expected', 'unavailable')}**.",
        f"- Deep link / callback components for review: **{counts.get('deep_link_callback_review', 'unavailable')}**.",
        f"- Provider components for read/write permission review: **{counts.get('provider_path_and_read_write_review', 'unavailable')}**.",
        f"- Native libraries inspected: **{len(lib)}**.",
        f"- Native libraries with executable GNU_STACK: **{sum(bool(x.get('executable_stack')) for x in lib)}**.",
        f"- Native libraries without estimated full RELRO: **{sum(x.get('full_relro_estimate') is False for x in lib)}**.",
        "- XML and per-library evidence is in deep-audit.json.",
        "- All are review observations, not confirmed exploits.",
    ]
    if network.get("configs"):
        for c in network["configs"]:
            lines.append(f"- Network config {c['type']}: cleartext={c['cleartextTrafficPermitted']}, domains={len(c['domains'])}, trust sources={c['cert_sources']}.")
    content = "\n".join(lines) + "\n"
    print(content)
    with (OUT / "audit.md").open("a", encoding="utf8") as output:
        output.write(content)
    import os
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf8") as f:
            f.write(content)

if __name__ == "__main__":
    main()
