#!/usr/bin/env python3
"""Read-only exported ContentProvider/DEX definition review for an extracted APK.

This does not call providers, access their data, hook an app, or patch a game.
"""
import json
import os
import struct
from pathlib import Path

from androguard.core.axml import AXMLPrinter
from bb_dex_triage import block, dex_strings, read_u32, uleb128

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "audit-output"
NS = "{http://schemas.android.com/apk/res/android}"
ENTRY_POINTS = {
    "onCreate", "query", "getType", "getStreamTypes", "openFile",
    "openAssetFile", "openTypedAssetFile", "call", "insert", "bulkInsert",
    "update", "delete", "applyBatch", "canonicalize", "uncanonicalize",
    "refresh", "shutdown",
}


def attr(node, name):
    return node.get(NS + name)


def qualified(package, name):
    if not name:
        return None
    if name.startswith("."):
        return package + name
    if "." not in name:
        return package + "." + name
    return name


def permission_level(value):
    if value is None:
        return None
    v = str(value).lower().strip()
    if v in ("normal", "0", "0x0", "0x00000000"):
        return "normal"
    if v.startswith("signature") or v in ("2", "0x2", "0x00000002"):
        return "signature"
    if v == "dangerous" or v in ("1", "0x1", "0x00000001"):
        return "dangerous"
    return "other_or_unknown"


def manifest_inventory():
    tree = AXMLPrinter((ROOT / "AndroidManifest.xml").read_bytes()).get_xml_obj()
    package = tree.get("package", "")
    declared = {attr(n, "name"): {
        "value": attr(n, "protectionLevel"),
        "normalized": permission_level(attr(n, "protectionLevel")),
    } for n in tree.findall("permission")}
    app = tree.find("application")
    app_perm = attr(app, "permission")
    records = []
    for node in app.findall("provider"):
        name = qualified(package, attr(node, "name"))
        generic_permission = attr(node, "permission") or app_perm
        read_permission = attr(node, "readPermission") or generic_permission
        write_permission = attr(node, "writePermission") or generic_permission
        exported = attr(node, "exported")
        records.append({
            "name": name,
            "class_descriptor": "L" + name.replace(".", "/") + ";" if name else None,
            "exported_explicit": exported,
            "authorities_present": bool(attr(node, "authorities")),
            "read_permission": read_permission,
            "read_permission_declaration": declared.get(read_permission),
            "write_permission": write_permission,
            "write_permission_declaration": declared.get(write_permission),
            "grant_uri_permissions": attr(node, "grantUriPermissions"),
            "path_permission_entries": len(node.findall("path-permission")),
            "dex_declaration": None,
        })
    return {"package": package, "declared_permissions": declared, "providers": records}


def decode_methods_in_class(buf, class_data_off, strings, types, method_ids_off, method_ids_size):
    if not class_data_off:
        return []
    off = class_data_off
    counts = []
    for _ in range(4):
        count, off = uleb128(buf, off)
        counts.append(count)
    for _ in range(counts[0] + counts[1]):
        _, off = uleb128(buf, off)
        _, off = uleb128(buf, off)
    methods = []
    for category, count in (("direct", counts[2]), ("virtual", counts[3])):
        method_idx = 0
        for _ in range(count):
            delta, off = uleb128(buf, off)
            method_idx += delta
            flags, off = uleb128(buf, off)
            code_off, off = uleb128(buf, off)
            if method_idx >= method_ids_size:
                raise ValueError("Method index out of range")
            class_idx, _proto_idx, name_idx = struct.unpack_from(
                "<HHI", buf, method_ids_off + method_idx * 8
            )
            if class_idx >= len(types) or name_idx >= len(strings):
                raise ValueError("Method owner/name out of range")
            name = strings[name_idx]
            if name in ENTRY_POINTS:
                methods.append({
                    "name": name,
                    "kind": category,
                    "has_code": bool(code_off),
                })
    return methods


def dex_definitions(descriptors):
    found = {}
    errors = []
    files = sorted(ROOT.glob("classes*.dex"))
    for path in files:
        try:
            buf = path.read_bytes()
            if not buf.startswith(b"dex\n") or len(buf) < 0x70:
                raise ValueError("Invalid DEX header")
            strings = dex_strings(buf)
            ntypes, otypes = read_u32(buf, 0x40), read_u32(buf, 0x44)
            types = [strings[read_u32(buf, at)] for at in block(buf, otypes, ntypes, 4)]
            nclasses, oclasses = read_u32(buf, 0x60), read_u32(buf, 0x64)
            nmethods, omethods = read_u32(buf, 0x58), read_u32(buf, 0x5c)
            for at in block(buf, oclasses, nclasses, 32):
                idx = read_u32(buf, at)
                if idx >= len(types) or types[idx] not in descriptors:
                    continue
                descriptor = types[idx]
                class_data_off = read_u32(buf, at + 24)
                found[descriptor] = {
                    "dex_file": path.name,
                    "class_defined": True,
                    "provider_entry_methods": decode_methods_in_class(
                        buf, class_data_off, strings, types, omethods, nmethods
                    ),
                }
        except (ValueError, IndexError, struct.error, OSError) as exc:
            errors.append({"file": path.name, "error": f"{type(exc).__name__}: {str(exc)[:100]}"})
    return found, errors, len(files)


def main():
    OUT.mkdir(exist_ok=True)
    report = manifest_inventory()
    descriptors = {p["class_descriptor"] for p in report["providers"] if p["class_descriptor"]}
    found, errors, dex_count = dex_definitions(descriptors)
    for provider in report["providers"]:
        descriptor = provider["class_descriptor"]
        provider["dex_declaration"] = found.get(descriptor, {
            "class_defined": False,
            "interpretation": "No matching class definition in packaged DEX; does not prove absence at runtime.",
        })
        provider["read_permission_is_normal"] = bool(
            provider["read_permission"] and
            (provider["read_permission_declaration"] or {}).get("normalized") == "normal"
        )
    report.update({
        "scope": "Manifest permission metadata and defined provider method names; static only",
        "dex_count": dex_count,
        "dex_errors": errors,
        "limitations": [
            "An exported provider with a normal read permission is a configuration review item, not proven data exposure.",
            "Presence of an entry point is not evidence of any specific returned data or missing runtime authorization.",
            "Provider implementations may be obfuscated, dynamically loaded, inherited, or native.",
            "No provider was called, no account was accessed, no game data or score was changed.",
        ],
    })
    (OUT / "provider-review.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    lines = ["\n## Provider permission and DEX declaration follow-up"]
    lines.append(f"- Providers: **{len(report['providers'])}**; DEX files checked: **{dex_count}**.")
    for p in report["providers"]:
        entry = p["dex_declaration"]
        methods = ", ".join(m["name"] for m in entry.get("provider_entry_methods", [])) or "(none identified)"
        lines.append(
            f"- \`{p['name']}\`: exported={p['exported_explicit']}, "
            f"read={p['read_permission']} "
            f"({(p['read_permission_declaration'] or {}).get('normalized', 'unknown')}), "
            f"write={p['write_permission']} "
            f"({(p['write_permission_declaration'] or {}).get('normalized', 'unknown')}), "
            f"DEX class defined={entry['class_defined']}, declared entry methods={methods}."
        )
    lines.append(f"- DEX errors: **{len(errors)}**. Findings require owner-authorized functional verification.")
    summary = "\n".join(lines) + "\n"
    with (OUT / "audit.md").open("a", encoding="utf-8") as handle:
        handle.write(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(summary)
    print(summary)


if __name__ == "__main__":
    main()
