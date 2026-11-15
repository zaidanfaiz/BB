#!/usr/bin/env python3
"""Read-only security policy checks, no exploitation attempts."""
import json
from pathlib import Path
from androguard.core.axml import AXMLPrinter

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "audit-output"
NS = "{http://schemas.android.com/apk/res/android}"

def a(node, key):
    return node.get(NS + key)

def parsed(path):
    return AXMLPrinter(path.read_bytes()).get_xml_obj()

def suspicious_domain(host):
    if not host or any(x in host for x in ("/", ":", " ", "\\", "@")):
        return True
    return any(not segment for segment in host.split("."))

def main():
    manifest = parsed(ROOT / "AndroidManifest.xml")
    declarations = [{"name": a(node, "name"), "protection_level": a(node, "protectionLevel")}
                    for node in manifest.findall("permission")]
    defined = {p["name"]: p for p in declarations}
    app = manifest.find("application")
    custom_references = []
    for kind in ("provider", "activity", "service", "receiver", "activity-alias"):
        for node in app.findall(kind):
            if a(node, "exported") != "true":
                continue
            for field in ("permission", "readPermission", "writePermission"):
                name = a(node, field)
                if name and not name.startswith("android.permission."):
                    custom_references.append({
                        "component": a(node, "name"), "type": kind, "attribute": field,
                        "permission": name, "declared_definition": defined.get(name),
                    })
    domains = []
    path = ROOT / "res/xml/network_security_config.xml"
    if path.exists():
        xml = parsed(path)
        for elem in xml.iter("domain"):
            host = (elem.text or "").strip()
            if suspicious_domain(host):
                domains.append({"hostname": host, "reason": "Unexpected characters or empty label in hostname"})
    unresolved = [item for item in custom_references if item["declared_definition"] is None]
    report = {
        "package": manifest.get("package"),
        "custom_permission_declarations": declarations,
        "exported_component_custom_permission_references": custom_references,
        "unresolved_custom_permission_references": unresolved,
        "unexpected_domain_entries": domains,
        "limitations": [
            "Custom permission declaration alone does not prove authorization checks are effective",
            "Domain syntax review is not a runtime test",
            "No component was invoked and no game memory or score was changed",
        ],
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "policy-review.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf8")
    lines = [
        "\n## Custom permissions and network domain syntax",
        f"- App-declared permissions: **{len(declarations)}**.",
        f"- Custom permission references on exported components: **{len(custom_references)}**.",
        f"- References without a matching manifest definition: **{len(unresolved)}**.",
        f"- Unexpected network domain strings: **{len(domains)}**.",
        "- Exact details in policy-review.json.",
        "- These are review observations, not confirmed exploits.",
    ]
    output = "\n".join(lines) + "\n"
    with (OUT / "audit.md").open("a", encoding="utf8") as f:
        f.write(output)
    print(output)
    import os
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf8") as f:
            f.write(output)

if __name__ == "__main__":
    main()
