#!/usr/bin/env python3
"""Build a CycloneDX SBOM from aboutlibraries.json shipped with the APK.

Declared library versions are not proof that a particular implementation is
loaded at runtime. Incomplete/ambiguous versions are excluded from OSV matching.
"""
import json
from pathlib import Path
import re
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "res/raw/aboutlibraries.json"
OUT = ROOT / "audit-output"
VERSION = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z._-]+)?$")

def main():
    OUT.mkdir(exist_ok=True)
    if not SOURCE.exists():
        raise SystemExit(f"Missing {SOURCE}")
    libraries = json.loads(SOURCE.read_text(encoding="utf-8")).get("libraries", [])
    components, skipped = [], []
    seen = set()
    for item in libraries:
        coord = item.get("uniqueId", "")
        ver = str(item.get("artifactVersion") or "")
        if ":" not in coord or not VERSION.fullmatch(ver):
            skipped.append({"coordinate": coord, "version": ver, "reason": "ambiguous or unsupported"})
            continue
        group, artifact = coord.split(":", 1)
        key = (group, artifact, ver)
        if key in seen:
            continue
        seen.add(key)
        components.append({
            "type": "library", "group": group, "name": artifact, "version": ver,
            "purl": f"pkg:maven/{quote(group, safe='.')}/{quote(artifact, safe='.-_')}@{quote(ver, safe='.-_')}",
        })
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": "blockblast-extracted-apk"}},
        "components": components,
    }
    (OUT / "bb-dependencies.cdx.json").write_text(json.dumps(bom, indent=2), encoding="utf-8")
    (OUT / "bb-sbom-skipped.json").write_text(json.dumps(skipped, indent=2), encoding="utf-8")
    print(f"SBOM: {len(components)} Maven packages; {len(skipped)} entries skipped/ambiguous from {len(libraries)} library records.")
    with open(OUT / "audit.md", "a", encoding="utf-8") as f:
        f.write(f"\n## Bundled dependency inventory\n- Library metadata records: **{len(libraries)}**\n")
        f.write(f"- Maven components with unambiguous versions: **{len(components)}**\n")
        f.write(f"- Entries skipped/ambiguous: **{len(skipped)}**\n")
        f.write("- Known-vulnerability matching is performed separately with OSV and does not cover all native dependencies.\n")

if __name__ == "__main__":
    main()
