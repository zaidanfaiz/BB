#!/usr/bin/env python3
"""Read-only inventory of HEK-prefixed assets; no decryption or modification."""
from collections import Counter
from pathlib import Path
from math import log2
import hashlib
import json
import os
import statistics

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "audit-output"
EXTS = {".json", ".js", ".jsc", ".bin", ".dbbin"}
MAGIC = b"HEK:"
SAMPLE_BYTES = 2048

def entropy(chunk):
    if not chunk:
        return 0.
    counter = Counter(chunk)
    n = len(chunk)
    return round(-sum((count / n) * log2(count / n) for count in counter.values()), 3)

def scan():
    paths = sorted(ROOT.joinpath("assets").rglob("*"))
    formats = Counter()
    versions = Counter()
    prefix_bytes = Counter()
    locations = Counter()
    opaque_by_extension = Counter()
    plaintext_by_extension = Counter()
    encrypted_samples = []
    opaque_score_files = []
    file_sizes = []
    errors = []
    content_prefix_hashes = Counter()
    total = 0
    for path in paths:
        if not path.is_file() or path.suffix.lower() not in EXTS:
            continue
        total += 1
        rel = path.relative_to(ROOT).as_posix()
        try:
            with path.open("rb") as handle:
                sample = handle.read(SAMPLE_BYTES)
            if not sample.startswith(MAGIC):
                plaintext_by_extension[path.suffix.lower()] += 1
                continue
            opaque_by_extension[path.suffix.lower()] += 1
            ver = sample[4] if len(sample) >= 5 else None
            versions[str(ver)] += 1
            prefix_bytes[sample[:8].hex()] += 1
            location = rel.split("/")[2] if len(rel.split("/")) > 2 else "(root)"
            locations[location] += 1
            file_sizes.append(path.stat().st_size)
            content_prefix_hashes[hashlib.sha256(sample[:64]).hexdigest()[:12]] += 1
            e = entropy(sample[8:])  # sampled opaque payload bytes; entropy is NOT encryption proof
            if len(encrypted_samples) < 24:
                encrypted_samples.append({
                    "file": rel, "byte_size": path.stat().st_size,
                    "header_hex": sample[:12].hex(), "sample_entropy_bits_per_byte": e,
                })
            if any(s in rel.lower() for s in ("score", "combo", "rank", "highscore", "main/index")):
                opaque_score_files.append(rel)
        except OSError as exc:
            errors.append({"file": rel, "error": str(exc)[:130]})
    report = {
        "scope": "Static bytes-only characterization; HEK is a signature, not proof of cryptography",
        "candidate_asset_file_count": total,
        "hek_count": sum(opaque_by_extension.values()),
        "hek_by_extension": dict(opaque_by_extension),
        "nonhek_by_extension": dict(plaintext_by_extension),
        "header_byte_4_distribution": dict(versions),
        "first_8_bytes_distribution": dict(prefix_bytes.most_common(25)),
        "top_25_asset_families": locations.most_common(25),
        "unique_sample_prefix_hashes": len(content_prefix_hashes),
        "sizes": {
            "smallest": min(file_sizes) if file_sizes else None,
            "median": round(statistics.median(file_sizes)) if file_sizes else None,
            "largest": max(file_sizes) if file_sizes else None,
        },
        "selected_samples": encrypted_samples,
        "score_related_opaque_files": opaque_score_files[:120],
        "score_related_opaque_count": len(opaque_score_files),
        "errors": errors[:30],
        "limitations": [
            "The data header is not enough to distinguish encryption, compression, or a proprietary container",
            "A single sample's Shannon entropy cannot prove that cryptography is involved",
            "This inventory does not reveal program logic, stable score addresses, encryption keys, or bypasses",
            "No HEK data was decrypted or modified",
        ],
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "hek-inventory.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "\n## HEK container inventory",
        f"- Candidate files: **{total}**; HEK-prefix files: **{report['hek_count']}**.",
        f"- HEK by extension: **{report['hek_by_extension']}**.",
        f"- Header byte 4 distribution: **{report['header_byte_4_distribution']}**.",
        f"- Unique SHA-256 fingerprints for first 64 bytes: **{report['unique_sample_prefix_hashes']}**.",
        f"- Score/combo-named HEK files: **{len(opaque_score_files)}**.",
        "- A HEK header alone does not establish that contents are encrypted or identify a decoder.",
        "- Per-file samples, aggregate distributions and limitations: hek-inventory.json.",
    ]
    md = "\n".join(lines) + "\n"
    with (OUT / "audit.md").open("a", encoding="utf-8") as f:
        f.write(md)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(md)
    print(md)

if __name__ == "__main__":
    scan()
