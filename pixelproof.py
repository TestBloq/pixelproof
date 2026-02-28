#!/usr/bin/env python3
"""
pixelproof — Quick forensic scan of a photo's EXIF metadata and Photoshop traces.

Usage:
    python pixelproof.py <image_path>
"""
import sys
import os
import PIL.Image
import PIL.ExifTags


# ── Known signatures ──────────────────────────────────────

CAMERA_FIELDS = [
    "Make",
    "Model",
    "LensModel",
    "FocalLength",
    "FNumber",
    "ExposureTime",
    "ISOSpeedRatings",
    "Flash",
    "ShutterSpeedValue",
    "ApertureValue",
    "BrightnessValue",
    "MeteringMode",
]

EDITING_SOFTWARE = [
    "photoshop",
    "gimp",
    "lightroom",
    "snapseed",
    "afterlight",
    "facetune",
    "picsart",
    "canva",
    "pixlr",
    "remini",
    "instagram",
    "vsco",
    "meitu",
    "beautyplus",
    "faceapp",
    "adobe",
]


# ── Helpers ───────────────────────────────────────────────


def _get_exif(image):
    """Return raw EXIF dict or None."""
    return image._getexif()


def _readable_exif(raw):
    """Map numeric EXIF tag IDs to human-readable names."""
    return {PIL.ExifTags.TAGS.get(t, t): v for t, v in raw.items()}


# ── Analysis ──────────────────────────────────────────────


def analyze_metadata(image_path):
    """Deep metadata analysis — flags missing camera data, editing software,
    Photoshop resource blocks, and other anomalies."""
    img = PIL.Image.open(image_path)
    raw = _get_exif(img)
    report = {"flags": [], "details": {}, "photoshop_blocks": []}

    # ── File-level info ──
    info_keys = list(img.info.keys())
    report["details"]["format"] = img.format
    report["details"]["mode"] = img.mode
    report["details"]["size"] = f"{img.size[0]} x {img.size[1]}"
    report["details"]["info_keys"] = info_keys

    # ── Photoshop resource blocks ──
    ps_data = img.info.get("photoshop")
    if ps_data:
        report["flags"].append(
            "PHOTOSHOP RESOURCE BLOCK detected in file headers — "
            "image was processed through Adobe Photoshop or compatible software"
        )
        if isinstance(ps_data, dict):
            for res_id, res_val in ps_data.items():
                entry = {
                    "id": f"0x{res_id:04X}",
                    "size": len(res_val) if isinstance(res_val, bytes) else 0,
                }
                if res_id == 0x0425 and isinstance(res_val, bytes):
                    digest = res_val.hex()
                    entry["caption_digest"] = digest
                    if digest == "d41d8cd98f00b204e9800998ecf8427e":
                        entry["note"] = (
                            "MD5 of empty string — caption was deliberately blanked"
                        )
                        report["flags"].append(
                            "Caption Digest is MD5('') — metadata was intentionally scrubbed"
                        )
                report["photoshop_blocks"].append(entry)

    # ── EXIF analysis ──
    if not raw:
        report["flags"].append(
            "NO EXIF DATA — metadata stripped or never existed (common in fakes / screenshots)"
        )
        return report

    meta = _readable_exif(raw)
    report["details"].update(meta)

    # Camera hardware
    present = [f for f in CAMERA_FIELDS if f in meta]
    missing = [f for f in CAMERA_FIELDS if f not in meta]
    if not present:
        report["flags"].append(
            "NO CAMERA HARDWARE INFO — no Make, Model, Lens, ISO, etc. "
            "Real photos almost always have these"
        )
    elif len(missing) > len(present):
        report["flags"].append(f"SPARSE CAMERA DATA — missing: {', '.join(missing)}")

    # Editing software
    software = str(meta.get("Software", "")).lower()
    for tool in EDITING_SOFTWARE:
        if tool in software:
            report["flags"].append(
                f"EDITING SOFTWARE DETECTED — '{meta.get('Software')}'"
            )
            break

    # Resolution mismatch
    xres = meta.get("XResolution", 0)
    yres = meta.get("YResolution", 0)
    if xres and yres and xres != yres:
        report["flags"].append(f"RESOLUTION MISMATCH — X={xres} vs Y={yres}")

    # Orientation
    if "Orientation" not in meta:
        report["flags"].append("NO ORIENTATION TAG — cameras always set this")

    # GPS
    if not meta.get("GPSInfo"):
        report["flags"].append("NO GPS DATA — could be stripped or location was off")

    # Timestamp
    dt = (
        meta.get("DateTime")
        or meta.get("DateTimeOriginal")
        or meta.get("DateTimeDigitized")
    )
    if dt:
        report["details"]["timestamp"] = str(dt)
    else:
        report["flags"].append("NO TIMESTAMP — real camera photos have date/time")

    return report


# ── CLI ───────────────────────────────────────────────────


def main():
    if len(sys.argv) < 2:
        print("Usage: python pixelproof.py <image_path>")
        sys.exit(1)

    image_path = sys.argv[1]
    if not os.path.isfile(image_path):
        print(f"Error: file not found — {image_path}")
        sys.exit(1)

    print("=" * 60)
    print("  PIXELPROOF — Quick Forensic Metadata Scan")
    print(f"  File: {image_path}")
    print("=" * 60)

    report = analyze_metadata(image_path)

    print("\n  FILE DETAILS")
    print("  " + "-" * 40)
    for k, v in report["details"].items():
        val = str(v)
        if len(val) > 100:
            val = val[:100] + "..."
        print(f"    {k}: {val}")

    if report["photoshop_blocks"]:
        print("\n  PHOTOSHOP RESOURCE BLOCKS")
        print("  " + "-" * 40)
        for block in report["photoshop_blocks"]:
            print(f"    ID {block['id']}: {block['size']} bytes")
            if "caption_digest" in block:
                print(f"      Caption Digest: {block['caption_digest']}")
            if "note" in block:
                print(f"      ⚠ {block['note']}")

    if report["flags"]:
        print(f"\n  ⚠ FLAGS ({len(report['flags'])})")
        print("  " + "-" * 40)
        for f in report["flags"]:
            print(f"    ‣ {f}")
    else:
        print("\n  ✓ No red flags found")

    # Verdict
    n = len(report["flags"])
    print("\n" + "=" * 60)
    if n >= 4:
        print("  🔴 HIGHLY SUSPICIOUS")
    elif n >= 2:
        print("  🟡 SUSPICIOUS")
    elif n == 1:
        print("  🟡 MINOR CONCERN")
    else:
        print("  🟢 CLEAN")
    print("=" * 60)


if __name__ == "__main__":
    main()
