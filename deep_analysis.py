#!/usr/bin/env python3
"""
pixelproof deep — Full 7-pass forensic analysis with ELA, noise, edge,
color-channel, and JPEG compression checks.

Usage:
    python deep_analysis.py <image_path>

Outputs:
    - Detailed terminal report
    - <image>_ELA.png — Error Level Analysis visualization
"""
import sys
import os
import io
import math

import PIL.Image
import PIL.ImageChops
import PIL.ImageEnhance
import PIL.ImageFilter
import PIL.ImageStat
import PIL.ExifTags


# ── Utilities ─────────────────────────────────────────────


def section(title):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


CAMERA_FIELDS = [
    "Make",
    "Model",
    "LensModel",
    "FocalLength",
    "FNumber",
    "ExposureTime",
    "ISOSpeedRatings",
    "DateTime",
    "DateTimeOriginal",
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


# ── 1. EXIF Metadata ─────────────────────────────────────


def full_exif_dump(path):
    section("1. COMPLETE EXIF METADATA DUMP")
    img = PIL.Image.open(path)
    raw = img._getexif()
    info = {
        "format": img.format,
        "mode": img.mode,
        "size": img.size,
        "info_keys": list(img.info.keys()),
    }
    print(f"  Format: {info['format']}")
    print(f"  Mode: {info['mode']}")
    print(f"  Size: {info['size'][0]} x {info['size'][1]}")
    print(f"  Info keys: {info['info_keys']}")

    if raw:
        meta = {PIL.ExifTags.TAGS.get(t, f"Unknown-{t}"): v for t, v in raw.items()}
        print(f"\n  EXIF tags found: {len(meta)}")
        for k, v in sorted(meta.items()):
            val = str(v)
            if len(val) > 120:
                val = val[:120] + "..."
            print(f"    {k}: {val}")
        return meta
    else:
        print("  NO EXIF DATA")
        return {}


# ── 2. Grid ELA ──────────────────────────────────────────


def grid_ela_analysis(original_path, grid_size=8):
    section("2. GRID-BASED ERROR LEVEL ANALYSIS")
    original = PIL.Image.open(original_path).convert("RGB")
    w, h = original.size

    buf = io.BytesIO()
    original.save(buf, "JPEG", quality=90)
    buf.seek(0)
    resaved = PIL.Image.open(buf).convert("RGB")
    diff = PIL.ImageChops.difference(original, resaved)

    cell_w = w // grid_size
    cell_h = h // grid_size
    print(f"\n  Grid: {grid_size}x{grid_size} cells, each {cell_w}x{cell_h} px")

    header = "        " + "".join(f"  Col{c:<3}" for c in range(grid_size))
    print(f"\n{header}")
    print("       " + "-" * (grid_size * 8))

    global_means = []
    grid_data = []
    for row in range(grid_size):
        row_str = f"  Row{row} |"
        for col in range(grid_size):
            x1, y1 = col * cell_w, row * cell_h
            x2, y2 = x1 + cell_w, y1 + cell_h
            cell = diff.crop((x1, y1, x2, y2))
            stat = PIL.ImageStat.Stat(cell)
            mean = sum(stat.mean) / 3
            global_means.append(mean)
            grid_data.append(
                {
                    "row": row,
                    "col": col,
                    "x1": x1,
                    "y1": y1,
                    "x2": x2,
                    "y2": y2,
                    "mean_error": round(mean, 2),
                    "max_per_channel": [int(e[1]) for e in cell.getextrema()],
                }
            )
            row_str += f"  {mean:5.2f} "
        print(row_str)

    overall_mean = sum(global_means) / len(global_means)
    overall_std = math.sqrt(
        sum((m - overall_mean) ** 2 for m in global_means) / len(global_means)
    )
    threshold = overall_mean + 2 * overall_std

    print(f"\n  Overall mean error: {overall_mean:.2f}")
    print(f"  Std deviation:      {overall_std:.2f}")
    print(f"  Hotspot threshold (mean + 2σ): {threshold:.2f}")

    hotspots = []
    print(f"\n  HOTSPOT CELLS (error > {threshold:.2f}):")
    for cell in grid_data:
        if cell["mean_error"] > threshold:
            hotspots.append(cell)
            col_pos = (
                "left"
                if cell["col"] < grid_size // 3
                else ("center" if cell["col"] < 2 * grid_size // 3 else "right")
            )
            row_pos = (
                "top"
                if cell["row"] < grid_size // 3
                else ("middle" if cell["row"] < 2 * grid_size // 3 else "bottom")
            )
            print(
                f"    ‣ Row {cell['row']}, Col {cell['col']} ({row_pos}-{col_pos}): "
                f"mean={cell['mean_error']:.2f}, max_channels={cell['max_per_channel']}, "
                f"region=({cell['x1']},{cell['y1']})-({cell['x2']},{cell['y2']})"
            )
    if not hotspots:
        print("    None detected above threshold")

    return grid_data, hotspots, overall_mean, overall_std, threshold


# ── 3. ELA Image Generation ──────────────────────────────


def perform_ela(image_path, quality=90, scale=15):
    section("3. ERROR LEVEL ANALYSIS (ELA) IMAGE")
    original = PIL.Image.open(image_path).convert("RGB")

    buf = io.BytesIO()
    original.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    resaved = PIL.Image.open(buf).convert("RGB")

    diff = PIL.ImageChops.difference(original, resaved)
    extrema = diff.getextrema()
    diff_scaled = PIL.ImageEnhance.Brightness(diff).enhance(scale)

    ela_path = os.path.splitext(image_path)[0] + "_ELA.png"
    diff_scaled.save(ela_path)

    raw_diff = PIL.ImageChops.difference(original, resaved)
    stat = PIL.ImageStat.Stat(raw_diff)

    result = {
        "ela_image_saved": ela_path,
        "channel_extrema_rgb": extrema,
        "mean_error_rgb": tuple(round(m, 2) for m in stat.mean),
        "stddev_rgb": tuple(round(s, 2) for s in stat.stddev),
        "max_error": max(e[1] for e in extrema),
    }

    print(f"    ELA image saved → {ela_path}")
    print(f"    Mean error (R,G,B):  {result['mean_error_rgb']}")
    print(f"    Std-dev (R,G,B):     {result['stddev_rgb']}")
    print(f"    Max pixel error:     {result['max_error']}")

    if result["max_error"] > 40:
        print("  ⚠ HIGH ERROR REGIONS — suggests edits or compositing")
    elif result["max_error"] > 25:
        print("  ⚠ MODERATE ERROR VARIATION — some regions may be altered")
    else:
        print("  ✓ Error levels appear relatively uniform")

    return result


# ── 4. Multi-Quality ELA ─────────────────────────────────


def multi_quality_ela(original_path):
    section("4. MULTI-QUALITY ELA COMPARISON")
    original = PIL.Image.open(original_path).convert("RGB")
    print(f"\n  Quality | Mean Error (R,G,B)          | Max Error")
    print(f"  {'─' * 55}")

    results = []
    for q in [50, 60, 70, 75, 80, 85, 90, 95, 98]:
        buf = io.BytesIO()
        original.save(buf, "JPEG", quality=q)
        buf.seek(0)
        resaved = PIL.Image.open(buf).convert("RGB")
        diff = PIL.ImageChops.difference(original, resaved)
        stat = PIL.ImageStat.Stat(diff)
        extrema = diff.getextrema()
        max_err = max(e[1] for e in extrema)
        mean_rgb = tuple(round(m, 2) for m in stat.mean)
        results.append({"quality": q, "mean_rgb": mean_rgb, "max_error": max_err})
        avg = sum(mean_rgb) / 3
        note = " ← low error" if q >= 85 and avg < 2.0 else ""
        if q >= 85 and avg < 1.0:
            note = " ← very low (may match original quality)"
        print(f"    {q:3d}   | {str(mean_rgb):32s} | {max_err:3d}  {note}")

    best = min(results, key=lambda r: sum(r["mean_rgb"]))
    print(f"\n  Estimated original JPEG quality: ~{best['quality']}")
    return results, best


# ── 5. Image Statistics ───────────────────────────────────


def analyze_image_stats(image_path):
    section("5. IMAGE STATISTICS")
    img = PIL.Image.open(image_path).convert("RGB")
    stat = PIL.ImageStat.Stat(img)
    w, h = img.size
    flags = []

    ratio = w / h
    file_size = os.path.getsize(image_path)
    pixels = w * h
    bpp = (file_size * 8) / pixels

    report = {
        "dimensions": f"{w} x {h}",
        "aspect_ratio": round(ratio, 3),
        "mean_rgb": tuple(round(m, 1) for m in stat.mean),
        "stddev_rgb": tuple(round(s, 1) for s in stat.stddev),
        "file_size_kb": round(file_size / 1024, 1),
        "bits_per_pixel": round(bpp, 2),
        "flags": flags,
    }

    stds = stat.stddev
    if max(stds) - min(stds) < 2.0:
        flags.append("SUSPICIOUSLY UNIFORM CHANNEL VARIANCE — possible AI-generated")

    if bpp < 0.5:
        flags.append(f"VERY LOW QUALITY — {bpp:.2f} bpp suggests heavy compression")
    elif bpp < 1.5:
        flags.append(f"LOW-MODERATE QUALITY — {bpp:.2f} bpp")

    if w % 64 == 0 and h % 64 == 0:
        flags.append(f"DIMENSIONS DIVISIBLE BY 64 ({w}x{h}) — common in AI images")

    for k, v in report.items():
        if k != "flags":
            print(f"    {k}: {v}")
    if flags:
        print("\n  ⚠ FLAGS:")
        for f in flags:
            print(f"    ‣ {f}")
    else:
        print("  ✓ Statistics appear normal")

    return report


# ── 6. Edge & Boundary Analysis ──────────────────────────


def edge_analysis(original_path):
    section("6. EDGE & BOUNDARY ANALYSIS")
    img = PIL.Image.open(original_path).convert("L")
    edges = img.filter(PIL.ImageFilter.FIND_EDGES)
    stat = PIL.ImageStat.Stat(edges)
    print(f"\n  Mean edge intensity: {stat.mean[0]:.2f}")
    print(f"  Std dev:             {stat.stddev[0]:.2f}")

    w, h = edges.size
    quadrants = {
        "top-left": edges.crop((0, 0, w // 2, h // 2)),
        "top-right": edges.crop((w // 2, 0, w, h // 2)),
        "bottom-left": edges.crop((0, h // 2, w // 2, h)),
        "bottom-right": edges.crop((w // 2, h // 2, w, h)),
    }
    print(f"\n  Edge density by quadrant:")
    quad_means = {}
    for name, quad in quadrants.items():
        qstat = PIL.ImageStat.Stat(quad)
        quad_means[name] = qstat.mean[0]
        print(f"    {name:15s}: mean={qstat.mean[0]:.2f}, std={qstat.stddev[0]:.2f}")

    vals = list(quad_means.values())
    if max(vals) > 2 * min(vals) and min(vals) > 1:
        print(f"\n  ⚠ EDGE DENSITY IMBALANCE")
    else:
        print(f"\n  ✓ Edge density is balanced")

    return quad_means


# ── 7. Color Channel Correlation ─────────────────────────


def channel_correlation(original_path):
    section("7. COLOR CHANNEL CORRELATION")
    img = PIL.Image.open(original_path).convert("RGB")
    r, g, b = img.split()
    w, h = img.size
    sample_size = min(50000, w * h)
    step = max(1, (w * h) // sample_size)

    r_data = list(r.getdata())[::step]
    g_data = list(g.getdata())[::step]
    b_data = list(b.getdata())[::step]
    n = len(r_data)

    def pearson(x, y):
        mx, my = sum(x) / n, sum(y) / n
        num = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
        dx = math.sqrt(sum((xi - mx) ** 2 for xi in x))
        dy = math.sqrt(sum((yi - my) ** 2 for yi in y))
        return num / (dx * dy) if dx * dy else 0

    rg = pearson(r_data, g_data)
    rb = pearson(r_data, b_data)
    gb = pearson(g_data, b_data)

    print(f"\n  Channel correlations (Pearson, {n} samples):")
    print(f"    R-G: {rg:.4f}")
    print(f"    R-B: {rb:.4f}")
    print(f"    G-B: {gb:.4f}")

    min_corr = min(rg, rb, gb)
    if min_corr < 0.5:
        print(f"\n  ⚠ LOW CORRELATION ({min_corr:.2f}) — unusual for natural photos")
    elif min_corr < 0.75:
        print(f"\n  ⚠ MODERATE CORRELATION ({min_corr:.2f})")
    else:
        print(f"\n  ✓ Correlations appear natural (min={min_corr:.2f})")

    return {"rg": round(rg, 4), "rb": round(rb, 4), "gb": round(gb, 4)}


# ── 8. Noise Analysis ────────────────────────────────────


def noise_analysis(original_path):
    section("8. NOISE ANALYSIS")
    img = PIL.Image.open(original_path).convert("L")
    w, h = img.size
    blurred = img.filter(PIL.ImageFilter.GaussianBlur(radius=2))
    noise = PIL.ImageChops.difference(img, blurred)

    grid = 4
    cell_w, cell_h = w // grid, h // grid
    print(f"\n  Noise levels by region:")
    noise_vals = {}
    for row in range(grid):
        line = "    "
        for col in range(grid):
            x1, y1 = col * cell_w, row * cell_h
            cell = noise.crop((x1, y1, x1 + cell_w, y1 + cell_h))
            stat = PIL.ImageStat.Stat(cell)
            noise_vals[f"({row},{col})"] = stat.mean[0]
            line += f"  {stat.mean[0]:5.2f}"
        print(line)

    vals = list(noise_vals.values())
    mean_n = sum(vals) / len(vals)
    std_n = math.sqrt(sum((v - mean_n) ** 2 for v in vals) / len(vals))
    cv = std_n / mean_n if mean_n > 0 else 0

    print(f"\n  Mean noise: {mean_n:.2f}, Std: {std_n:.2f}, CV: {cv:.3f}")

    if cv > 0.3:
        print(f"  ⚠ INCONSISTENT NOISE (CV={cv:.2f}) — strong editing indicator")
    elif cv > 0.15:
        print(f"  ⚠ MODERATELY INCONSISTENT NOISE (CV={cv:.2f})")
    else:
        print(f"  ✓ Noise is consistent (CV={cv:.2f})")

    return noise_vals, mean_n, std_n, cv


# ── 9. JPEG Compression ──────────────────────────────────


def check_jpeg_compression(image_path):
    section("9. JPEG COMPRESSION ANALYSIS")
    img = PIL.Image.open(image_path)
    qtables = img.quantization if hasattr(img, "quantization") else None
    flags = []

    if qtables is None:
        print("  Not a JPEG or no quantization tables found")
        return {"flags": flags}

    report = {"num_tables": len(qtables), "flags": flags}
    for idx, table in qtables.items():
        table_values = list(table.values()) if isinstance(table, dict) else list(table)
        avg = sum(table_values) / len(table_values)
        report[f"table_{idx}_avg"] = round(avg, 2)
        print(f"    Table {idx}: avg quantization = {avg:.2f}")
        if avg > 15:
            flags.append(
                f"Table {idx}: high avg ({avg:.1f}) — heavy compression or re-saves"
            )

    if flags:
        print("\n  ⚠ COMPRESSION FLAGS:")
        for f in flags:
            print(f"    ‣ {f}")
    else:
        print("  ✓ Compression tables appear normal")

    return report


# ── Full Report ───────────────────────────────────────────


def full_forensic_analysis(image_path):
    print("╔" + "═" * 58 + "╗")
    print("║   PIXELPROOF — COMPREHENSIVE FORENSIC ANALYSIS            ║")
    print("║   " + os.path.basename(image_path).ljust(54) + " ║")
    print("╚" + "═" * 58 + "╝")

    exif = full_exif_dump(image_path)
    grid_data, hotspots, g_mean, g_std, thresh = grid_ela_analysis(image_path)
    ela = perform_ela(image_path)
    mq_results, best_q = multi_quality_ela(image_path)
    stats = analyze_image_stats(image_path)
    edges = edge_analysis(image_path)
    channels = channel_correlation(image_path)
    noise_vals, noise_mean, noise_std, noise_cv = noise_analysis(image_path)
    jpeg = check_jpeg_compression(image_path)

    # ── Verdict ──
    flags = []
    present = [f for f in CAMERA_FIELDS if f in exif]
    if not present:
        flags.append("No camera hardware metadata")
    if "DateTime" not in exif and "DateTimeOriginal" not in exif:
        flags.append("No timestamp")
    if "GPSInfo" not in exif:
        flags.append("No GPS data")
    if hotspots:
        flags.append(f"ELA detected {len(hotspots)} hotspot(s)")
    if ela["max_error"] > 25:
        flags.append("ELA shows inconsistent error levels")
    if noise_cv > 0.15:
        flags.append(f"Inconsistent noise (CV={noise_cv:.2f})")
    edge_vals = list(edges.values())
    if max(edge_vals) > 2 * min(edge_vals) and min(edge_vals) > 1:
        flags.append("Edge density imbalance")
    min_corr = min(channels.values())
    if min_corr < 0.75:
        flags.append(f"Low channel correlation (min={min_corr:.2f})")
    flags.extend(stats.get("flags", []))
    flags.extend(jpeg.get("flags", []))

    section("FINAL VERDICT")
    print(f"\n  Total flags: {len(flags)}")
    for i, f in enumerate(flags, 1):
        print(f"    {i}. {f}")

    if len(flags) >= 5:
        print("\n  🔴 HIGHLY SUSPICIOUS")
    elif len(flags) >= 3:
        print("\n  🟡 SUSPICIOUS")
    elif len(flags) >= 1:
        print("\n  🟡 MINOR CONCERN")
    else:
        print("\n  🟢 NO RED FLAGS")

    print(f"\n  ELA image: {ela['ela_image_saved']}")
    print("=" * 60)


# ── CLI ───────────────────────────────────────────────────


def main():
    if len(sys.argv) < 2:
        print("Usage: python deep_analysis.py <image_path>")
        sys.exit(1)
    image_path = sys.argv[1]
    if not os.path.isfile(image_path):
        print(f"Error: file not found — {image_path}")
        sys.exit(1)
    full_forensic_analysis(image_path)


if __name__ == "__main__":
    main()
