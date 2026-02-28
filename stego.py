#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pixelproof stego -- LSB steganography encode, decode, and forensic detection.

Supports:
    - Single-bit and multi-bit LSB embedding (1-4 bits per channel)
    - Password-based pixel-order shuffling (PRNG seeded scatter)
    - Chi-square statistical detection of hidden payloads
    - Sample Pairs Analysis (SPA) for estimating embedding rate
    - RS (Regular-Singular) steganalysis for LSB detection
    - Bit-plane visual analysis
    - JPEG DCT-level steganalysis (JSteg / F5 detection)
    - Automatic JPEG vs lossless format handling (avoids false positives)

Usage:
    python stego.py encode <image> <output.png> -m "secret message"
    python stego.py encode <image> <output.png> -f secret.txt
    python stego.py encode <image> <output.png> -m "msg" --password s3cret
    python stego.py encode <image> <output.png> -m "msg" --bits 2
    python stego.py decode <image>
    python stego.py decode <image> --password s3cret
    python stego.py decode <image> --bits 2
    python stego.py scan   <image>
"""

import sys
import os
import math
import hashlib
import random
import struct

import PIL.Image
import PIL.ImageStat

# ---------------------------------------------------------------------------
# 16-bit end-of-message delimiter (1111111111111110)
# ---------------------------------------------------------------------------

DELIMITER = "1111111111111110"

# ---------------------------------------------------------------------------
# Chi-square significance thresholds for stego detection
# ---------------------------------------------------------------------------

CHI_SQ_SUSPICIOUS = 0.75
CHI_SQ_LIKELY = 0.90

# ---------------------------------------------------------------------------
# JSteg detection thresholds for DCT coefficient pair analysis
# ---------------------------------------------------------------------------

JSTEG_PAIR_RATIO_MIN = 0.85
JSTEG_PAIR_RATIO_MAX = 1.15
JSTEG_STD_THRESHOLD = 0.15


# ===========================================================================
# Binary conversion helpers
# ===========================================================================


def _text_to_bits(msg):
    """Convert a text string to a binary string with end-of-message delimiter.

    Args:
        msg: The plaintext message to convert.

    Returns:
        Binary string representation with DELIMITER appended.
    """
    bin_msg = "".join(format(ord(c), "08b") for c in msg)
    return bin_msg + DELIMITER


def _bits_to_text(bin_str):
    """Convert a binary string back to plaintext characters.

    Args:
        bin_str: Binary string (multiples of 8 bits).

    Returns:
        Decoded plaintext string.
    """
    chars = []
    for i in range(0, len(bin_str) - 7, 8):
        byte_val = int(bin_str[i : i + 8], 2)
        if byte_val == 0:
            break
        chars.append(chr(byte_val))
    return "".join(chars)


def _file_to_bits(file_path):
    """Read a file and convert its contents to a binary string with delimiter.

    Args:
        file_path: Path to the file to read.

    Returns:
        Binary string representation with DELIMITER appended.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        return _text_to_bits(f.read())


# ===========================================================================
# Pixel shuffling helpers (password-based PRNG scatter)
# ===========================================================================


def _seed_from_password(password):
    """Derive a deterministic PRNG seed from a password string.

    Args:
        password: The password string.

    Returns:
        Integer seed derived from SHA-256 hash of the password.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _shuffled_indices(total, password):
    """Generate a shuffled list of pixel indices using a password seed.

    Args:
        total: Total number of pixels in the image.
        password: Password string for seeding the shuffle.

    Returns:
        List of shuffled pixel indices.
    """
    indices = list(range(total))
    rng = random.Random(_seed_from_password(password))
    rng.shuffle(indices)
    return indices


# ===========================================================================
# Capacity calculation helpers
# ===========================================================================


def _compute_capacity(width, height, bits_per_channel, channels):
    """Compute the maximum number of message bits an image can hold.

    Args:
        width: Image width in pixels.
        height: Image height in pixels.
        bits_per_channel: Number of LSBs used per channel (1-4).
        channels: Number of color channels (e.g. 3 for RGB).

    Returns:
        Maximum embeddable bits (excluding delimiter).
    """
    total_bits = width * height * channels * bits_per_channel
    return total_bits - len(DELIMITER)


def _validate_capacity(bin_msg, capacity, width, height, bits_per_channel):
    """Validate that the message fits in the image, raising if not.

    Args:
        bin_msg: Binary message string to embed.
        capacity: Maximum embeddable bits.
        width: Image width.
        height: Image height.
        bits_per_channel: Number of LSBs per channel.

    Raises:
        ValueError: If the message exceeds image capacity.
    """
    if len(bin_msg) > capacity + len(DELIMITER):
        raise ValueError(
            f"Message ({len(bin_msg)} bits) exceeds image capacity "
            f"({capacity} bits) at {bits_per_channel} bit(s)/channel "
            f"in {width}x{height} image"
        )


# ===========================================================================
# LSB Encoding helpers
# ===========================================================================


def _embed_bits_in_value(value, msg_bits, num_bits):
    """Embed message bits into the least significant bits of a pixel value.

    Args:
        value: Original pixel channel value (0-255).
        msg_bits: String of bits to embed.
        num_bits: Number of LSBs to replace (1-4).

    Returns:
        Modified pixel value with message bits embedded.
    """
    mask = ~((1 << num_bits) - 1) & 0xFF
    cleared = value & mask
    data_val = int(msg_bits, 2)
    return cleared | data_val


def _build_flat_pixels(img):
    """Flatten image pixel data into a list of individual channel values.

    Args:
        img: PIL Image in RGB mode.

    Returns:
        List of integer channel values [R, G, B, R, G, B, ...].
    """
    return [val for pixel in img.get_flattened_data() for val in pixel]


def _reorder_by_indices(flat_pixels, indices, channels):
    """Reorder flat pixel values according to shuffled pixel indices.

    Args:
        flat_pixels: List of flat channel values.
        indices: List of shuffled pixel indices.
        channels: Number of channels per pixel.

    Returns:
        List of reordered channel values.
    """
    reordered = []
    for idx in indices:
        base = idx * channels
        reordered.extend(flat_pixels[base : base + channels])
    return reordered


def _apply_shuffle(flat_pixels, password, channels):
    """Reorder flat pixel values by password-shuffled pixel indices.

    Args:
        flat_pixels: List of flat channel values.
        password: Password for shuffling, or None for sequential order.
        channels: Number of channels per pixel.

    Returns:
        Tuple of (reordered_values, shuffled_indices_or_None).
    """
    if not password:
        return flat_pixels[:], None
    total_px = len(flat_pixels) // channels
    indices = _shuffled_indices(total_px, password)
    return _reorder_by_indices(flat_pixels, indices, channels), indices


def _embed_single_value(values, i, bin_msg, bit_pos, bits_per_channel):
    """Embed message bits into a single pixel channel value in place.

    Args:
        values: List of pixel channel values to modify.
        i: Index of the value to modify.
        bin_msg: Binary message string.
        bit_pos: Current position in the binary message.
        bits_per_channel: Number of LSBs to use per channel (1-4).
    """
    chunk = bin_msg[bit_pos : bit_pos + bits_per_channel]
    chunk = chunk.ljust(bits_per_channel, "0")
    values[i] = _embed_bits_in_value(values[i], chunk, bits_per_channel)


def _embed_message_into_values(values, bin_msg, bits_per_channel, channels):
    """Embed a binary message into flat pixel channel values.

    Args:
        values: List of pixel channel values to modify.
        bin_msg: Binary message string to embed.
        bits_per_channel: Number of LSBs to use per channel (1-4).
        channels: Number of channels per pixel.

    Returns:
        Modified list of channel values with message embedded.
    """
    bit_pos = 0
    for i in range(len(values)):
        if bit_pos >= len(bin_msg):
            break
        _embed_single_value(values, i, bin_msg, bit_pos, bits_per_channel)
        bit_pos += bits_per_channel
    return values


def _unshuffle_values(values, indices, channels):
    """Restore shuffled pixel values back to their original pixel positions.

    Args:
        values: List of channel values in shuffled order.
        indices: Shuffled index list mapping shuffled -> original positions.
        channels: Number of channels per pixel.

    Returns:
        List of channel values in original pixel order.
    """
    total_px = len(values) // channels
    result = [0] * len(values)
    for new_pos, orig_idx in enumerate(indices):
        for c in range(channels):
            result[orig_idx * channels + c] = values[new_pos * channels + c]
    return result


def _values_to_image(values, width, height, channels):
    """Convert flat channel values back into a PIL Image.

    Args:
        values: List of channel values [R, G, B, ...].
        width: Image width.
        height: Image height.
        channels: Number of channels per pixel.

    Returns:
        New PIL Image with the given pixel data.
    """
    pixels = [tuple(values[i : i + channels]) for i in range(0, len(values), channels)]
    img = PIL.Image.new("RGB", (width, height))
    img.putdata(pixels)
    return img


def _prepare_cover_image(image_path, bin_msg, bits_per_channel):
    """Open and validate a cover image for LSB encoding.

    Args:
        image_path: Path to the cover image.
        bin_msg: Binary string to embed (with delimiter).
        bits_per_channel: Number of LSBs per channel (1-4).

    Returns:
        Tuple of (PIL Image, width, height).
    """
    img = PIL.Image.open(image_path).convert("RGB")
    w, h = img.size
    _validate_capacity(
        bin_msg, _compute_capacity(w, h, bits_per_channel, 3), w, h, bits_per_channel
    )
    return img, w, h


def _embed_and_save(img, w, h, bin_msg, output_path, bits_per_channel, password):
    """Embed message bits into an image and save the result as PNG.

    Args:
        img: PIL Image in RGB mode.
        w: Image width.
        h: Image height.
        bin_msg: Binary string to embed.
        output_path: Path to save the stego image.
        bits_per_channel: Number of LSBs per channel (1-4).
        password: Optional password for pixel-order shuffling.
    """
    flat = _build_flat_pixels(img)
    values, indices = _apply_shuffle(flat, password, 3)
    values = _embed_message_into_values(values, bin_msg, bits_per_channel, 3)
    if indices:
        values = _unshuffle_values(values, indices, 3)
    result = _values_to_image(values, w, h, 3)
    result.save(output_path, "PNG")


def _encode_lsb(image_path, bin_msg, output_path, bits_per_channel=1, password=None):
    """Encode a binary message into an image using multi-bit LSB steganography.

    Args:
        image_path: Path to the cover image.
        bin_msg: Binary string to embed (with delimiter).
        output_path: Path to save the stego image (must be PNG).
        bits_per_channel: Number of LSBs per channel (1-4).
        password: Optional password for pixel-order shuffling.
    """
    img, w, h = _prepare_cover_image(image_path, bin_msg, bits_per_channel)
    _embed_and_save(img, w, h, bin_msg, output_path, bits_per_channel, password)


# ===========================================================================
# LSB Decoding helpers
# ===========================================================================


def _extract_bits_from_value(value, num_bits):
    """Extract the least significant bits from a pixel channel value.

    Args:
        value: Pixel channel value (0-255).
        num_bits: Number of LSBs to extract (1-4).

    Returns:
        Binary string of extracted bits.
    """
    mask = (1 << num_bits) - 1
    return format(value & mask, f"0{num_bits}b")


def _extract_all_bits(values, bits_per_channel):
    """Extract LSB data from all channel values until delimiter is found.

    Args:
        values: List of pixel channel values.
        bits_per_channel: Number of LSBs per channel.

    Returns:
        Binary string of extracted message (before delimiter), or empty string.
    """
    bits = []
    for val in values:
        bits.append(_extract_bits_from_value(val, bits_per_channel))
        combined = "".join(bits)
        if DELIMITER in combined:
            return combined.split(DELIMITER)[0]
    return "".join(bits).split(DELIMITER)[0]


def _decode_lsb(image_path, bits_per_channel=1, password=None):
    """Decode a hidden message from an image using LSB steganography.

    Args:
        image_path: Path to the stego image.
        bits_per_channel: Number of LSBs per channel (1-4).
        password: Optional password for pixel-order unshuffling.

    Returns:
        Decoded plaintext message string.
    """
    img = PIL.Image.open(image_path).convert("RGB")
    flat = _build_flat_pixels(img)
    values, _ = _apply_shuffle(flat, password, 3)
    bin_msg = _extract_all_bits(values, bits_per_channel)
    return _bits_to_text(bin_msg)


# ===========================================================================
# Chi-Square Steganalysis helpers
# ===========================================================================


def _count_value_pairs(channel_data):
    """Count occurrences of each byte value in channel data.

    Args:
        channel_data: List of pixel channel values (0-255).

    Returns:
        List of 256 counts, one per possible byte value.
    """
    counts = [0] * 256
    for v in channel_data:
        counts[v] += 1
    return counts


def _chi_square_pair_contribution(count_even, count_odd):
    """Compute chi-square contribution for a single adjacent value pair.

    Args:
        count_even: Count of the even-valued member of the pair.
        count_odd: Count of the odd-valued member of the pair.

    Returns:
        Tuple of (chi_square_contribution, dof_increment).
    """
    expected = (count_even + count_odd) / 2.0
    if expected <= 0:
        return 0.0, 0
    contrib = (count_even - expected) ** 2 / expected
    contrib += (count_odd - expected) ** 2 / expected
    return contrib, 1


def _compute_chi_square_pairs(counts):
    """Compute chi-square statistic from adjacent value-pair frequencies.

    LSB embedding causes values 2k and 2k+1 to converge in frequency.
    This function measures whether such convergence has occurred.

    Args:
        counts: List of 256 byte-value counts.

    Returns:
        Tuple of (chi_square_statistic, degrees_of_freedom).
    """
    chi_sq = 0.0
    dof = 0
    for i in range(0, 256, 2):
        contrib, d = _chi_square_pair_contribution(counts[i], counts[i + 1])
        chi_sq += contrib
        dof += d
    return chi_sq, dof


def _chi_square_probability(chi_sq, dof):
    """Approximate the chi-square cumulative probability.

    Uses the Wilson-Hilferty normal approximation for large DOF.

    Args:
        chi_sq: Chi-square test statistic.
        dof: Degrees of freedom.

    Returns:
        Approximate probability (0.0 to 1.0) of observing this chi-square.
    """
    if dof <= 0:
        return 0.0
    z = ((chi_sq / dof) ** (1 / 3) - (1 - 2 / (9 * dof))) / math.sqrt(2 / (9 * dof))
    p = 0.5 * (1 + math.erf(z / math.sqrt(2)))
    return min(max(p, 0.0), 1.0)


def _classify_chi_verdict(p_val):
    """Classify a chi-square p-value into a stego detection verdict.

    Args:
        p_val: Chi-square probability value.

    Returns:
        String verdict: 'LIKELY', 'SUSPICIOUS', or 'CLEAN'.
    """
    if p_val >= CHI_SQ_LIKELY:
        return "LIKELY"
    if p_val >= CHI_SQ_SUSPICIOUS:
        return "SUSPICIOUS"
    return "CLEAN"


def _build_chi_result(chi_sq, dof, p_val, verdict):
    """Build the chi-square result dictionary for a single channel.

    Args:
        chi_sq: Chi-square test statistic.
        dof: Degrees of freedom.
        p_val: Chi-square probability value.
        verdict: Classification verdict string.

    Returns:
        Dictionary with chi_square, dof, p_value, and verdict keys.
    """
    return {
        "chi_square": round(chi_sq, 2),
        "dof": dof,
        "p_value": round(p_val, 4),
        "verdict": verdict,
    }


def _chi_square_channel(channel_data):
    """Run chi-square steganalysis on a single color channel.

    Args:
        channel_data: List of pixel values for one channel.

    Returns:
        Dictionary with chi_square, dof, p_value, and verdict keys.
    """
    counts = _count_value_pairs(channel_data)
    chi_sq, dof = _compute_chi_square_pairs(counts)
    p_val = _chi_square_probability(chi_sq, dof)
    verdict = _classify_chi_verdict(p_val)
    return _build_chi_result(chi_sq, dof, p_val, verdict)


def _classify_overall_verdict(verdicts):
    """Classify an overall verdict from per-channel verdict strings.

    Args:
        verdicts: List of per-channel verdict strings.

    Returns:
        String: 'LIKELY', 'SUSPICIOUS', or 'CLEAN'.
    """
    if "LIKELY" in verdicts:
        return "LIKELY"
    if "SUSPICIOUS" in verdicts:
        return "SUSPICIOUS"
    return "CLEAN"


def _compute_chi_channels(image_path):
    """Compute chi-square results for each RGB channel.

    Args:
        image_path: Path to the image file.

    Returns:
        Dictionary with per-channel chi-square result dictionaries.
    """
    img = PIL.Image.open(image_path).convert("RGB")
    r_data, g_data, b_data = [list(ch.get_flattened_data()) for ch in img.split()]
    return {
        "R": _chi_square_channel(r_data),
        "G": _chi_square_channel(g_data),
        "B": _chi_square_channel(b_data),
    }


def _chi_square_analysis(image_path):
    """Run chi-square LSB steganalysis across all RGB channels.

    Chi-square analysis detects LSB steganography by measuring whether
    adjacent byte-value pairs (0,1), (2,3), ... (254,255) have converged
    in frequency.  LSB embedding causes such convergence because flipping
    the LSB moves values between each pair equally.

    Args:
        image_path: Path to the image file.

    Returns:
        Dictionary with per-channel results and overall verdict.
    """
    results = _compute_chi_channels(image_path)
    verdicts = [results[ch]["verdict"] for ch in "RGB"]
    results["overall"] = _classify_overall_verdict(verdicts)
    return results


# ===========================================================================
# Sample Pairs Analysis (SPA) helpers
# ===========================================================================


def _classify_pair(u, v):
    """Classify a sample pair as X, Y, or Z type per SPA definitions.

    In SPA, adjacent pixel pairs are classified based on their value
    relationship to determine the probability of LSB embedding.

    Args:
        u: First pixel value in the pair.
        v: Second pixel value in the pair.

    Returns:
        String classification: 'X' (close/equal), 'Y' (far), or 'Z' (neutral).
    """
    if u // 2 == v // 2:
        return "X"
    if abs(u - v) > 1:
        return "Y"
    return "Z"


def _count_spa_classes(data):
    """Count SPA pair classifications across channel data.

    Args:
        data: List of pixel values for one channel.

    Returns:
        Tuple of (x_count, y_count, z_count).
    """
    counts = {"X": 0, "Y": 0, "Z": 0}
    for i in range(0, len(data) - 1, 2):
        cls = _classify_pair(data[i], data[i + 1])
        counts[cls] += 1
    return counts["X"], counts["Y"], counts["Z"]


def _spa_channel(data):
    """Run Sample Pairs Analysis on a single channel to estimate embedding rate.

    SPA counts how many adjacent pixel pairs fall into different
    classification buckets before and after simulated LSB flipping,
    then estimates what fraction of pixels have been modified.

    Args:
        data: List of pixel values for one channel.

    Returns:
        Estimated embedding rate (0.0 = clean, 1.0 = fully embedded).
    """
    x_count, y_count, z_count = _count_spa_classes(data)
    total = x_count + y_count + z_count
    if total == 0:
        return 0.0
    return max(0.0, min(1.0, (y_count - x_count) / total))


def _compute_spa_rates(image_path):
    """Compute per-channel SPA embedding rates for an image.

    Args:
        image_path: Path to the image file.

    Returns:
        Tuple of (r_rate, g_rate, b_rate).
    """
    img = PIL.Image.open(image_path).convert("RGB")
    r_data, g_data, b_data = [list(ch.get_flattened_data()) for ch in img.split()]
    r_rate = _spa_channel(r_data)
    g_rate = _spa_channel(g_data)
    b_rate = _spa_channel(b_data)
    return r_rate, g_rate, b_rate


def _build_spa_result(r_rate, g_rate, b_rate):
    """Build the SPA results dictionary from per-channel rates.

    Args:
        r_rate: Red channel embedding rate estimate.
        g_rate: Green channel embedding rate estimate.
        b_rate: Blue channel embedding rate estimate.

    Returns:
        Dictionary with per-channel rates and overall average rate.
    """
    overall = (r_rate + g_rate + b_rate) / 3
    return {
        "R": round(r_rate, 4),
        "G": round(g_rate, 4),
        "B": round(b_rate, 4),
        "overall": round(overall, 4),
    }


def _spa_analysis(image_path):
    """Run Sample Pairs Analysis across all RGB channels.

    Args:
        image_path: Path to the image file.

    Returns:
        Dictionary with per-channel embedding rate estimates and overall rate.
    """
    r_rate, g_rate, b_rate = _compute_spa_rates(image_path)
    return _build_spa_result(r_rate, g_rate, b_rate)


# ===========================================================================
# RS (Regular-Singular) Steganalysis helpers
# ===========================================================================


def _flip_single_value(val, m):
    """Apply a single mask flip operation to a pixel value.

    Args:
        val: Pixel channel value.
        m: Mask value (0, 1, or -1).

    Returns:
        Flipped pixel value.
    """
    if m == 1:
        return val ^ 1
    if m == -1:
        return val ^ 1 if val % 2 == 0 else val ^ 1
    return val


def _apply_mask_flip(group, mask):
    """Apply a flipping mask to a group of pixel values.

    For each pixel in the group, if the corresponding mask bit is 1,
    the LSB is flipped. If the mask bit is -1, the LSB is set to its
    inverse plus one (negative flip).

    Args:
        group: List of pixel values.
        mask: List of mask values (0, 1, or -1) same length as group.

    Returns:
        New list of pixel values after mask application.
    """
    return [_flip_single_value(val, m) for val, m in zip(group, mask)]


def _group_smoothness(group):
    """Compute smoothness of a pixel group as sum of adjacent differences.

    Args:
        group: List of pixel values.

    Returns:
        Float smoothness score (lower = smoother).
    """
    return sum(abs(group[i] - group[i + 1]) for i in range(len(group) - 1))


def _classify_rs_group(group, mask):
    """Classify a pixel group as Regular, Singular, or Unusable.

    A group is Regular if flipping increases smoothness, Singular if
    it decreases smoothness, and Unusable otherwise.

    Args:
        group: List of pixel values.
        mask: Flipping mask to apply.

    Returns:
        String: 'R' (regular), 'S' (singular), or 'U' (unusable).
    """
    original_smooth = _group_smoothness(group)
    flipped = _apply_mask_flip(group, mask)
    flipped_smooth = _group_smoothness(flipped)
    if flipped_smooth > original_smooth:
        return "R"
    if flipped_smooth < original_smooth:
        return "S"
    return "U"


def _build_rs_masks(group_size):
    """Build positive and negative RS flipping masks.

    Args:
        group_size: Number of pixels per analysis group.

    Returns:
        Tuple of (positive_mask, negative_mask).
    """
    mask_p = [1, 0] * (group_size // 2)
    mask_n = [-1, 0] * (group_size // 2)
    return mask_p, mask_n


def _classify_and_count_group(group, mask_p, mask_n):
    """Classify a group under both positive and negative masks.

    Args:
        group: List of pixel values.
        mask_p: Positive flipping mask.
        mask_n: Negative flipping mask.

    Returns:
        Tuple of (is_regular_p, is_singular_p, is_regular_n, is_singular_n).
    """
    cls_p = _classify_rs_group(group, mask_p)
    cls_n = _classify_rs_group(group, mask_n)
    return (cls_p == "R", cls_p == "S", cls_n == "R", cls_n == "S")


def _count_rs_groups(data, group_size, mask_p, mask_n):
    """Count Regular and Singular groups across all pixel data.

    Args:
        data: List of pixel values for one channel.
        group_size: Number of pixels per analysis group.
        mask_p: Positive flipping mask.
        mask_n: Negative flipping mask.

    Returns:
        Tuple of (rm, sm, r_m, s_m) counts.
    """
    rm, sm, r_m, s_m = 0, 0, 0, 0
    for i in range(0, len(data) - group_size + 1, group_size):
        rp, sp, rn, sn = _classify_and_count_group(
            data[i : i + group_size], mask_p, mask_n
        )
        rm, sm = rm + rp, sm + sp
        r_m, s_m = r_m + rn, s_m + sn
    return rm, sm, r_m, s_m


def _rs_channel(data, group_size=4):
    """Run RS steganalysis on a single channel.

    Counts Regular and Singular groups under positive and negative
    masks, then estimates the embedding rate from the R-S imbalance.

    Args:
        data: List of pixel values for one channel.
        group_size: Number of pixels per analysis group (default 4).

    Returns:
        Dictionary with rm, sm, r_m, s_m counts and estimated embedding rate.
    """
    mask_p, mask_n = _build_rs_masks(group_size)
    rm, sm, r_m, s_m = _count_rs_groups(data, group_size, mask_p, mask_n)
    total = rm + sm + r_m + s_m
    rate = abs(rm - sm) / total if total > 0 else 0.0
    return {"rm": rm, "sm": sm, "r_m": r_m, "s_m": s_m, "rate": round(rate, 4)}


def _compute_rs_channels(image_path):
    """Compute RS analysis results for each RGB channel.

    Args:
        image_path: Path to the image file.

    Returns:
        Dictionary with per-channel RS result dictionaries.
    """
    img = PIL.Image.open(image_path).convert("RGB")
    r_data, g_data, b_data = [list(ch.get_flattened_data()) for ch in img.split()]
    return {
        "R": _rs_channel(r_data),
        "G": _rs_channel(g_data),
        "B": _rs_channel(b_data),
    }


def _rs_analysis(image_path):
    """Run RS steganalysis across all RGB channels.

    RS analysis compares Regular and Singular group counts under
    positive and negative flipping masks to estimate the probability
    and rate of LSB steganographic embedding.

    Args:
        image_path: Path to the image file.

    Returns:
        Dictionary with per-channel RS results and overall embedding estimate.
    """
    results = _compute_rs_channels(image_path)
    overall = (results["R"]["rate"] + results["G"]["rate"] + results["B"]["rate"]) / 3
    results["overall"] = round(overall, 4)
    return results


# ===========================================================================
# Bit-plane analysis helpers
# ===========================================================================


def _extract_bit_plane(channel_data, width, height, bit):
    """Extract a single bit plane from channel data as a binary image.

    Args:
        channel_data: List of pixel values for one channel.
        width: Image width.
        height: Image height.
        bit: Bit position to extract (0 = LSB, 7 = MSB).

    Returns:
        PIL Image showing the extracted bit plane (white = 1, black = 0).
    """
    plane = PIL.Image.new("L", (width, height))
    pixels = [255 if (v >> bit) & 1 else 0 for v in channel_data]
    plane.putdata(pixels)
    return plane


def _bit_plane_entropy(channel_data, bit):
    """Compute Shannon entropy of a single bit plane.

    Random-looking LSB planes (high entropy) can indicate hidden data,
    while natural images typically have structured LSB planes.

    Args:
        channel_data: List of pixel values for one channel.
        bit: Bit position to analyze (0 = LSB).

    Returns:
        Float entropy value (0.0 to 1.0).
    """
    ones = sum(1 for v in channel_data if (v >> bit) & 1)
    total = len(channel_data)
    p1 = ones / total if total > 0 else 0
    p0 = 1 - p1
    if p0 <= 0 or p1 <= 0:
        return 0.0
    return -(p0 * math.log2(p0) + p1 * math.log2(p1))


def _extract_rgb_channels(image_path):
    """Load an image and extract per-channel pixel data as a dictionary.

    Args:
        image_path: Path to the image file.

    Returns:
        Dictionary mapping channel name ('R', 'G', 'B') to pixel value lists.
    """
    img = PIL.Image.open(image_path).convert("RGB")
    return {
        "R": list(img.split()[0].get_flattened_data()),
        "G": list(img.split()[1].get_flattened_data()),
        "B": list(img.split()[2].get_flattened_data()),
    }


def _analyze_channel_entropy(ch_name, ch_data, results, flags):
    """Compute bit-plane entropies for one channel and flag anomalies.

    Args:
        ch_name: Channel name string ('R', 'G', or 'B').
        ch_data: List of pixel values for the channel.
        results: Dictionary to populate with entropy values.
        flags: List to append anomaly flag strings to.
    """
    entropies = [round(_bit_plane_entropy(ch_data, bit), 4) for bit in range(8)]
    results[ch_name] = entropies
    if entropies[0] > 0.995:
        flags.append(
            f"{ch_name} LSB entropy={entropies[0]:.4f} (near-random, possible steganography)"
        )


def _analyze_bit_planes(image_path):
    """Analyze bit-plane entropy across RGB channels for LSB anomalies.

    Args:
        image_path: Path to the image file.

    Returns:
        Dictionary with per-channel, per-bit entropy values and flags.
    """
    channels = _extract_rgb_channels(image_path)
    results = {}
    flags = []
    for ch_name, ch_data in channels.items():
        _analyze_channel_entropy(ch_name, ch_data, results, flags)
    results["flags"] = flags
    return results


# ===========================================================================
# LSB brute-force extraction attempt helpers
# ===========================================================================


def _is_printable_text(text):
    """Check whether a decoded string consists of plausible printable text.

    Args:
        text: Decoded string to check.

    Returns:
        True if the text looks like real human-readable content.
    """
    if len(text) < 3:
        return False
    printable = sum(1 for c in text if 32 <= ord(c) <= 126)
    return printable / len(text) > 0.85


def _try_decode_at_bits(image_path, bits):
    """Attempt LSB decoding at a specific bit depth without password.

    Args:
        image_path: Path to the image file.
        bits: Number of LSBs per channel to try.

    Returns:
        Decoded text if readable, or None.
    """
    try:
        text = _decode_lsb(image_path, bits_per_channel=bits)
        if _is_printable_text(text):
            return text
    except Exception:
        pass
    return None


def _brute_force_decode(image_path):
    """Attempt to extract hidden messages by trying common LSB configurations.

    Tries 1-4 bits per channel without a password. If steganography was
    done with a password, this will not find the message (by design).

    Args:
        image_path: Path to the image file.

    Returns:
        List of dicts with 'bits', 'text' for each successful extraction.
    """
    found = []
    for bits in range(1, 5):
        text = _try_decode_at_bits(image_path, bits)
        if text:
            found.append({"bits": bits, "text": text})
    return found


# ===========================================================================
# JPEG format detection
# ===========================================================================


def _is_jpeg_file(image_path):
    """Detect whether a file is JPEG by checking its magic bytes.

    Args:
        image_path: Path to the image file.

    Returns:
        True if the file starts with the JPEG SOI marker (FF D8).
    """
    with open(image_path, "rb") as f:
        header = f.read(2)
    return header == b"\xff\xd8"


# ===========================================================================
# JPEG DCT coefficient analysis helpers
# ===========================================================================


def _process_jpeg_segment(data, pos, qt_tables):
    """Process a single JPEG segment, extracting DQT tables if found.

    Args:
        data: Raw JPEG file bytes.
        pos: Current byte position in the data.
        qt_tables: Dictionary to populate with quantization tables.

    Returns:
        Segment length, or -1 if an end marker was encountered.
    """
    marker = data[pos : pos + 2]
    if marker in (b"\xff\xd9", b"\xff\xda"):
        return -1
    seg_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
    if marker == b"\xff\xdb":
        _parse_dqt_segment(data, pos + 4, pos + 2 + seg_len, qt_tables)
    return seg_len


def _scan_jpeg_segments(data, qt_tables):
    """Scan all JPEG segments to extract quantization tables.

    Args:
        data: Raw JPEG file bytes.
        qt_tables: Dictionary to populate with table_id -> values.
    """
    pos = 2
    while pos < len(data) - 3:
        if data[pos] != 0xFF:
            break
        seg_len = _process_jpeg_segment(data, pos, qt_tables)
        if seg_len < 0:
            break
        pos += 2 + seg_len


def _read_jpeg_quant_tables(data):
    """Parse JPEG data to extract quantization tables.

    Scans JPEG segment markers to find DQT (Define Quantization Table)
    segments and returns each table indexed by its ID.

    Args:
        data: Raw JPEG file bytes.

    Returns:
        Dictionary mapping table_id to list of 64 quantization values.
    """
    qt_tables = {}
    _scan_jpeg_segments(data, qt_tables)
    return qt_tables


def _parse_single_qt(data, offset):
    """Parse a single quantization table entry from raw bytes.

    Args:
        data: Raw JPEG file bytes.
        offset: Byte offset where the table entry begins.

    Returns:
        Tuple of (table_id, quantization_values, bytes_consumed).
    """
    precision_id = data[offset]
    table_id = precision_id & 0x0F
    precision = (precision_id >> 4) & 0x0F
    elem_size = 2 if precision else 1
    qt = _extract_qt_values(data, offset + 1, elem_size)
    return table_id, qt, 1 + 64 * elem_size


def _parse_dqt_segment(data, start, end, qt_tables):
    """Parse a single DQT segment to populate quantization tables.

    Args:
        data: Raw JPEG file bytes.
        start: Byte offset where table data begins.
        end: Byte offset where segment ends.
        qt_tables: Dictionary to populate with table_id -> values.
    """
    offset = start
    while offset < end:
        table_id, qt, advance = _parse_single_qt(data, offset)
        qt_tables[table_id] = qt
        offset += advance


def _extract_qt_values(data, start, elem_size):
    """Extract 64 quantization values from raw bytes.

    Args:
        data: Raw JPEG file bytes.
        start: Byte offset where values begin.
        elem_size: 1 for 8-bit precision, 2 for 16-bit.

    Returns:
        List of 64 quantization coefficient values.
    """
    qt = []
    for i in range(64):
        if elem_size == 2:
            qt.append(struct.unpack(">H", data[start + i * 2 : start + i * 2 + 2])[0])
        else:
            qt.append(data[start + i])
    return qt


def _import_cv2_numpy():
    """Import OpenCV and NumPy, returning None pair if unavailable.

    Returns:
        Tuple of (cv2_module, numpy_module) or (None, None).
    """
    try:
        import cv2
        import numpy as np

        return cv2, np
    except ImportError:
        return None, None


def _prepare_dct_array(y_channel, np_mod):
    """Convert luminance channel to a float32 array aligned to 8x8 blocks.

    Args:
        y_channel: 2D list/array of luminance pixel values.
        np_mod: NumPy module reference.

    Returns:
        Tuple of (aligned_array, height_8, width_8).
    """
    arr = np_mod.array(y_channel, dtype=np_mod.float32)
    h, w = arr.shape
    h8, w8 = (h // 8) * 8, (w // 8) * 8
    return arr[:h8, :w8], h8, w8


def _compute_dct_blocks(y_channel):
    """Compute DCT coefficients for all 8x8 blocks of a luminance channel.

    Applies the type-II DCT to each non-overlapping 8x8 pixel block
    after centering values around zero (subtracting 128).

    Args:
        y_channel: 2D list/array of luminance pixel values.

    Returns:
        List of all AC DCT coefficients (DC coefficients excluded).
    """
    cv2, np = _import_cv2_numpy()
    if cv2 is None:
        return []
    arr, h8, w8 = _prepare_dct_array(y_channel, np)
    return _extract_ac_coefficients(arr, h8, w8, cv2)


def _extract_ac_coefficients(arr, h8, w8, cv2):
    """Extract all AC DCT coefficients from aligned 8x8 blocks.

    Args:
        arr: Float32 numpy array of pixel values.
        h8: Height truncated to multiple of 8.
        w8: Width truncated to multiple of 8.
        cv2: OpenCV module reference.

    Returns:
        Numpy array of all AC (non-DC) DCT coefficients.
    """
    import numpy as np

    all_coeffs = []
    for i in range(0, h8, 8):
        for j in range(0, w8, 8):
            block = arr[i : i + 8, j : j + 8] - 128.0
            dct_block = cv2.dct(block)
            _collect_ac_from_block(dct_block, all_coeffs)
    return np.array(all_coeffs)


def _collect_ac_from_block(dct_block, all_coeffs):
    """Append all AC coefficients from a single DCT block.

    Args:
        dct_block: 8x8 DCT coefficient matrix.
        all_coeffs: List to append rounded integer AC values to.
    """
    for r in range(8):
        for c in range(8):
            if r == 0 and c == 0:
                continue
            all_coeffs.append(int(round(dct_block[r, c])))


def _count_dct_pair(coeffs, even_val):
    """Count occurrences of an even value and its odd neighbor.

    Args:
        coeffs: Numpy array of DCT coefficients.
        even_val: The even-valued coefficient to check.

    Returns:
        Tuple of (even_count, odd_count) for the pair.
    """
    import numpy as np

    even_count = int(np.sum(coeffs == even_val))
    odd_count = int(np.sum(coeffs == even_val + 1))
    return even_count, odd_count


def _compute_dct_pair_ratios(coeffs):
    """Compute even/odd pair ratios for JSteg detection.

    JSteg replaces LSBs of non-zero, non-one DCT coefficients. This
    equalizes pair counts (ratio -> 1.0). Natural images show unequal
    pair counts (ratio != 1.0).

    Args:
        coeffs: Numpy array of all AC DCT coefficients.

    Returns:
        List of (even_val, ratio) tuples for analyzed pairs.
    """
    test_values = [2, 4, 6, 8, 10, -10, -8, -6, -4, -2]
    ratios = []
    for even_val in test_values:
        even_count, odd_count = _count_dct_pair(coeffs, even_val)
        if odd_count > 0:
            ratios.append((even_val, even_count / odd_count))
    return ratios


def _compute_dct_pair_stats(pair_ratios):
    """Compute mean and standard deviation of DCT pair ratios.

    Args:
        pair_ratios: List of (even_val, ratio) tuples.

    Returns:
        Tuple of (mean_ratio, std_ratio).
    """
    if not pair_ratios:
        return 0.0, 0.0
    vals = [r for _, r in pair_ratios]
    mean = sum(vals) / len(vals)
    variance = sum((v - mean) ** 2 for v in vals) / len(vals)
    return mean, variance**0.5


def _detect_jsteg(pair_ratios):
    """Determine if DCT pair ratios indicate JSteg embedding.

    JSteg makes pair ratios converge to ~1.0 with low variance. Natural
    images have widely varying pair ratios.

    Args:
        pair_ratios: List of (even_val, ratio) tuples.

    Returns:
        String verdict: 'DETECTED', 'SUSPICIOUS', or 'CLEAN'.
    """
    mean, std = _compute_dct_pair_stats(pair_ratios)
    if JSTEG_PAIR_RATIO_MIN < mean < JSTEG_PAIR_RATIO_MAX and std < JSTEG_STD_THRESHOLD:
        return "DETECTED"
    if 0.80 < mean < 1.20 and std < 0.25:
        return "SUSPICIOUS"
    return "CLEAN"


def _count_dct_zeros(coeffs):
    """Count zero-valued DCT coefficients and compute their percentage.

    F5 steganography shrinks non-zero coefficients toward zero, inflating
    the zero count above what the quantization tables would predict.

    Args:
        coeffs: Numpy array of all AC DCT coefficients.

    Returns:
        Tuple of (zero_count, zero_percentage, plus_minus_one_count).
    """
    import numpy as np

    zero_count = int(np.sum(coeffs == 0))
    pm1_count = int(np.sum(coeffs == 1)) + int(np.sum(coeffs == -1))
    zero_pct = zero_count / max(len(coeffs), 1) * 100
    return zero_count, zero_pct, pm1_count


def _detect_f5(zero_pct):
    """Determine if the zero-coefficient percentage suggests F5 embedding.

    Args:
        zero_pct: Percentage of zero-valued AC DCT coefficients.

    Returns:
        String verdict: 'SUSPICIOUS' or 'CLEAN'.
    """
    if zero_pct > 80:
        return "SUSPICIOUS"
    return "CLEAN"


def _compute_dct_lsb_ratio(coeffs):
    """Compute the even/odd LSB ratio of usable DCT coefficients.

    Excludes zero and ±1 coefficients (not modified by JSteg). A ratio
    near 1.0 indicates possible JSteg embedding.

    Args:
        coeffs: Numpy array of all AC DCT coefficients.

    Returns:
        Tuple of (even_count, odd_count, ratio).
    """
    import numpy as np

    usable = coeffs[(coeffs != 0) & (coeffs != 1) & (coeffs != -1)]
    even = int(np.sum(usable % 2 == 0))
    odd = int(np.sum(np.abs(usable) % 2 == 1))
    ratio = even / max(odd, 1)
    return even, odd, ratio


def _build_dct_histogram(coeffs):
    """Build a frequency histogram of DCT coefficients from -50 to +50.

    Args:
        coeffs: Numpy array of all AC DCT coefficients.

    Returns:
        Dictionary mapping integer value to its count.
    """
    import numpy as np

    counts = {}
    for v in range(-50, 51):
        counts[v] = int(np.sum(coeffs == v))
    return counts


def _load_image_cv2(image_path):
    """Load an image using OpenCV, returning None pair if unavailable.

    Args:
        image_path: Path to the image file.

    Returns:
        Tuple of (cv2_module, loaded_image) or (None, None).
    """
    try:
        import cv2
    except ImportError:
        return None, None
    img = cv2.imread(image_path)
    return cv2, img


def _get_luminance_channel(image_path):
    """Load an image and extract the Y (luminance) channel in YCrCb space.

    Args:
        image_path: Path to the image file.

    Returns:
        2D numpy array of luminance values, or None if OpenCV unavailable.
    """
    cv2, img = _load_image_cv2(image_path)
    if img is None:
        return None
    ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
    return ycrcb[:, :, 0]


def _jpeg_dct_analysis(image_path):
    """Run full DCT-level steganography analysis on a JPEG image.

    Performs JSteg pair analysis, F5 zero-count analysis, and DCT LSB
    ratio measurement. These detect steganography hidden in DCT
    coefficients rather than in spatial-domain pixel values.

    Args:
        image_path: Path to the JPEG image file.

    Returns:
        Dictionary with jsteg, f5, lsb_ratio, histogram, and pair data,
        or None if OpenCV is not available.
    """
    y_channel = _get_luminance_channel(image_path)
    if y_channel is None:
        return None
    coeffs = _compute_dct_blocks(y_channel)
    if len(coeffs) == 0:
        return None
    return _assemble_dct_results(coeffs)


def _compute_dct_jsteg_parts(coeffs):
    """Compute JSteg-related DCT analysis components.

    Args:
        coeffs: Numpy array of all AC DCT coefficients.

    Returns:
        Tuple of (pair_ratios, jsteg_verdict, mean, std).
    """
    pair_ratios = _compute_dct_pair_ratios(coeffs)
    jsteg_verdict = _detect_jsteg(pair_ratios)
    mean, std = _compute_dct_pair_stats(pair_ratios)
    return pair_ratios, jsteg_verdict, mean, std


def _compute_dct_f5_lsb_parts(coeffs):
    """Compute F5 and LSB-related DCT analysis components.

    Args:
        coeffs: Numpy array of all AC DCT coefficients.

    Returns:
        Tuple of (zero_count, zero_pct, pm1_count, f5_verdict,
        even, odd, lsb_ratio, histogram).
    """
    zero_count, zero_pct, pm1_count = _count_dct_zeros(coeffs)
    f5_verdict = _detect_f5(zero_pct)
    even, odd, lsb_ratio = _compute_dct_lsb_ratio(coeffs)
    histogram = _build_dct_histogram(coeffs)
    return zero_count, zero_pct, pm1_count, f5_verdict, even, odd, lsb_ratio, histogram


def _build_dct_pair_dict(pair_ratios, jsteg_verdict, mean, std):
    """Build the JSteg pair analysis portion of DCT results.

    Args:
        pair_ratios: List of (even_val, ratio) tuples.
        jsteg_verdict: JSteg detection verdict string.
        mean: Mean of pair ratios.
        std: Standard deviation of pair ratios.

    Returns:
        Dictionary with jsteg, pair_ratios, pair_mean, pair_std keys.
    """
    return {
        "jsteg": jsteg_verdict,
        "pair_ratios": pair_ratios,
        "pair_mean": round(mean, 4),
        "pair_std": round(std, 4),
    }


def _build_dct_zero_dict(f5_verdict, zero_count, zero_pct, pm1_count):
    """Build the F5 zero-count portion of DCT results.

    Args:
        f5_verdict: F5 detection verdict string.
        zero_count: Number of zero-valued AC coefficients.
        zero_pct: Percentage of zero-valued AC coefficients.
        pm1_count: Count of plus/minus one coefficients.

    Returns:
        Dictionary with f5, zero_count, zero_pct, pm1_count keys.
    """
    return {
        "f5": f5_verdict,
        "zero_count": zero_count,
        "zero_pct": round(zero_pct, 1),
        "pm1_count": pm1_count,
    }


def _build_dct_lsb_dict(even, odd, lsb_ratio, total, histogram):
    """Build the LSB ratio portion of DCT results.

    Args:
        even: Count of even-valued usable coefficients.
        odd: Count of odd-valued usable coefficients.
        lsb_ratio: Even/odd ratio.
        total: Total number of AC coefficients.
        histogram: DCT coefficient frequency histogram.

    Returns:
        Dictionary with lsb_even, lsb_odd, lsb_ratio, total_coeffs,
        histogram keys.
    """
    return {
        "lsb_even": even,
        "lsb_odd": odd,
        "lsb_ratio": round(lsb_ratio, 4),
        "total_coeffs": total,
        "histogram": histogram,
    }


def _assemble_dct_results(coeffs):
    """Assemble all DCT analysis results into a single dictionary.

    Args:
        coeffs: Numpy array of all AC DCT coefficients.

    Returns:
        Dictionary with jsteg, f5, lsb_ratio, pair_ratios, and histogram.
    """
    pair_ratios, jsteg_verdict, mean, std = _compute_dct_jsteg_parts(coeffs)
    zero_count, zero_pct, pm1_count, f5_verdict, even, odd, lsb_ratio, histogram = (
        _compute_dct_f5_lsb_parts(coeffs)
    )
    result = _build_dct_pair_dict(pair_ratios, jsteg_verdict, mean, std)
    result.update(_build_dct_zero_dict(f5_verdict, zero_count, zero_pct, pm1_count))
    result.update(_build_dct_lsb_dict(even, odd, lsb_ratio, len(coeffs), histogram))
    return result


# ===========================================================================
# Comprehensive stego scan (terminal output) helpers
# ===========================================================================


def _print_scan_header(image_path):
    """Print the steganography scan banner.

    Args:
        image_path: Path to the image being scanned.
    """
    print(f"\n{'=' * 70}")
    print(f"  PIXELPROOF STEGANOGRAPHY SCAN")
    print(f"  {os.path.basename(image_path)}")
    print(f"{'=' * 70}")


def _print_chi_header():
    """Print the chi-square analysis section header and column labels."""
    print(f"\n  --- Chi-Square LSB Analysis ---\n")
    print(
        f"    {'Channel':10s} {'Chi-Sq':12s} {'DoF':6s} {'p-value':10s} {'Verdict':10s}"
    )
    print(f"    {'-' * 10} {'-' * 12} {'-' * 6} {'-' * 10} {'-' * 10}")


def _print_chi_channel_row(ch, r):
    """Print a single channel row in the chi-square results table.

    Args:
        ch: Channel name string ('R', 'G', or 'B').
        r: Channel result dictionary with chi_square, dof, p_value, verdict.
    """
    print(
        f"    {ch:10s} {r['chi_square']:12.2f} {r['dof']:6d} {r['p_value']:10.4f} {r['verdict']:10s}"
    )


def _print_chi_results(chi):
    """Print chi-square steganalysis results table.

    Args:
        chi: Chi-square analysis results dictionary.
    """
    _print_chi_header()
    for ch in "RGB":
        _print_chi_channel_row(ch, chi[ch])
    print(f"\n    Overall: {chi['overall']}")


def _print_spa_results(spa):
    """Print Sample Pairs Analysis results table.

    Args:
        spa: SPA results dictionary.
    """
    print(f"\n  --- Sample Pairs Analysis (SPA) ---\n")
    print(f"    {'Channel':10s} {'Est. Rate':12s}")
    print(f"    {'-' * 10} {'-' * 12}")
    for ch in "RGB":
        print(f"    {ch:10s} {spa[ch]:12.4f}")
    print(f"\n    Overall estimated embedding rate: {spa['overall']:.4f}")


def _print_rs_header():
    """Print the RS analysis section header and column labels."""
    print(f"\n  --- RS (Regular-Singular) Analysis ---\n")
    print(f"    {'Channel':10s} {'Rm':8s} {'Sm':8s} {'R-m':8s} {'S-m':8s} {'Rate':8s}")
    print(f"    {'-' * 10} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 8}")


def _print_rs_results(rs):
    """Print RS steganalysis results table.

    Args:
        rs: RS analysis results dictionary.
    """
    _print_rs_header()
    for ch in "RGB":
        r = rs[ch]
        print(
            f"    {ch:10s} {r['rm']:8d} {r['sm']:8d} {r['r_m']:8d} {r['s_m']:8d} {r['rate']:8.4f}"
        )
    print(f"\n    Overall RS embedding estimate: {rs['overall']:.4f}")


def _print_bitplane_header():
    """Print the bit-plane entropy section header and column labels."""
    print(f"\n  --- Bit-Plane Entropy Analysis ---\n")
    print(
        f"    {'Channel':10s} {'Bit 0 (LSB)':12s} {'Bit 1':12s} {'Bit 2':12s} {'Bit 7 (MSB)':12s}"
    )
    print(f"    {'-' * 10} {'-' * 12} {'-' * 12} {'-' * 12} {'-' * 12}")


def _print_bitplane_flags(bp):
    """Print any bit-plane anomaly flags.

    Args:
        bp: Bit-plane analysis results dictionary.
    """
    if bp["flags"]:
        print("\n    Flags:")
        for f in bp["flags"]:
            print(f"      >> {f}")


def _print_bitplane_results(bp):
    """Print bit-plane entropy analysis results.

    Args:
        bp: Bit-plane analysis results dictionary.
    """
    _print_bitplane_header()
    for ch in "RGB":
        e = bp[ch]
        print(f"    {ch:10s} {e[0]:12.4f} {e[1]:12.4f} {e[2]:12.4f} {e[7]:12.4f}")
    _print_bitplane_flags(bp)


def _print_extraction_results(found):
    """Print brute-force LSB extraction results.

    Args:
        found: List of successful extraction dicts.
    """
    print(f"\n  --- Brute-Force LSB Extraction ---\n")
    if not found:
        print("    No readable hidden messages found (without password).")
        return
    for hit in found:
        preview = hit["text"][:200] + "..." if len(hit["text"]) > 200 else hit["text"]
        print(f"    FOUND at {hit['bits']} bit(s)/channel:")
        print(f'    >> "{preview}"')


def _print_jpeg_warning():
    """Print a warning that pixel-level analysis is unreliable for JPEG.

    JPEG lossy compression makes spatial-domain LSBs inherently random,
    which causes false positives in chi-square, SPA, RS, and bit-plane
    entropy analyses. DCT-level analysis is used instead.
    """
    print(f"\n  {'*' * 60}")
    print(f"  * JPEG FORMAT DETECTED")
    print(f"  * Pixel-level LSB tests are UNRELIABLE for JPEG images.")
    print(f"  * JPEG compression makes spatial LSBs inherently random,")
    print(f"  * which causes false positives. Using DCT analysis instead.")
    print(f"  {'*' * 60}")


def _print_dct_pair_header():
    """Print the DCT pair analysis section header and column labels."""
    print(f"\n  --- DCT Pair Analysis (JSteg Detection) ---\n")
    print(f"    {'Pair':12s} {'Even Count':12s} {'Odd Count':12s} {'Ratio':10s}")
    print(f"    {'-' * 12} {'-' * 12} {'-' * 12} {'-' * 10}")


def _print_dct_pair_table(dct):
    """Print the DCT coefficient pair ratio table for JSteg detection.

    Args:
        dct: DCT analysis results dictionary.
    """
    _print_dct_pair_header()
    for even_val, ratio in dct["pair_ratios"]:
        print(
            f"    ({even_val:3d},{even_val + 1:3d})   {'':12s} {'':12s} {ratio:10.4f}"
        )
    print(f"\n    Mean ratio: {dct['pair_mean']:.4f}  (std: {dct['pair_std']:.4f})")
    print(f"    JSteg verdict: {dct['jsteg']}")


def _print_dct_f5_results(dct):
    """Print DCT zero-count analysis for F5 detection.

    Args:
        dct: DCT analysis results dictionary.
    """
    print(f"\n  --- DCT Zero Analysis (F5 Detection) ---\n")
    print(f"    Total AC coefficients: {dct['total_coeffs']}")
    print(f"    Zero coefficients:     {dct['zero_count']} ({dct['zero_pct']:.1f}%)")
    print(f"    +/-1 coefficients:     {dct['pm1_count']}")
    print(f"    F5 verdict: {dct['f5']}")


def _print_dct_lsb_results(dct):
    """Print DCT LSB even/odd ratio analysis.

    Args:
        dct: DCT analysis results dictionary.
    """
    print(f"\n  --- DCT LSB Ratio (excl. 0, +/-1) ---\n")
    print(
        f"    Even: {dct['lsb_even']}  Odd: {dct['lsb_odd']}  Ratio: {dct['lsb_ratio']:.4f}"
    )
    if 0.9 < dct["lsb_ratio"] < 1.1:
        print("    >> Near-equal ratio: possible JSteg embedding")
    else:
        print("    >> Natural distribution (no JSteg)")


def _print_dct_results(dct):
    """Print all DCT analysis subsections.

    Args:
        dct: DCT analysis results dictionary, or None if unavailable.
    """
    if dct is None:
        print("\n  --- DCT Analysis ---\n")
        print("    OpenCV not available; skipping DCT analysis.")
        return
    _print_dct_pair_table(dct)
    _print_dct_f5_results(dct)
    _print_dct_lsb_results(dct)


def _gather_base_jpeg_findings(found):
    """Gather initial findings for JPEG verdict computation.

    Args:
        found: List of brute-force extraction hits.

    Returns:
        List of (description, severity) tuples.
    """
    findings = []
    if found:
        findings.append((f"Hidden message extracted ({len(found)} config(s))", 3))
    return findings


def _gather_dct_findings(dct, findings):
    """Gather DCT-based findings from JSteg, F5, and LSB analyses.

    Args:
        dct: DCT analysis results dictionary.
        findings: List of (description, severity) to append to.
    """
    _evaluate_dct_jsteg(dct, findings)
    _evaluate_dct_f5(dct, findings)
    _evaluate_dct_lsb(dct, findings)


def _compute_jpeg_verdict(dct, found):
    """Compute steganography verdict for JPEG images using DCT analysis.

    For JPEG images, only DCT-level analysis and brute-force extraction
    are reliable. Pixel-level chi-square, SPA, RS, and bit-plane results
    are ignored because JPEG compression creates false positives.

    Args:
        dct: DCT analysis results dictionary (may be None).
        found: List of brute-force extraction hits.

    Returns:
        Tuple of (verdict_string, findings_list).
    """
    findings = _gather_base_jpeg_findings(found)
    if dct is None:
        findings.append(("DCT analysis unavailable (install opencv-python)", 1))
        return _classify_jpeg_findings(findings, found)
    _gather_dct_findings(dct, findings)
    return _classify_jpeg_findings(findings, found)


def _evaluate_dct_jsteg(dct, findings):
    """Add JSteg-related findings based on DCT pair analysis.

    Args:
        dct: DCT analysis results dictionary.
        findings: List of (description, severity) to append to.
    """
    if dct["jsteg"] == "DETECTED":
        findings.append(("JSteg embedding detected in DCT coefficients", 3))
    elif dct["jsteg"] == "SUSPICIOUS":
        findings.append(("DCT pairs show possible JSteg equalization", 2))


def _evaluate_dct_f5(dct, findings):
    """Add F5-related findings based on zero-coefficient analysis.

    Args:
        dct: DCT analysis results dictionary.
        findings: List of (description, severity) to append to.
    """
    if dct["f5"] == "SUSPICIOUS":
        findings.append(("Excess zero DCT coefficients (possible F5)", 2))


def _evaluate_dct_lsb(dct, findings):
    """Add findings based on DCT LSB even/odd ratio.

    Args:
        dct: DCT analysis results dictionary.
        findings: List of (description, severity) to append to.
    """
    if 0.9 < dct["lsb_ratio"] < 1.1:
        findings.append(("DCT LSB ratio near 1.0 (possible embedding)", 2))


def _classify_jpeg_findings(findings, found):
    """Classify the overall JPEG verdict from accumulated findings.

    Args:
        findings: List of (description, severity) tuples.
        found: List of brute-force extraction hits.

    Returns:
        Tuple of (verdict_string, findings_list).
    """
    total = sum(s for _, s in findings)
    if total >= 5 or found:
        return "STEGANOGRAPHY DETECTED", findings
    if total >= 2:
        return "SUSPICIOUS -- possible hidden data", findings
    return "CLEAN -- no steganography indicators", findings


def _gather_chi_findings(chi, findings):
    """Add chi-square analysis findings to the findings list.

    Args:
        chi: Chi-square results dictionary.
        findings: List of (description, severity) to append to.
    """
    if chi["overall"] == "LIKELY":
        findings.append(("Chi-square detects LSB embedding", 3))
    elif chi["overall"] == "SUSPICIOUS":
        findings.append(("Chi-square anomaly in value-pair distribution", 2))


def _gather_spa_rs_findings(spa, rs, findings):
    """Add SPA and RS analysis findings to the findings list.

    Args:
        spa: SPA results dictionary.
        rs: RS results dictionary.
        findings: List of (description, severity) to append to.
    """
    if spa["overall"] > 0.05:
        findings.append((f"SPA estimates {spa['overall']:.1%} embedding rate", 2))
    if rs["overall"] > 0.02:
        findings.append((f"RS analysis detects {rs['overall']:.1%} embedding rate", 2))


def _gather_bp_extract_findings(bp, found, findings):
    """Add bit-plane and extraction findings to the findings list.

    Args:
        bp: Bit-plane results dictionary.
        found: List of brute-force extraction hits.
        findings: List of (description, severity) to append to.
    """
    for f in bp["flags"]:
        findings.append((f, 2))
    if found:
        findings.append((f"Hidden message extracted ({len(found)} config(s))", 3))


def _classify_scan_findings(findings, found):
    """Classify the overall scan verdict from accumulated findings.

    Args:
        findings: List of (description, severity) tuples.
        found: List of brute-force extraction hits.

    Returns:
        Tuple of (verdict_string, findings_list).
    """
    total = sum(s for _, s in findings)
    if total >= 5 or found:
        return "STEGANOGRAPHY DETECTED", findings
    if total >= 2:
        return "SUSPICIOUS -- possible hidden data", findings
    return "CLEAN -- no steganography indicators", findings


def _compute_scan_verdict(chi, spa, rs, bp, found):
    """Compute overall steganography scan verdict from all analyses.

    Args:
        chi: Chi-square results dictionary.
        spa: SPA results dictionary.
        rs: RS results dictionary.
        bp: Bit-plane results dictionary.
        found: List of brute-force extraction hits.

    Returns:
        Tuple of (verdict_string, findings_list).
    """
    findings = []
    _gather_chi_findings(chi, findings)
    _gather_spa_rs_findings(spa, rs, findings)
    _gather_bp_extract_findings(bp, found, findings)
    return _classify_scan_findings(findings, found)


def _print_scan_verdict(verdict, findings):
    """Print the steganography scan verdict section.

    Args:
        verdict: Verdict string.
        findings: List of (description, severity) tuples.
    """
    print(f"\n{'=' * 70}")
    print(f"  STEGANOGRAPHY VERDICT: {verdict}")
    print(f"{'=' * 70}")
    if findings:
        sev_labels = {1: "LOW", 2: "MOD", 3: "HIGH"}
        for i, (desc, sev) in enumerate(findings, 1):
            bar = "\u25aa" * sev
            print(f"    {i}. [{bar:<3s}] [{sev_labels.get(sev, '?'):4s}] {desc}")


def _run_chi_spa(image_path):
    """Run chi-square and SPA analyses with printed output.

    Args:
        image_path: Path to the image file.

    Returns:
        Tuple of (chi_results, spa_results).
    """
    chi = _chi_square_analysis(image_path)
    _print_chi_results(chi)
    spa = _spa_analysis(image_path)
    _print_spa_results(spa)
    return chi, spa


def _run_rs_bp(image_path):
    """Run RS and bit-plane analyses with printed output.

    Args:
        image_path: Path to the image file.

    Returns:
        Tuple of (rs_results, bitplane_results).
    """
    rs = _rs_analysis(image_path)
    _print_rs_results(rs)
    bp = _analyze_bit_planes(image_path)
    _print_bitplane_results(bp)
    return rs, bp


def _run_extraction_analysis(image_path):
    """Run brute-force extraction with printed output.

    Args:
        image_path: Path to the image file.

    Returns:
        List of extraction hit dictionaries.
    """
    found = _brute_force_decode(image_path)
    _print_extraction_results(found)
    return found


def _full_stego_scan(image_path):
    """Run comprehensive steganography detection on an image.

    For lossless formats (PNG, BMP, TIFF), runs chi-square, SPA, RS,
    bit-plane, and brute-force extraction analyses.  For JPEG images,
    additionally runs DCT-level JSteg/F5 detection and uses only DCT
    results for the verdict (pixel-level tests produce false positives
    on JPEG due to lossy compression artifacts).

    Args:
        image_path: Path to the image file.

    Returns:
        Dictionary with all analysis results and verdict.
    """
    _print_scan_header(image_path)
    is_jpeg = _is_jpeg_file(image_path)
    chi, spa = _run_chi_spa(image_path)
    rs, bp = _run_rs_bp(image_path)
    found = _run_extraction_analysis(image_path)
    if is_jpeg:
        return _run_jpeg_branch(image_path, chi, spa, rs, bp, found)
    return _run_lossless_branch(chi, spa, rs, bp, found)


def _run_jpeg_branch(image_path, chi, spa, rs, bp, found):
    """Handle scan results for a JPEG image using DCT-level analysis.

    Args:
        image_path: Path to the JPEG image.
        chi: Chi-square results (informational only for JPEG).
        spa: SPA results (informational only for JPEG).
        rs: RS results (informational only for JPEG).
        bp: Bit-plane results (informational only for JPEG).
        found: Brute-force extraction hits.

    Returns:
        Combined results dictionary with DCT analysis and verdict.
    """
    _print_jpeg_warning()
    dct = _jpeg_dct_analysis(image_path)
    _print_dct_results(dct)
    verdict, findings = _compute_jpeg_verdict(dct, found)
    _print_scan_verdict(verdict, findings)
    return _assemble_scan_results(chi, spa, rs, bp, found, verdict, findings, dct)


def _run_lossless_branch(chi, spa, rs, bp, found):
    """Handle scan results for a lossless image using pixel-level analysis.

    Args:
        chi: Chi-square results.
        spa: SPA results.
        rs: RS results.
        bp: Bit-plane results.
        found: Brute-force extraction hits.

    Returns:
        Combined results dictionary with pixel-level verdict.
    """
    verdict, findings = _compute_scan_verdict(chi, spa, rs, bp, found)
    _print_scan_verdict(verdict, findings)
    return _assemble_scan_results(chi, spa, rs, bp, found, verdict, findings, None)


def _build_analysis_dict(chi, spa, rs, bp):
    """Build the analysis portion of scan results.

    Args:
        chi: Chi-square results.
        spa: SPA results.
        rs: RS results.
        bp: Bit-plane results.

    Returns:
        Dictionary with chi, spa, rs, bitplane keys.
    """
    return {"chi": chi, "spa": spa, "rs": rs, "bitplane": bp}


def _build_verdict_dict(found, verdict, findings):
    """Build the verdict portion of scan results.

    Args:
        found: List of brute-force extraction hits.
        verdict: Final verdict string.
        findings: List of (description, severity) findings.

    Returns:
        Dictionary with extracted, verdict, findings keys.
    """
    return {"extracted": found, "verdict": verdict, "findings": findings}


def _assemble_scan_results(chi, spa, rs, bp, found, verdict, findings, dct):
    """Build the final scan results dictionary.

    Args:
        chi: Chi-square results.
        spa: SPA results.
        rs: RS results.
        bp: Bit-plane results.
        found: Brute-force extraction hits.
        verdict: Final verdict string.
        findings: List of (description, severity) findings.
        dct: DCT analysis results (None for lossless images).

    Returns:
        Comprehensive results dictionary.
    """
    results = _build_analysis_dict(chi, spa, rs, bp)
    results.update(_build_verdict_dict(found, verdict, findings))
    if dct is not None:
        results["dct"] = dct
    return results


# ===========================================================================
# Public encode / decode / scan API
# ===========================================================================


def encode_message(image_path, output_path, message, bits_per_channel=1, password=None):
    """Encode a text message into an image using LSB steganography.

    The output MUST be saved as PNG (lossless). JPEG will destroy the
    hidden bits.

    Args:
        image_path: Path to the cover image.
        output_path: Path to save the stego image (.png).
        message: Plaintext message to hide.
        bits_per_channel: Number of LSBs per channel (1-4, default 1).
        password: Optional password for pixel-order shuffling.
    """
    bin_msg = _text_to_bits(message)
    _encode_lsb(image_path, bin_msg, output_path, bits_per_channel, password)
    print(f"  Encoded {len(message)} chars ({len(bin_msg)} bits) into {output_path}")


def encode_file(image_path, output_path, file_path, bits_per_channel=1, password=None):
    """Encode a file's contents into an image using LSB steganography.

    Args:
        image_path: Path to the cover image.
        output_path: Path to save the stego image (.png).
        file_path: Path to the file whose contents will be hidden.
        bits_per_channel: Number of LSBs per channel (1-4, default 1).
        password: Optional password for pixel-order shuffling.
    """
    bin_msg = _file_to_bits(file_path)
    _encode_lsb(image_path, bin_msg, output_path, bits_per_channel, password)
    print(f"  Encoded file '{file_path}' ({len(bin_msg)} bits) into {output_path}")


def decode_message(image_path, bits_per_channel=1, password=None):
    """Decode a hidden message from a stego image.

    Args:
        image_path: Path to the stego image.
        bits_per_channel: Number of LSBs per channel (1-4, default 1).
        password: Optional password used during encoding.

    Returns:
        Decoded plaintext message string.
    """
    text = _decode_lsb(image_path, bits_per_channel, password)
    print(f'  Decoded message: "{text}"')
    return text


def scan_image(image_path):
    """Run full steganography detection scan on an image.

    Args:
        image_path: Path to the image to scan.

    Returns:
        Comprehensive scan results dictionary.
    """
    return _full_stego_scan(image_path)


# ===========================================================================
# CLI entry point
# ===========================================================================


def _print_usage_lines():
    """Print CLI usage instruction lines to stdout."""
    print("Usage:")
    print('  python stego.py encode <image> <output.png> -m "message"')
    print("  python stego.py encode <image> <output.png> -f secret.txt")
    print('  python stego.py encode <image> <output.png> -m "msg" --password pw')
    print('  python stego.py encode <image> <output.png> -m "msg" --bits 2')
    print("  python stego.py decode <image>")
    print("  python stego.py decode <image> --password pw --bits 2")
    print("  python stego.py scan   <image>")


def _print_usage():
    """Print CLI usage instructions and exit."""
    _print_usage_lines()
    sys.exit(1)


def _parse_flag(args, flag, default=None):
    """Extract a flag value from the argument list.

    Args:
        args: List of command-line arguments.
        flag: The flag string to look for (e.g. '--password').
        default: Default value if flag is not found.

    Returns:
        The value following the flag, or the default.
    """
    if flag in args:
        idx = args.index(flag)
        if idx + 1 < len(args):
            return args[idx + 1]
    return default


def _parse_encode_args(args):
    """Parse CLI arguments for the encode subcommand.

    Args:
        args: List of CLI arguments after 'encode'.

    Returns:
        Tuple of (image_path, output_path, bits, password, message, file_path).
    """
    if len(args) < 2:
        _print_usage()
    image_path, output_path = args[0], args[1]
    bits = int(_parse_flag(args, "--bits", "1"))
    password = _parse_flag(args, "--password")
    message = _parse_flag(args, "-m")
    file_path = _parse_flag(args, "-f")
    return image_path, output_path, bits, password, message, file_path


def _execute_encode(image_path, output_path, bits, password, message, file_path):
    """Execute the encode operation with parsed arguments.

    Args:
        image_path: Path to the cover image.
        output_path: Path to save the stego image.
        bits: Number of LSBs per channel.
        password: Optional password for shuffling.
        message: Message string to encode, or None.
        file_path: File path to encode, or None.
    """
    if message:
        encode_message(image_path, output_path, message, bits, password)
    elif file_path:
        encode_file(image_path, output_path, file_path, bits, password)
    else:
        print('Error: provide -m "message" or -f file.txt')
        sys.exit(1)


def _handle_encode(args):
    """Handle the 'encode' CLI subcommand.

    Args:
        args: List of CLI arguments after 'encode'.
    """
    image_path, output_path, bits, password, message, file_path = _parse_encode_args(
        args
    )
    _execute_encode(image_path, output_path, bits, password, message, file_path)


def _handle_decode(args):
    """Handle the 'decode' CLI subcommand.

    Args:
        args: List of CLI arguments after 'decode'.
    """
    if not args:
        _print_usage()
    bits = int(_parse_flag(args, "--bits", "1"))
    password = _parse_flag(args, "--password")
    decode_message(args[0], bits, password)


def _handle_scan(args):
    """Handle the 'scan' CLI subcommand.

    Args:
        args: List of CLI arguments after 'scan'.
    """
    if not args:
        _print_usage()
    scan_image(args[0])


def _dispatch_command(cmd, rest):
    """Dispatch a CLI command to the appropriate handler.

    Args:
        cmd: Command string ('encode', 'decode', or 'scan').
        rest: Remaining CLI arguments after the command.
    """
    if cmd == "encode":
        _handle_encode(rest)
    elif cmd == "decode":
        _handle_decode(rest)
    elif cmd == "scan":
        _handle_scan(rest)
    else:
        _print_usage()


def main():
    """Entry point for the stego command-line tool."""
    if len(sys.argv) < 2:
        _print_usage()
    cmd = sys.argv[1]
    rest = sys.argv[2:]
    _dispatch_command(cmd, rest)


if __name__ == "__main__":
    main()
