
"""
ps_securescan.py

PS-SecureScan: lightweight pre-execution scanner for creative image workflows.
Focus: PSD + common raster formats.
This module is intentionally conservative: it does not fully decode complex formats.
It performs structural checks, metadata sanity checks, entropy heuristics, decompression risk estimation,
and (optional) sandbox hooks.

Design goals:
- deterministic, explainable scores in [0,1]
- minimal dependencies
- safe-by-default parsing (bounded reads, length checks)

NOTE:
- PSD parsing here is partial, focused on header, section lengths and offset consistency.
- Metadata extraction is minimal unless you enable optional parsers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List, Callable
import math
import struct
import hashlib
import os


# ---------------------------
# Utilities
# ---------------------------

def clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else x)

def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def safe_read(path: Path, max_bytes: int) -> bytes:
    with path.open("rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"File too large for safe_read limit: {max_bytes} bytes")
    return data

def entropy_bytes(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = len(buf)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent  # in [0,8]

def normalize_entropy(ent: float, lo: float = 6.5, hi: float = 7.99) -> float:
    """
    Heuristic:
    - very low entropy suggests highly structured payload or repeated patterns
    - very high entropy can indicate encrypted / compressed payload in pixels or metadata
    We map to anomaly in [0,1] by distance from a typical natural-image range.
    """
    if lo <= ent <= hi:
        return 0.0
    if ent < lo:
        return clamp01((lo - ent) / lo)
    return clamp01((ent - hi) / (8.0 - hi))

def linear_penalty(violations: int, scale: int = 5) -> float:
    return clamp01(violations / float(scale))


# ---------------------------
# Data structures
# ---------------------------

@dataclass
class ScanConfig:
    # Structural
    max_file_size: int = 500 * 1024 * 1024  # 500 MB
    max_static_read: int = 8 * 1024 * 1024  # 8 MB for heuristics
    # Metadata
    max_metadata_block: int = 512 * 1024    # 512 KB
    # Decompression
    mem_threshold_bytes: int = 2 * 1024 * 1024 * 1024  # 2 GB
    max_dimensions: int = 200_000  # conservative; protects against bombs
    # Sandbox
    enable_sandbox: bool = False
    sandbox_runner: Optional[Callable[[Path], Dict[str, Any]]] = None
    # Weights
    w_struct: float = 0.30
    w_meta: float = 0.15
    w_steg: float = 0.20
    w_decomp: float = 0.20
    w_sandbox: float = 0.15

    def normalize_weights(self) -> None:
        s = self.w_struct + self.w_meta + self.w_steg + self.w_decomp + self.w_sandbox
        if s <= 0:
            raise ValueError("Sum of weights must be > 0")
        self.w_struct /= s
        self.w_meta /= s
        self.w_steg /= s
        self.w_decomp /= s
        self.w_sandbox /= s


@dataclass
class ModuleScores:
    S_struct: float = 0.0
    S_meta: float = 0.0
    S_steg: float = 0.0
    S_decomp: float = 0.0
    S_sandbox: float = 0.0

    def total(self, cfg: ScanConfig) -> float:
        cfg.normalize_weights()
        r = (cfg.w_struct * self.S_struct +
             cfg.w_meta * self.S_meta +
             cfg.w_steg * self.S_steg +
             cfg.w_decomp * self.S_decomp +
             cfg.w_sandbox * self.S_sandbox)
        return clamp01(r)


@dataclass
class ScanReport:
    file_path: str
    file_size: int
    sha256: str
    file_type: str
    scores: ModuleScores
    R_total: float
    risk_class: str
    findings: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "file_type": self.file_type,
            "scores": {
                "S_struct": self.scores.S_struct,
                "S_meta": self.scores.S_meta,
                "S_steg": self.scores.S_steg,
                "S_decomp": self.scores.S_decomp,
                "S_sandbox": self.scores.S_sandbox,
            },
            "R_total": self.R_total,
            "risk_class": self.risk_class,
            "findings": self.findings,
        }


# ---------------------------
# Core scanner
# ---------------------------

class PSSecureScan:
    """
    Main entry point.
    """

    def __init__(self, cfg: Optional[ScanConfig] = None):
        self.cfg = cfg or ScanConfig()
        self.cfg.normalize_weights()

    def scan(self, path: str | Path) -> ScanReport:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(str(p))
        size = p.stat().st_size
        if size > self.cfg.max_file_size:
            raise ValueError(f"File exceeds max_file_size: {size} > {self.cfg.max_file_size}")

        ftype = detect_file_type(p)
        sha = sha256_file(p)

        scores = ModuleScores()
        findings: Dict[str, Any] = {"type_detection": ftype}

        # Structural
        if ftype == "psd":
            s, fd = validate_psd_structure(p)
        else:
            s, fd = validate_raster_structure(p, ftype)
        scores.S_struct = s
        findings["struct"] = fd

        # Metadata (light)
        sm, md = analyze_metadata_light(p, ftype, max_block=self.cfg.max_metadata_block)
        scores.S_meta = sm
        findings["meta"] = md

        # Entropy / stego (heuristic over prefix bytes)
        buf = safe_read(p, min(self.cfg.max_static_read, size))
        ent = entropy_bytes(buf)
        scores.S_steg = clamp01(normalize_entropy(ent))
        findings["steg"] = {"entropy_prefix_bits_per_byte": ent, "normalized": scores.S_steg}

        # Decompression risk (estimate)
        sd, dd = estimate_decompression_risk(p, ftype, mem_thresh=self.cfg.mem_threshold_bytes,
                                             max_dims=self.cfg.max_dimensions)
        scores.S_decomp = sd
        findings["decomp"] = dd

        # Sandbox (optional hook)
        if self.cfg.enable_sandbox and self.cfg.sandbox_runner:
            try:
                out = self.cfg.sandbox_runner(p)
                scores.S_sandbox = clamp01(float(out.get("S_sandbox", 0.0)))
                findings["sandbox"] = out
            except Exception as e:
                # sandbox failure itself is a signal, but keep bounded
                scores.S_sandbox = 0.25
                findings["sandbox"] = {"error": str(e), "note": "sandbox_runner failed"}
        else:
            scores.S_sandbox = 0.0
            findings["sandbox"] = {"enabled": False}

        R = scores.total(self.cfg)
        risk = classify_risk(R)

        return ScanReport(
            file_path=str(p),
            file_size=size,
            sha256=sha,
            file_type=ftype,
            scores=scores,
            R_total=R,
            risk_class=risk,
            findings=findings,
        )


# ---------------------------
# File type detection
# ---------------------------

def detect_file_type(p: Path) -> str:
    """
    Returns: psd, jpeg, png, tiff, bmp, gif, webp, unknown
    """
    with p.open("rb") as f:
        sig = f.read(16)

    if sig.startswith(b"8BPS"):
        return "psd"
    if sig[:2] == b"\xFF\xD8":
        return "jpeg"
    if sig.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if sig.startswith(b"II*\x00") or sig.startswith(b"MM\x00*"):
        return "tiff"
    if sig.startswith(b"BM"):
        return "bmp"
    if sig.startswith(b"GIF87a") or sig.startswith(b"GIF89a"):
        return "gif"
    if sig.startswith(b"RIFF") and sig[8:12] == b"WEBP":
        return "webp"
    return "unknown"


# ---------------------------
# 3.2 Structural validation
# ---------------------------

def validate_psd_structure(p: Path) -> Tuple[float, Dict[str, Any]]:
    """
    Partial PSD structural validation:
    - header fields
    - section lengths: color mode, image resources, layer/mask
    - bounds checking: offset + length <= file_size

    PSD header:
    0-3   signature '8BPS'
    4-5   version (1)
    6-11  reserved
    12-13 channels (1-56)
    14-17 height
    18-21 width
    22-23 depth (1,8,16,32)
    24-25 color mode
    """
    size = p.stat().st_size
    violations = 0
    info: Dict[str, Any] = {"violations": [], "header": {}}

    with p.open("rb") as f:
        header = f.read(26)
        if len(header) < 26:
            violations += 2
            info["violations"].append("truncated_header")
            return clamp01(0.4 + linear_penalty(violations)), info

        sig = header[0:4]
        ver = struct.unpack(">H", header[4:6])[0]
        reserved = header[6:12]
        channels = struct.unpack(">H", header[12:14])[0]
        height = struct.unpack(">I", header[14:18])[0]
        width = struct.unpack(">I", header[18:22])[0]
        depth = struct.unpack(">H", header[22:24])[0]
        colormode = struct.unpack(">H", header[24:26])[0]

        info["header"] = {
            "sig": sig.decode("latin1", errors="replace"),
            "version": ver,
            "channels": channels,
            "height": height,
            "width": width,
            "depth": depth,
            "color_mode": colormode,
        }

        if sig != b"8BPS":
            violations += 3
            info["violations"].append("bad_signature")
        if ver not in (1, 2):  # v2 for large docs
            violations += 1
            info["violations"].append("unexpected_version")
        if reserved != b"\x00" * 6:
            violations += 1
            info["violations"].append("reserved_not_zero")
        if not (1 <= channels <= 56):
            violations += 1
            info["violations"].append("channels_out_of_range")
        if height == 0 or width == 0:
            violations += 2
            info["violations"].append("zero_dimension")
        if depth not in (1, 8, 16, 32):
            violations += 1
            info["violations"].append("unexpected_depth")

        # Read section lengths with bounds checks
        try:
            # Color mode data length (4 bytes)
            cm_len_b = f.read(4)
            if len(cm_len_b) != 4:
                raise EOFError("truncated_color_mode_length")
            cm_len = struct.unpack(">I", cm_len_b)[0]
            if f.tell() + cm_len > size:
                violations += 2
                info["violations"].append("color_mode_length_oob")
                cm_len = max(0, size - f.tell())
            f.seek(cm_len, os.SEEK_CUR)

            # Image resources length (4 bytes)
            ir_len_b = f.read(4)
            if len(ir_len_b) != 4:
                raise EOFError("truncated_image_resources_length")
            ir_len = struct.unpack(">I", ir_len_b)[0]
            if ir_len > 50 * 1024 * 1024:
                violations += 1
                info["violations"].append("image_resources_suspiciously_large")
            if f.tell() + ir_len > size:
                violations += 2
                info["violations"].append("image_resources_length_oob")
                ir_len = max(0, size - f.tell())
            f.seek(ir_len, os.SEEK_CUR)

            # Layer and mask info length (4 bytes)
            lm_len_b = f.read(4)
            if len(lm_len_b) != 4:
                raise EOFError("truncated_layer_mask_length")
            lm_len = struct.unpack(">I", lm_len_b)[0]
            if lm_len > 200 * 1024 * 1024:
                violations += 1
                info["violations"].append("layer_mask_suspiciously_large")
            if f.tell() + lm_len > size:
                violations += 2
                info["violations"].append("layer_mask_length_oob")
            # do not fully parse layers here

            info["sections"] = {
                "color_mode_data_len": cm_len,
                "image_resources_len": ir_len,
                "layer_mask_len": lm_len,
            }

        except Exception as e:
            violations += 2
            info["violations"].append(f"section_parse_error:{e}")

    # Score
    S_struct = clamp01(0.1 * violations + (0.15 if "bad_signature" in info["violations"] else 0.0))
    info["S_struct"] = S_struct
    return S_struct, info


def validate_raster_structure(p: Path, ftype: str) -> Tuple[float, Dict[str, Any]]:
    """
    Minimal raster structural checks:
    - marker integrity for jpeg/png/gif/webp
    - size sanity
    For TIFF/unknown we keep conservative.
    """
    size = p.stat().st_size
    violations = 0
    info: Dict[str, Any] = {"ftype": ftype, "violations": []}

    with p.open("rb") as f:
        head = f.read(64)

    if ftype == "jpeg":
        # SOI present, EOI likely at end
        if not head.startswith(b"\xFF\xD8"):
            violations += 2
            info["violations"].append("jpeg_missing_soi")
        with p.open("rb") as f:
            f.seek(max(0, size - 2))
            tail = f.read(2)
        if tail != b"\xFF\xD9":
            violations += 1
            info["violations"].append("jpeg_missing_eoi")
    elif ftype == "png":
        if not head.startswith(b"\x89PNG\r\n\x1a\n"):
            violations += 2
            info["violations"].append("png_bad_signature")
        # IHDR should appear early
        if b"IHDR" not in head:
            violations += 1
            info["violations"].append("png_missing_ihdr_near_start")
    elif ftype == "gif":
        if not (head.startswith(b"GIF87a") or head.startswith(b"GIF89a")):
            violations += 2
            info["violations"].append("gif_bad_signature")
    elif ftype == "webp":
        if not (head.startswith(b"RIFF") and head[8:12] == b"WEBP"):
            violations += 2
            info["violations"].append("webp_bad_signature")
    elif ftype == "tiff":
        # Only signature check at detect stage; deeper parsing requires lib
        pass
    elif ftype == "unknown":
        violations += 1
        info["violations"].append("unknown_format")

    # suspiciously small or huge
    if size < 64:
        violations += 1
        info["violations"].append("file_too_small")
    if size > 300 * 1024 * 1024 and ftype in ("jpeg", "png", "gif", "webp", "bmp"):
        violations += 1
        info["violations"].append("file_unusually_large_for_raster")

    S_struct = clamp01(violations / 6.0)
    info["S_struct"] = S_struct
    return S_struct, info


# ---------------------------
# 3.3 Metadata analysis (light)
# ---------------------------

def analyze_metadata_light(p: Path, ftype: str, max_block: int) -> Tuple[float, Dict[str, Any]]:
    """
    Conservative, dependency-free checks:
    - scans the first N bytes for common metadata markers
    - estimates size of APP1 (EXIF) in JPEG
    - checks for oversized XMP packets in the prefix window
    """
    buf = safe_read(p, min(2 * max_block, p.stat().st_size))
    findings: Dict[str, Any] = {"signals": []}
    violations = 0

    if ftype == "jpeg":
        # naive scan for APP1 marker (0xFFE1) and declared length
        i = 0
        while i + 4 <= len(buf) and i < 64 * 1024:
            if buf[i] == 0xFF and buf[i+1] == 0xE1:
                seg_len = struct.unpack(">H", buf[i+2:i+4])[0]
                findings["signals"].append({"jpeg_app1_len": seg_len, "offset": i})
                if seg_len > max_block:
                    violations += 2
                    findings["signals"].append("oversized_exif_app1")
                break
            i += 1

    # XMP packet markers
    xmp_idx = buf.find(b"<x:xmpmeta")
    if xmp_idx != -1:
        end = buf.find(b"</x:xmpmeta>")
        if end != -1:
            xmp_size = (end + len(b"</x:xmpmeta>")) - xmp_idx
            findings["signals"].append({"xmp_size": xmp_size, "offset": xmp_idx})
            if xmp_size > max_block:
                violations += 2
                findings["signals"].append("oversized_xmp")
        else:
            violations += 1
            findings["signals"].append("truncated_xmp")

    # generic high-entropy metadata hint: if ASCII ratio very low in prefix but 'xml' present
    if b"xml" in buf and sum(32 <= b <= 126 for b in buf) / max(1, len(buf)) < 0.10:
        violations += 1
        findings["signals"].append("xml_present_but_low_ascii_ratio")

    S_meta = clamp01(violations / 5.0)
    findings["S_meta"] = S_meta
    return S_meta, findings


# ---------------------------
# 3.5 Decompression risk estimation
# ---------------------------

def estimate_decompression_risk(p: Path, ftype: str, mem_thresh: int, max_dims: int) -> Tuple[float, Dict[str, Any]]:
    """
    Estimates memory footprint using header-level dimension parsing for PNG/JPEG/GIF/BMP/WEBP (partial).
    For PSD uses header fields.
    If dimensions cannot be parsed, returns a conservative low score.
    """
    info: Dict[str, Any] = {"ftype": ftype}
    W = H = C = B = None
    violations = 0

    try:
        if ftype == "psd":
            with p.open("rb") as f:
                f.read(12)  # skip sig/ver/res
                channels = struct.unpack(">H", f.read(2))[0]
                height = struct.unpack(">I", f.read(4))[0]
                width = struct.unpack(">I", f.read(4))[0]
                depth = struct.unpack(">H", f.read(2))[0]
            W, H = width, height
            C = channels
            B = max(1, depth // 8)  # bytes per channel sample (heuristic)
        elif ftype == "png":
            with p.open("rb") as f:
                f.read(8)  # sig
                # length(4) + type(4) + data(13) for IHDR
                ihdr_len = struct.unpack(">I", f.read(4))[0]
                ihdr_type = f.read(4)
                if ihdr_type != b"IHDR":
                    raise ValueError("IHDR not found")
                ihdr = f.read(13)
            W = struct.unpack(">I", ihdr[0:4])[0]
            H = struct.unpack(">I", ihdr[4:8])[0]
            bit_depth = ihdr[8]
            color_type = ihdr[9]
            # approximate channels by color type
            C = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type, 3)
            B = max(1, bit_depth // 8)
        elif ftype == "gif":
            with p.open("rb") as f:
                f.read(6)
                w, h = struct.unpack("<HH", f.read(4))
            W, H = w, h
            C, B = 3, 1
        elif ftype == "bmp":
            with p.open("rb") as f:
                f.read(18)
                w, h = struct.unpack("<ii", f.read(8))
            W, H = abs(w), abs(h)
            C, B = 3, 1
        else:
            # JPEG/WEBP parsing fully is non-trivial without extra deps; skip
            pass

    except Exception as e:
        info["parse_error"] = str(e)

    if W is None or H is None:
        info["dims_known"] = False
        return 0.05, info

    info["dims_known"] = True
    info["width"] = int(W)
    info["height"] = int(H)
    info["channels_est"] = int(C)
    info["bytes_per_sample_est"] = int(B)

    if W <= 0 or H <= 0:
        violations += 2
        info["violations"] = ["non_positive_dimensions"]
        return 0.6, info

    if W > max_dims or H > max_dims or (W * H) > (max_dims * max_dims):
        violations += 2
        info.setdefault("violations", []).append("dimensions_exceed_policy")

    M_est = int(W) * int(H) * int(C) * int(B)
    info["M_est_bytes"] = M_est
    info["mem_threshold_bytes"] = mem_thresh

    if M_est > mem_thresh:
        violations += 2
        info.setdefault("violations", []).append("estimated_memory_exceeds_threshold")
    elif M_est > 0.5 * mem_thresh:
        violations += 1
        info.setdefault("violations", []).append("estimated_memory_near_threshold")

    S_decomp = clamp01(violations / 3.0)
    info["S_decomp"] = S_decomp
    return S_decomp, info


# ---------------------------
# Risk classification
# ---------------------------

def classify_risk(R_total: float, tau1: float = 0.20, tau2: float = 0.45, tau3: float = 0.70) -> str:
    if R_total < tau1:
        return "Low"
    if R_total < tau2:
        return "Moderate"
    if R_total < tau3:
        return "High"
    return "Critical"


# ---------------------------
# CLI helper (optional)
# ---------------------------

def scan_to_json(path: str, cfg: Optional[ScanConfig] = None) -> str:
    scanner = PSSecureScan(cfg=cfg)
    report = scanner.scan(path)
    import json
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
