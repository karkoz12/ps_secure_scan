
# PS-SecureScan (Prototype)

This repository provides a small Python module implementing the **PS-SecureScan** framework described in the paper section "3. Method".
The implementation is a **prototype**: it aims for explainability and safe bounded parsing, not full decoding of every format.

## What it does

For a file `F` it computes module scores in `[0,1]`:

- `S_struct` structural validation (PSD partial, raster minimal)
- `S_meta` metadata anomaly (lightweight EXIF/XMP heuristics)
- `S_steg` entropy-based steganography suspicion (prefix entropy)
- `S_decomp` decompression risk estimation (memory footprint)
- `S_sandbox` optional sandbox hook (user-provided runner)

Total score:

`R_total = w1*S_struct + w2*S_meta + w3*S_steg + w4*S_decomp + w5*S_sandbox`

## Quick usage

```bash
python -c "from ps_securescan import scan_to_json; print(scan_to_json('sample.psd'))"
```

## Publication mapping

- Section 3.2 -> `validate_psd_structure`, `validate_raster_structure`
- Section 3.3 -> `analyze_metadata_light`
- Section 3.4 -> entropy heuristic `entropy_bytes` + `normalize_entropy`
- Section 3.5 -> `estimate_decompression_risk`
- Section 3.6 -> sandbox via `ScanConfig.enable_sandbox` and `sandbox_runner`
- Section 3.7 -> `ModuleScores.total` + `classify_risk`

## Notes

- PSD layer parsing is deliberately limited to reduce risk and complexity.
- For JPEG and WEBP dimension parsing you may integrate Pillow or format-specific parsers if allowed.
