PS-SecureScan – Software Description and Usage Guidelines
A. Methods – Software Description
PS-SecureScan was implemented as a deterministic Python module operating in a pre-execution scan mode without full decoding of image files. 
The input is a file F (PSD or raster format), and the output is a structured report containing five risk components S_i ∈ [0,1] and a total risk score R_total. 
The implementation uses bounded parsing and strict boundary checks of binary structures in order to reduce the risk of scanner-side parsing vulnerabilities.
The analytical modules correspond to the methodological components described in the framework: 
(i) structural validation of the file format (PSD: header fields, section lengths, offset consistency; raster formats: signatures and marker integrity), 
(ii) metadata heuristics detecting oversized EXIF/XMP blocks and encoding anomalies, 
(iii) entropy-based estimation of steganographic likelihood using prefix data entropy, 
(iv) decompression risk estimation by computing an approximate memory footprint M_est = W · H · C · B, and 
(v) an optional sandbox component implemented as a user-defined execution hook returning S_sandbox.
The final score is computed as a weighted linear combination of module outputs:
R_total = Σ (w_k · S_k), where Σ w_k = 1
The resulting score is mapped to four risk classes (Low, Moderate, High, Critical) using threshold parameters τ1, τ2, τ3.
B. Practical Guideline for Using the Code
1. Installation and execution
The implementation does not require external dependencies beyond the Python standard library. 
After extracting the archive, ensure that the file ps_securescan.py is located in the working directory or available in the PYTHONPATH.
Example execution returning a JSON report:
python -c "from ps_securescan import scan_to_json; print(scan_to_json('file.psd'))"
In production environments the recommended integration approach is calling:
scanner = PSSecureScan()
report = scanner.scan(path)
and storing report.to_dict() in a logging system or digital asset management pipeline.
2. Decision policy (risk gating)
Recommended mapping between risk classes and operational actions:
Low – automatic acceptance  
Moderate – acceptance with logging and monitoring  
High – quarantine and manual inspection  
Critical – automatic rejection and file isolation
3. Calibration of weights and thresholds
Weights w_k and thresholds τ should be calibrated using organization-specific datasets containing both benign and crafted test files. 
Configuration parameters are exposed through the ScanConfig object in the implementation.
4. Sandbox integration
The sandbox module is optional and implemented as a controlled callback mechanism. 
To enable sandbox evaluation:
- set ScanConfig.enable_sandbox = True
- provide a sandbox_runner(path) function returning a dictionary containing S_sandbox.
The sandbox environment should operate in an isolated VM or container with restricted network access and defined CPU and memory limits.
5. Prototype limitations
The implementation intentionally performs partial format parsing rather than full decoding in order to minimize complexity and reduce attack surface. 
PSD validation focuses on header and structural consistency checks, while JPEG/WEBP dimension extraction is intentionally conservative. 
For extended production deployments additional parsers may be integrated, provided strict resource limits and validation checks remain enforced.
