
from ps_securescan import PSSecureScan, ScanConfig

cfg = ScanConfig()
scanner = PSSecureScan(cfg)
report = scanner.scan("YOUR_FILE_HERE.psd")
print(report.to_dict())
