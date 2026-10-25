# Aegis-IDF: Quick Execution & Operator Guide

See the full documentation in [`docs/HOW_TO_RUN.md`](docs/HOW_TO_RUN.md).

### Quick Summary

#### 1. Run Automated Tests:
```bash
python3 -m unittest discover -s insider_forensics/test_suite -p "test_*.py"
```

#### 2. Run Built-In Multi-Artifact Simulation:
```bash
python3 insider_forensics/cli.py simulate --workspace ./simulated_case
```

#### 3. Analyze Any Acquired Triage Folder:
```bash
python3 insider_forensics/cli.py analyze --source /path/to/triage_artifacts --output ./reports
```

#### 4. Outputs Generated:
- `FORENSIC_REPORT.md`: Comprehensive formal investigation dossier with chain-of-custody table.
- `forensic_findings.json`: Machine-readable structured findings for SIEM / SOAR automation.
- `super_timeline.csv`: Plaso and Eric Zimmerman's Timeline Explorer compatible CSV.

For detailed detection rules, mathematical weights, and alternative hypotheses, see:
[`docs/EXPLAINABLE_DETECTION_RULES.md`](docs/EXPLAINABLE_DETECTION_RULES.md)
