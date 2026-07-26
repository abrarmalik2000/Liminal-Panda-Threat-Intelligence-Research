# LIMINAL PANDA Threat Intelligence Research
**Author:** Abrar Malik — Utah State University   

## Overview
Analysis of LIMINAL PANDA, a China-nexus Advanced 
Persistent Threat actor targeting global 
telecommunications infrastructure across Asia,
Africa, and the Middle East.

## Key Contributions
- First dual mapping of LIMINAL PANDA TTPs to both
  MITRE ATT&CK Enterprise and FiGHT (5G Hierarchy
  of Threats) frameworks simultaneously
- Original YARA and Sigma detection rules
- Consolidated IoC corpus from two independent
  vendor sources (CrowdStrike + Palo Alto Unit 42)
- Structured risk assessment for telecom operators

## Repository Contents
- `/rules/liminal_panda.yar` — YARA detection rules
- `/rules/liminal_panda_sigma.yml` — Sigma rules
- `README.md` — research overview

## Threat Actor Profile
- **Attribution:** China-nexus (high confidence)
- **Targets:** Mobile Network Operators (MNOs)
- **Regions:** Asia, Africa, Middle East
- **Objectives:** Subscriber data exfiltration,
  signalling intelligence collection
- **Active Since:** At least 2019

## Frameworks Used
- MITRE ATT&CK Enterprise
- MITRE FiGHT (5G Hierarchy of Threats)
- Diamond Model of Intrusion Analysis
- Cyber Kill Chain

## Detection Rules
YARA and Sigma rules provided in `/rules` directory.
Rules target LIMINAL PANDA toolset including:
- SIGTRANslator
- CordScan
- TinyShell variants
- Fast Reverse Proxy
- Microsocks proxy

## References
- CrowdStrike Counter Adversary Operations (2024)
- Palo Alto Unit 42 CL-STA-0969 Report (2024)
- US Senate Intelligence Committee Testimony (2024)

## Note
This research was conducted using publicly available
threat intelligence reporting. All IoCs and detection
rules are derived from open-source intelligence.

## Connect
[LinkedIn](https://www.linkedin.com/in/abrarmalik/) | [GitHub Profile](https://github.com/abrarmalik2000)
