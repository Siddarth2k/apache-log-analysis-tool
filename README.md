# 🔐 Apache Log Analysis & Threat Detection Tool

A Python-based security log analysis engine that detects suspicious activity from Apache access logs, including brute-force attempts, reconnaissance scanning, and SQL injection patterns.

---

## Project Overview

This project simulates a basic SOC (Security Operations Center) detection pipeline:

1. Log ingestion & parsing  
2. Threat detection using heuristic & regex-based logic  
3. Alert generation  
4. Structured reporting (CSV + JSON)  
5. Visualization of top source IPs  

---

## Features

- Apache log parsing using regex
- Brute-force detection (401/403 spike)
- Reconnaissance detection (404 spike)
- SQL injection pattern detection
- Configurable detection thresholds via CLI
- CSV alert report generation
- JSON summary output
- Top IP visualization (matplotlib)

---

## Installation

Clone the repository:

```bash
git clone <your-repo-url>
cd log-analysis-tool
