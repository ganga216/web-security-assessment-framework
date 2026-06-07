# 🛡️ Enterprise Web Security Assessment Platform

An enterprise-style Web Security Assessment Platform built using Python and Streamlit that performs reconnaissance, technology fingerprinting, attack surface discovery, risk analysis, OWASP Top 10 mapping, MITRE ATT&CK mapping, and automated security reporting.

Designed to simulate the workflow of a Security Engineer performing web application security assessments.

---

## Features

### Reconnaissance

* Target URL validation
* HTTP response analysis
* Status code collection
* Web server information gathering

### Technology Fingerprinting

* Web server identification
* Technology stack detection
* HTTP header analysis

### Security Header Assessment

* Content-Security-Policy analysis
* HSTS validation
* X-Frame-Options verification
* X-Content-Type-Options validation
* Referrer Policy assessment

### Attack Surface Discovery

* Form enumeration
* Input field discovery
* Link analysis
* Surface exposure assessment

### Risk Assessment Engine

* Automated risk scoring
* Severity classification
* Risk level determination
* Security posture evaluation

### OWASP Top 10 Mapping

Maps findings against:

* A01 Broken Access Control
* A03 Injection
* A05 Security Misconfiguration
* A07 Identification & Authentication Failures
* A09 Security Logging & Monitoring Failures

### MITRE ATT&CK Mapping

Maps identified weaknesses to relevant MITRE ATT&CK techniques for improved threat context.

### Interactive SOC Dashboard

* Security Score Gauge
* Severity Distribution Charts
* OWASP Radar Visualization
* Attack Surface Analytics
* Scan History Tracking

### Reporting

* JSON Report Export
* HTML Report Export
* Executive Summary Generation
* Recommendation Engine

---

## Technology Stack

* Python
* Streamlit
* Pandas
* Plotly
* Requests
* BeautifulSoup

---

## Project Structure

web-security-assessment-framework/

├── app.py
├── modules/
│ ├── recon.py
│ ├── fingerprint.py
│ ├── headers.py
│ ├── attack_surface.py
│ ├── risk_engine.py
│ ├── owasp_mapper.py
│ ├── mitre_mapper.py
│ ├── recommendations.py
│ └── summary.py
├── reports/
├── requirements.txt
└── README.md

---

## Installation

```bash
git clone https://github.com/ganga216/web-security-assessment-framework.git

cd web-security-assessment-framework

pip install -r requirements.txt
```

Run the platform:

```bash
streamlit run app.py
```

---

## Assessment Workflow

Target URL

↓

Reconnaissance

↓

Technology Fingerprinting

↓

Security Header Analysis

↓

Attack Surface Discovery

↓

Risk Scoring

↓

OWASP Mapping

↓

MITRE ATT&CK Mapping

↓

Recommendations

↓

Executive Summary

↓

Report Generation

---

## Sample Capabilities

* Detect missing security headers
* Evaluate web application security posture
* Identify exposed attack surfaces
* Generate remediation recommendations
* Produce executive-level security reports
* Track historical assessments

---

## Future Enhancements

* Authentication and RBAC
* Vulnerability Database Integration
* CVE Correlation
* AI-powered Risk Prioritization
* PDF Report Generation
* Multi-target Assessments
* Scan Scheduling
* Asset Inventory Management
* Security Trend Analysis

---

## Author

Gangadhar

Aspiring SOC Analyst & Security Engineer

Focused on:

* Security Operations (SOC)
* Detection Engineering
* Web Application Security
* Threat Detection
* Security Automation
