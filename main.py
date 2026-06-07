import json

from modules.recon import gather_info
from modules.fingerprint import fingerprint
from modules.headers import analyze_headers
from modules.attack_surface import discover_attack_surface
from modules.risk_engine import calculate_score

from modules.owasp_mapper import map_owasp
from modules.mitre_mapper import map_mitre
from modules.recommendations import generate_recommendations
from modules.summary import generate_summary

# Target Input
url = input("Enter target URL: ")

# Recon
data = gather_info(url)

if "error" in data:
    print(data["error"])
    exit()

# Target Information
print("\n===== TARGET INFORMATION =====")
print(f"Status Code: {data['status_code']}")

# Fingerprinting
print("\n===== TECHNOLOGY FINGERPRINTING =====")

tech = fingerprint(data["headers"])

if tech:
    for item in tech:
        print(item)
else:
    print("No technologies identified")

# Header Analysis
print("\n===== SECURITY HEADER ANALYSIS =====")

findings = analyze_headers(data["headers"])

if findings:
    for finding in findings:
        print(finding)
else:
    print("No missing security headers detected")

# Attack Surface Discovery
print("\n===== ATTACK SURFACE DISCOVERY =====")

surface = discover_attack_surface(url)

if "error" not in surface:

    print(f"Forms Found : {surface['forms']}")
    print(f"Inputs Found: {surface['inputs']}")
    print(f"Links Found : {surface['links']}")

else:
    print(surface["error"])

# Risk Score
score = calculate_score(
    findings,
    {
        "links": surface.get("links", 0)
    }
)

print("\n===== SECURITY SCORE =====")
print(f"Security Score: {score}/100")

# OWASP Mapping
owasp = map_owasp(findings)

print("\n===== OWASP TOP 10 MAPPING =====")

if owasp:
    for item in owasp:
        print(item)
else:
    print("No OWASP mappings found")

# MITRE Mapping
mitre = map_mitre(findings)

print("\n===== MITRE ATT&CK MAPPING =====")

if mitre:
    for item in mitre:
        print(item)
else:
    print("No MITRE mappings found")

# Recommendations
recommendations = generate_recommendations(findings)

print("\n===== RECOMMENDATIONS =====")

if recommendations:
    for rec in recommendations:
        print(f"- {rec}")
else:
    print("No recommendations available")

# Executive Summary
summary = generate_summary(score)

print("\n===== EXECUTIVE SUMMARY =====")
print(summary)

# Report Data
report_data = {
    "target": url,
    "status_code": data["status_code"],
    "technologies": tech,
    "findings": findings,
    "attack_surface": {
        "forms": surface.get("forms", 0),
        "inputs": surface.get("inputs", 0),
        "links": surface.get("links", 0)
    },
    "security_score": score,
    "owasp_mapping": owasp,
    "mitre_mapping": mitre,
    "recommendations": recommendations,
    "executive_summary": summary
}

# Save JSON Report
with open("reports/report.json", "w") as report_file:
    json.dump(report_data, report_file, indent=4)

print("\nReport saved successfully:")
print("reports/report.json")