# main.py
from modules.recon import gather_info
from modules.fingerprint import fingerprint
from modules.headers import analyze_headers
from modules.attack_surface import discover_attack_surface
from modules.exploit_checks import check_xss, check_sql_injection
from modules.recommendations import generate_recommendations
from modules.report_generator import generate_report
from modules.risk_engine import calculate_score

url = input("Enter target URL: ")
data = gather_info(url)
if "error" in data:
    print(data["error"])
    exit()

print(f"\nStatus Code: {data['status_code']}")
print("Fingerprinting:")
tech = fingerprint(data["headers"])
print("\n".join(tech) or "No tech identified")

print("\nHeader Analysis:")
findings = analyze_headers(data["headers"])
print("\n".join(findings) or "No missing headers")

# Attack surface
surface = discover_attack_surface(url)
if "error" not in surface:
    print(f"\nAttack Surface: Forms={surface['forms']}, Inputs={surface['inputs']}, Links={surface['links']}")

# Optional exploit checks (disabled by default, enable with flag)
# if safe_mode_enabled:
#     if check_xss(url, ...): findings.append("[HIGH] Reflective XSS detected")
#     if check_sql_injection(url, ...): findings.append("[HIGH] Potential SQL injection")

# Generate recommendations
recs = generate_recommendations(findings)
# Combine findings with recommendations for report
report_data = {
    "target": url,
    "status_code": data["status_code"],
    "server": next((h for h in tech if h.startswith("Server:")), ""),
    "findings": [
        {"id": i+1, "title": f.split("] ")[1], "risk": f.split("] ")[0].strip("[]"), 
         "recommendation": recs[i] if i < len(recs) else ""}
        for i, f in enumerate(findings)
    ],
    "attack_surface": {"forms":surface.get("forms",0), "inputs":surface.get("inputs",0), "links":surface.get("links",0)},
    "score": calculate_score(findings, {"admin_links": surface.get("links",0)})  # simple context
}

print(f"\nSecurity Score: {report_data['score']}/100")
