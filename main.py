from modules.recon import gather_info
from modules.fingerprint import fingerprint
from modules.headers import analyze_headers
from modules.attack_surface import discover_attack_surface
from modules.risk_engine import calculate_score

url = input("Enter target URL: ")

data = gather_info(url)

if "error" in data:

    print(data["error"])

else:

    print("\n===== TARGET INFORMATION =====")

    print(f"Status Code: {data['status_code']}")

    print("\n===== TECHNOLOGY FINGERPRINTING =====")

    tech = fingerprint(data["headers"])

    for item in tech:
        print(item)

    print("\n===== SECURITY HEADER ANALYSIS =====")

    findings = analyze_headers(data["headers"])

    if findings:

        for finding in findings:
            print(finding)

    else:

        print("No missing security headers detected.")

    print("\n===== ATTACK SURFACE DISCOVERY =====")

    surface = discover_attack_surface(url)

    if "error" not in surface:

        print(f"Forms Found : {surface['forms']}")
        print(f"Inputs Found: {surface['inputs']}")
        print(f"Links Found : {surface['links']}")

    print("\n===== SECURITY SCORE =====")

    score = calculate_score(findings)

    print(f"Security Score: {score}/100")