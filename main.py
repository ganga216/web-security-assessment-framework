from modules.recon import gather_info
from modules.fingerprint import fingerprint
from modules.headers import analyze_headers

url = input("Enter target URL: ")

data = gather_info(url)

if "error" in data:

    print(f"\nError: {data['error']}")

else:

    print("\n===== TARGET INFORMATION =====")

    print(f"Status Code: {data['status_code']}")

    print("\n===== TECHNOLOGY FINGERPRINTING =====")

    results = fingerprint(data["headers"])

    for item in results:
        print(item)

    print("\n===== SECURITY HEADER ANALYSIS =====")

    findings = analyze_headers(data["headers"])

    if findings:

        for finding in findings:
            print(finding)

    else:

        print("No missing security headers detected.")