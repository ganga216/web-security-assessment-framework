from modules.recon import gather_info
from modules.fingerprint import fingerprint

url = input("Enter target URL: ")

data = gather_info(url)

if "error" in data:

    print(data["error"])

else:

    print(f"\nStatus Code: {data['status_code']}")

    results = fingerprint(data["headers"])

    for item in results:

        print(item)