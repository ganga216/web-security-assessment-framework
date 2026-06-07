from bs4 import BeautifulSoup
import requests

def discover_attack_surface(url):

    try:

        response = requests.get(url, timeout=10)

        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")
        inputs = soup.find_all("input")
        links = soup.find_all("a")

        return {
            "forms": len(forms),
            "inputs": len(inputs),
            "links": len(links)
        }

    except Exception as e:

        return {
            "error": str(e)
        }