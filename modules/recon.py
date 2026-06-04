import requests

def gather_info(url):

    try:

        response = requests.get(url, timeout=10)

        return {
            "status_code": response.status_code,
            "headers": response.headers
        }

    except Exception as e:

        return {"error": str(e)}