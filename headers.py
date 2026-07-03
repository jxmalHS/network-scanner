import requests 

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy"
]

def check_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        missing = []
        for header in SECURITY_HEADERS:
            if header not in headers:
                missing.append(header)
        return {"present": [h for h in SECURITY_HEADERS if h not in missing], "missing": missing}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
    