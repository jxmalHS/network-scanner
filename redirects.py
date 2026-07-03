import requests

REDIRECT_PARAMS = ["next", "url", "redirect", "return", "goto", "dest", "destination", "redir"]
TEST_URL = "http://evil.com"

def check_open_redirect(host):
    vulnerable = []
    for param in REDIRECT_PARAMS:
        test = f"http://{host}?{param}={TEST_URL}"
        try:
            response = requests.get(test, timeout=5, allow_redirects=True)
            if response.history and TEST_URL in response.url:
                vulnerable.append(test)
        except requests.exceptions.RequestException:
            pass
    return vulnerable