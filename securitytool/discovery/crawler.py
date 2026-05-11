import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def crawl_unauthenticated(target: str, max_urls: int = 100) -> list:
    visited = set()
    to_visit = [target]
    endpoints = []
    base_domain = urlparse(target).netloc

    while to_visit and len(endpoints) < max_urls:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            response = requests.get(url, timeout=10, verify=False)
            endpoints.append({
                "url": url,
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "auth_required": response.status_code == 401 or response.status_code == 403,
                "forms": [],
                "parameters": []
            })

            soup = BeautifulSoup(response.text, "html.parser")

            # Extract forms and parameters
            for form in soup.find_all("form"):
                form_data = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").upper(),
                    "inputs": []
                }
                for input_tag in form.find_all(["input", "textarea", "select"]):
                    if input_tag.get("name"):
                        form_data["inputs"].append({
                            "name": input_tag.get("name"),
                            "type": input_tag.get("type", "text")
                        })
                endpoints[-1]["forms"].append(form_data)

            # Extract query parameters from URL
            parsed = urlparse(url)
            if parsed.query:
                params = [p.split("=")[0] for p in parsed.query.split("&")]
                endpoints[-1]["parameters"] = params

            # Find new links
            for tag in soup.find_all("a", href=True):
                href = urljoin(url, tag["href"])
                parsed_href = urlparse(href)
                if parsed_href.netloc == base_domain and href not in visited:
                    to_visit.append(href)

        except requests.exceptions.RequestException as e:
            logger.warning("Crawl error", extra={"url": url, "error": str(e)})

    logger.info("Crawl complete", extra={
        "endpoints": len(endpoints),
        "visited": len(visited)
    })
    return endpoints


def crawl_authenticated(target: str, auth_config: dict, max_urls: int = 100) -> list:
    session = requests.Session()
    session.verify = False

    try:
        login_url = auth_config.get("login_url", f"{target}/login")
        username = auth_config.get("username", "")
        password = auth_config.get("password", "")
        username_field = auth_config.get("username_field", "username")
        password_field = auth_config.get("password_field", "password")

        login_response = session.post(login_url, data={
            username_field: username,
            password_field: password
        }, timeout=10)

        if login_response.status_code in [200, 302]:
            logger.info("Authentication successful", extra={"login_url": login_url})
        else:
            logger.warning("Authentication may have failed", extra={
                "status": login_response.status_code
            })

    except Exception as e:
        logger.error("Login failed", extra={"error": str(e)})
        return []

    visited = set()
    to_visit = [target]
    endpoints = []
    base_domain = urlparse(target).netloc

    while to_visit and len(endpoints) < max_urls:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            response = session.get(url, timeout=10)
            endpoints.append({
                "url": url,
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "auth_required": False,
                "authenticated": True,
                "forms": [],
                "parameters": []
            })

            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup.find_all("a", href=True):
                href = urljoin(url, tag["href"])
                parsed_href = urlparse(href)
                if parsed_href.netloc == base_domain and href not in visited:
                    to_visit.append(href)

        except requests.exceptions.RequestException as e:
            logger.warning("Crawl error", extra={"url": url, "error": str(e)})

    logger.info("Authenticated crawl complete", extra={"endpoints": len(endpoints)})
    return endpoints