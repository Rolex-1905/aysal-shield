import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import urllib3
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


def _extract_endpoint_data(url: str, response, authenticated: bool = False) -> dict:
    """Parse a response and return structured endpoint data."""
    soup = BeautifulSoup(response.text, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        form_data = {
            "action": urljoin(url, form.get("action", "")),
            "method": form.get("method", "get").upper(),
            "inputs": [],
        }
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                form_data["inputs"].append({
                    "name": name,
                    "type": tag.get("type", "text"),
                })
        forms.append(form_data)

    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())

    return {
        "url": url,
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type", ""),
        "auth_required": response.status_code in (401, 403),
        "authenticated": authenticated,
        "forms": forms,
        "parameters": params,
    }


def _collect_links(base_url: str, response, base_domain: str) -> list:
    """Extract same-domain hrefs from a response."""
    soup = BeautifulSoup(response.text, "html.parser")
    links = []
    for tag in soup.find_all("a", href=True):
        href = urljoin(base_url, tag["href"])
        parsed = urlparse(href)
        # Strip fragments; stay on same domain
        clean = href.split("#")[0]
        if parsed.netloc == base_domain and clean not in links:
            links.append(clean)
    return links


def _verify_login(session: requests.Session, target: str, logged_in_indicator: str) -> bool:
    """Quick check: fetch target and look for a logged-in indicator."""
    try:
        resp = session.get(target, timeout=10, verify=False)
        return logged_in_indicator.lower() in resp.text.lower()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Unauthenticated crawl
# ---------------------------------------------------------------------------

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
            endpoints.append(_extract_endpoint_data(url, response, authenticated=False))
            for link in _collect_links(url, response, base_domain):
                if link not in visited:
                    to_visit.append(link)
        except requests.exceptions.RequestException as e:
            logger.warning("Crawl error", extra={"url": url, "error": str(e)})

    logger.info("Unauthenticated crawl complete", extra={
        "endpoints": len(endpoints), "visited": len(visited)
    })
    return endpoints


# ---------------------------------------------------------------------------
# Authenticated crawl — form-based, HTTP Basic, and token (Bearer)
# ---------------------------------------------------------------------------

def crawl_authenticated(target: str, auth_config: dict, max_urls: int = 100) -> list:
    session = requests.Session()
    session.verify = False

    auth_type = auth_config.get("type", "form").lower()

    if auth_type == "form":
        _login_form(session, target, auth_config)

    elif auth_type == "basic":
        username = auth_config.get("username", "")
        password = auth_config.get("password", "")
        session.auth = (username, password)
        logger.info("HTTP Basic auth configured", extra={"username": username})

    elif auth_type == "token":
        token = auth_config.get("token", "")
        token_type = auth_config.get("token_type", "Bearer")
        session.headers.update({"Authorization": f"{token_type} {token}"})
        logger.info("Token auth configured", extra={"token_type": token_type})

    else:
        logger.warning("Unknown auth type, proceeding unauthenticated", extra={"type": auth_type})

    # Verify session was actually established (for form auth)
    if auth_type == "form":
        indicator = auth_config.get("logged_in_indicator", "logout")
        if not _verify_login(session, target, indicator):
            logger.warning("Login verification failed — session may not be authenticated")

    # Crawl with established session
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
            endpoints.append(_extract_endpoint_data(url, response, authenticated=True))
            for link in _collect_links(url, response, base_domain):
                if link not in visited:
                    to_visit.append(link)
        except requests.exceptions.RequestException as e:
            logger.warning("Auth crawl error", extra={"url": url, "error": str(e)})

    logger.info("Authenticated crawl complete", extra={
        "auth_type": auth_type, "endpoints": len(endpoints)
    })
    return endpoints


def _login_form(session: requests.Session, target: str, auth_config: dict):
    login_url = auth_config.get("login_url", f"{target}/login")
    username = auth_config.get("username", "")
    password = auth_config.get("password", "")
    username_field = auth_config.get("username_field", "username")
    password_field = auth_config.get("password_field", "password")

    try:
        # Fetch login page first to capture any CSRF token
        login_page = session.get(login_url, timeout=10, verify=False)
        soup = BeautifulSoup(login_page.text, "html.parser")
        form_data = {username_field: username, password_field: password}

        # Carry over hidden fields (CSRF tokens, etc.)
        for hidden in soup.find_all("input", type="hidden"):
            name = hidden.get("name")
            value = hidden.get("value", "")
            if name:
                form_data[name] = value

        resp = session.post(login_url, data=form_data, timeout=10, verify=False)

        if resp.status_code in (200, 302):
            logger.info("Form login submitted", extra={"login_url": login_url, "status": resp.status_code})
        else:
            logger.warning("Form login returned unexpected status", extra={"status": resp.status_code})

    except Exception as e:
        logger.error("Form login failed", extra={"error": str(e)})
