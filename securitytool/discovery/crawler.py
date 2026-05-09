import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

def crawl_unauthenticated(target: str) -> list:
    visited = set()
    to_visit = [target]
    endpoints = []

    while to_visit:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            response = requests.get(url, timeout=10, verify=False)
            endpoints.append({
                "url": url,
                "status_code": response.status_code,
                "auth_required": False
            })

            soup = BeautifulSoup(response.text, "html.parser")
            for tag in soup.find_all("a", href=True):
                href = urljoin(url, tag["href"])
                if urlparse(href).netloc == urlparse(target).netloc:
                    if href not in visited:
                        to_visit.append(href)

        except requests.exceptions.RequestException as e:
            logger.warning("Crawl error", extra={"url": url, "error": str(e)})

    logger.info("Crawl complete", extra={"endpoints": len(endpoints)})
    return endpoints