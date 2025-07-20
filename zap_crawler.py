import asyncio
import aiohttp
from aiohttp import ClientSession
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from zapv2 import ZAPv2
import time
import argparse

# --- ZAP Config ---
ZAP_API_KEY = ''
ZAP_ADDRESS = 'localhost'
ZAP_PORT = '8090'
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={
    'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}',
    'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'
})

# --- Globals (will be initialized in main) ---
visited = set()
target_urls = set()
MAX_DEPTH = 2
semaphore = None  # set based on --threads


async def fetch(session: ClientSession, url: str) -> str:
    try:
        async with semaphore:
            async with session.get(url, timeout=10) as response:
                if response.content_type == 'text/html':
                    return await response.text()
    except Exception as e:
        print(f"[-] Failed to fetch {url}: {e}")
    return ""


def extract_links(base_url, html):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for tag in soup.find_all(["a", "script", "link"]):
        href = tag.get("href") or tag.get("src")
        if href:
            full_url = urljoin(base_url, href)
            links.add(full_url)
    return links


def is_in_scope(url, base_domain):
    parsed = urlparse(url)
    return parsed.netloc.endswith(base_domain)


async def crawl(session: ClientSession, url: str, base_domain: str, depth=1):
    if url in visited or depth > MAX_DEPTH:
        return
    visited.add(url)
    target_urls.add(url)
    print(f"[+] Crawled: {url}")

    html = await fetch(session, url)
    if not html:
        return

    links = extract_links(url, html)
    tasks = []
    for link in links:
        if is_in_scope(link, base_domain) and link not in visited:
            tasks.append(crawl(session, link, base_domain, depth + 1))

    await asyncio.gather(*tasks)


def zap_spider_and_scan(url):
    print(f"\n[*] Accessing in ZAP: {url}")
    zap.urlopen(url)
    time.sleep(2)

    print("[*] Starting Spider...")
    sid = zap.spider.scan(url)
    time.sleep(2)
    while int(zap.spider.status(sid)) < 100:
        print(f"Spider progress: {zap.spider.status(sid)}%")
        time.sleep(2)
    print("[+] Spider done.")

    print("[*] Starting Active Scan...")
    aid = zap.ascan.scan(url)
    while int(zap.ascan.status(aid)) < 100:
        print(f"Active Scan progress: {zap.ascan.status(aid)}%")
        time.sleep(5)
    print("[+] Active Scan done.")

    print("[*] Alerts found:")
    for alert in zap.core.alerts(baseurl=url)['alerts']:
        print(f"  - {alert['alert']} ({alert['risk']}) at {alert['url']}")


async def main(start_url, thread_count):
    global semaphore
    base_domain = urlparse(start_url).netloc
    semaphore = asyncio.Semaphore(thread_count)

    async with aiohttp.ClientSession() as session:
        await crawl(session, start_url, base_domain)

    print(f"\n[✔] Total discovered URLs in scope: {len(target_urls)}")
    for url in sorted(target_urls):
        zap_spider_and_scan(url)


if _name_ == "_main_":
    parser = argparse.ArgumentParser(description="Async Katana-like crawler with ZAP scan")
    parser.add_argument("url", help="Target URL to crawl and scan")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent crawling threads (default: 5)")
    args = parser.parse_args()

    asyncio.run(main(args.url, args.threads))
