"""
A minimal same-origin crawler. Not trying to be exhaustive or handle
JS-rendered pages - just enough to discover links and forms so the
vulnerability checks have targets to test.
"""
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser


class _PageParser(HTMLParser):
    """Extracts <a href> links and <form> definitions from raw HTML."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        elif tag == "form":
            self._current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").lower(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attrs.get("name"),
                "type": attrs.get("type", "text"),
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def crawl(session, base_url, max_pages=25):
    """
    Breadth-first crawl of same-origin pages starting at base_url.
    Returns (pages, forms) where pages is a set of visited URLs and
    forms is a list of (page_url, form_dict) tuples.
    """
    base_netloc = urlparse(base_url).netloc
    to_visit = [base_url]
    visited = set()
    all_forms = []

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=5)
        except Exception:
            continue
        if "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        parser = _PageParser()
        parser.feed(resp.text)

        for form in parser.forms:
            all_forms.append((url, form))

        for link in parser.links:
            full = urljoin(url, link)
            parsed = urlparse(full)
            if parsed.netloc == base_netloc and parsed.scheme in ("http", "https"):
                clean = full.split("#")[0]
                if clean not in visited:
                    to_visit.append(clean)

    return visited, all_forms
