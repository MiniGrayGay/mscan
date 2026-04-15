import json
import os
import re
import shlex
import ssl
import stat
import subprocess
import time
from collections import deque
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from ipaddress import ip_address
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener


BASE_DIR = Path(__file__).resolve().parent
BIN_DIR = BASE_DIR / "bin"
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
XRAY_DIR = BASE_DIR / "web" / "xray_1.9.1"
XRAY_BINARY = XRAY_DIR / "xray"
XRAY_LIB_DIR = BASE_DIR / "lib"
INPUT_DIR = DATA_DIR / "input"
URLS_DIR = DATA_DIR / "urls"

HTTP_SCHEMES = {"http", "https"}
STATIC_SUFFIXES = {
    ".7z",
    ".avi",
    ".bmp",
    ".css",
    ".eot",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".mov",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".rar",
    ".svg",
    ".tar",
    ".tgz",
    ".ttf",
    ".wav",
    ".webm",
    ".woff",
    ".woff2",
    ".zip",
}
CRAWLER_MAX_DEPTH = 2
CRAWLER_MAX_VISITS_PER_SEED = 40
CRAWLER_TIMEOUT_SECONDS = 8
HTTP_USER_AGENT = "mscan/2.0"

MODULE_RESULTS = {}


def times():
    return time.strftime("%Y%m%d%H%M%S")


def resolve_path(path_like):
    path = Path(path_like)
    if path.is_absolute():
        return path
    return BASE_DIR / path


def relative_path(path_like):
    path = resolve_path(path_like)
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)


def ensure_dir(path_like):
    resolve_path(path_like).mkdir(parents=True, exist_ok=True)


def ensure_runtime_dirs():
    for path in [
        DATA_DIR / "afrog",
        DATA_DIR / "amass",
        DATA_DIR / "dig",
        DATA_DIR / "dnsx",
        DATA_DIR / "fuzz",
        DATA_DIR / "httpx",
        DATA_DIR / "ipcdn",
        DATA_DIR / "nuclei",
        DATA_DIR / "POC-bomber",
        DATA_DIR / "saucerframe",
        DATA_DIR / "txport",
        DATA_DIR / "xray",
        INPUT_DIR,
        URLS_DIR,
        REPORTS_DIR,
        XRAY_LIB_DIR,
    ]:
        ensure_dir(path)


def reads(path_like):
    path = resolve_path(path_like)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        return handle.readlines()


def read_nonempty_lines(path_like):
    return [line.strip() for line in reads(path_like) if line.strip()]


def save_files(path_like, data):
    path = resolve_path(path_like)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        return handle.write(data)


def write_lines(path_like, lines):
    path = resolve_path(path_like)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(f"{line}\n")


def write_text(path_like, content):
    path = resolve_path(path_like)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def remove_file(path_like):
    path = resolve_path(path_like)
    if path.exists():
        path.unlink()


def run_command(command, cwd=BASE_DIR, env=None):
    cwd_path = resolve_path(cwd)
    print(f"[cmd] ({cwd_path}) {command}", flush=True)
    process = subprocess.Popen(
        command,
        shell=True,
        cwd=str(cwd_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="ignore",
        env=env,
    )
    output = []
    if process.stdout is not None:
        for line in process.stdout:
            line = line.rstrip("\n")
            output.append(line)
            if line:
                print(line, flush=True)
    process.wait()
    if process.returncode != 0:
        print(f"[!] command failed with exit code {process.returncode}", flush=True)
    return process.returncode, output


def quote(path_like):
    return shlex.quote(str(resolve_path(path_like)))


def artifact_info(path_like):
    if path_like is None:
        return None
    path = resolve_path(path_like)
    if not path.exists():
        return None
    return {
        "path": relative_path(path),
        "size_bytes": path.stat().st_size,
    }


def record_module(name, status, findings=None, artifacts=None, notes=""):
    MODULE_RESULTS[name] = {
        "status": status,
        "findings": findings,
        "artifacts": [item for item in (artifacts or []) if item is not None],
        "notes": notes,
    }


def count_lines(path_like):
    return len(read_nonempty_lines(path_like))


def read_preview(path_like, limit=10):
    return read_nonempty_lines(path_like)[:limit]


def latest_file(directory, pattern):
    directory = resolve_path(directory)
    matches = sorted(directory.glob(pattern), key=lambda item: item.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def dedupe_preserve_order(items):
    seen = set()
    result = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def has_url_scheme(value):
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value.strip()))


def is_ip_host(host):
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def default_port_for_scheme(scheme):
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None


def normalize_url(value):
    if not value:
        return None

    raw_value = value.strip()
    if not raw_value:
        return None

    candidate = raw_value if has_url_scheme(raw_value) else f"http://{raw_value.lstrip('/')}"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in HTTP_SCHEMES:
        return None

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    path = parsed.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    if not path.startswith("/"):
        path = f"/{path}"

    netloc = host
    default_port = default_port_for_scheme(scheme)
    if port and port != default_port:
        netloc = f"{host}:{port}"

    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def normalize_probe_target(target):
    target = target.strip()
    if not target:
        return None
    if has_url_scheme(target):
        return normalize_url(target)
    if "/" in target:
        return normalize_url(target)
    return target


def normalize_host(value):
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if not has_url_scheme(candidate):
        candidate = f"http://{candidate.lstrip('/')}"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    host = (parsed.hostname or "").strip().lower()
    return host or None


def should_use_amass(host):
    return bool(host and not is_ip_host(host) and host != "localhost" and "." in host)


def is_probably_page(url):
    normalized = normalize_url(url)
    if not normalized:
        return False
    parsed = urlsplit(normalized)
    path = parsed.path.lower()
    if parsed.query:
        return True
    return not any(path.endswith(suffix) for suffix in STATIC_SUFFIXES)


def scan_scope(url):
    parsed = urlsplit(url)
    port = parsed.port or default_port_for_scheme(parsed.scheme.lower())
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def is_same_scan_scope(candidate, seed):
    candidate_url = normalize_url(candidate)
    seed_url = normalize_url(seed)
    if not candidate_url or not seed_url:
        return False
    _, candidate_host, candidate_port = scan_scope(candidate_url)
    _, seed_host, seed_port = scan_scope(seed_url)
    return candidate_host == seed_host and candidate_port == seed_port


def create_empty_file(path_like):
    write_text(path_like, "")


def scan_target_file():
    return URLS_DIR / "scan_targets.txt"


def root_url_file():
    return DATA_DIR / "httpx" / "url.txt"


def crawler_url_file():
    return URLS_DIR / "crawler.txt"


def fuzz_url_file():
    return DATA_DIR / "fuzz" / "urls.txt"


def load_json_records(path_like):
    if path_like is None:
        return []
    path = resolve_path(path_like)
    if not path.exists() or path.stat().st_size == 0:
        return []
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            return [payload]
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records
    return []


def prepare_targets():
    raw_targets = read_nonempty_lines(BASE_DIR / "domain.txt")
    probe_targets = []
    host_targets = []
    amass_targets = []

    for raw_target in raw_targets:
        probe_target = normalize_probe_target(raw_target)
        if probe_target:
            probe_targets.append(probe_target)

        host = normalize_host(raw_target)
        if host:
            host_targets.append(host)
            if should_use_amass(host):
                amass_targets.append(host)

    write_lines(INPUT_DIR / "probe_targets.txt", dedupe_preserve_order(probe_targets))
    write_lines(INPUT_DIR / "hosts.txt", dedupe_preserve_order(host_targets))
    write_lines(INPUT_DIR / "amass_domains.txt", dedupe_preserve_order(amass_targets))

    write_lines(crawler_url_file(), [])
    write_lines(fuzz_url_file(), [])
    write_lines(scan_target_file(), [])


def merge_scan_targets():
    combined = []
    for source_file in [root_url_file(), crawler_url_file(), fuzz_url_file()]:
        for url in read_nonempty_lines(source_file):
            normalized_url = normalize_url(url)
            if normalized_url and is_probably_page(normalized_url):
                combined.append(normalized_url)

    merged = dedupe_preserve_order(combined)
    write_lines(scan_target_file(), merged)
    return merged


def infer_module_result(name):
    if name == "amass":
        artifact = artifact_info(DATA_DIR / "amass" / "domain.txt")
        return {
            "status": "ok" if artifact else "unknown",
            "findings": count_lines(DATA_DIR / "amass" / "domain.txt") if artifact else None,
            "artifacts": [artifact] if artifact else [],
            "notes": "",
        }
    if name == "httpx":
        artifact = artifact_info(root_url_file())
        return {
            "status": "ok" if artifact else "unknown",
            "findings": count_lines(root_url_file()) if artifact else None,
            "artifacts": [artifact] if artifact else [],
            "notes": "",
        }
    if name == "url_discovery":
        artifacts = [artifact_info(crawler_url_file()), artifact_info(scan_target_file())]
        artifacts = [item for item in artifacts if item]
        return {
            "status": "ok" if artifacts else "unknown",
            "findings": count_lines(crawler_url_file()) if artifacts else None,
            "artifacts": artifacts,
            "notes": "",
        }
    if name == "POC-bomber":
        artifact = artifact_info(DATA_DIR / "POC-bomber" / "poc.txt")
        return {
            "status": "ok" if artifact else "unknown",
            "findings": count_lines(DATA_DIR / "POC-bomber" / "poc.txt") if artifact else None,
            "artifacts": [artifact] if artifact else [],
            "notes": "",
        }
    if name == "saucerframe":
        artifact = artifact_info(DATA_DIR / "saucerframe" / "poc.txt")
        return {
            "status": "ok" if artifact else "unknown",
            "findings": count_lines(DATA_DIR / "saucerframe" / "poc.txt") if artifact else None,
            "artifacts": [artifact] if artifact else [],
            "notes": "",
        }
    if name == "afrog":
        artifact = artifact_info(DATA_DIR / "afrog" / "reports" / "result.html")
        return {
            "status": "ok" if artifact else "unknown",
            "findings": None,
            "artifacts": [artifact] if artifact else [],
            "notes": "",
        }
    if name == "nuclei":
        artifact = artifact_info(DATA_DIR / "nuclei" / "poc.txt")
        return {
            "status": "ok" if artifact else "unknown",
            "findings": count_lines(DATA_DIR / "nuclei" / "poc.txt") if artifact else None,
            "artifacts": [artifact] if artifact else [],
            "notes": "",
        }
    if name == "fuzz":
        artifacts = [
            artifact_info(DATA_DIR / "fuzz" / "url.log"),
            artifact_info(DATA_DIR / "fuzz" / "data.json"),
            artifact_info(fuzz_url_file()),
        ]
        artifacts = [item for item in artifacts if item]
        return {
            "status": "ok" if artifacts else "unknown",
            "findings": count_lines(fuzz_url_file()) if artifacts else None,
            "artifacts": artifacts,
            "notes": "",
        }
    if name == "cdn_dig":
        artifact = artifact_info(DATA_DIR / "dig" / "cdn.txt")
        return {
            "status": "ok" if artifact else "unknown",
            "findings": count_lines(DATA_DIR / "dig" / "cdn.txt") if artifact else None,
            "artifacts": [artifact] if artifact else [],
            "notes": "",
        }
    if name == "dnsx":
        artifact = artifact_info(DATA_DIR / "dnsx" / "ip.txt")
        return {
            "status": "ok" if artifact else "unknown",
            "findings": count_lines(DATA_DIR / "dnsx" / "ip.txt") if artifact else None,
            "artifacts": [artifact] if artifact else [],
            "notes": "",
        }
    if name == "ipcdn":
        artifacts = [artifact_info(DATA_DIR / "ipcdn" / "ips.txt"), artifact_info(DATA_DIR / "ipcdn" / "ip.txt")]
        artifacts = [item for item in artifacts if item]
        return {
            "status": "ok" if artifacts else "unknown",
            "findings": count_lines(DATA_DIR / "ipcdn" / "ip.txt") if artifacts else None,
            "artifacts": artifacts,
            "notes": "",
        }
    if name == "txport":
        artifact = artifact_info(DATA_DIR / "txport" / "hosts.txt")
        return {
            "status": "ok" if artifact else "unknown",
            "findings": count_lines(DATA_DIR / "txport" / "hosts.txt") if artifact else None,
            "artifacts": [artifact] if artifact else [],
            "notes": "",
        }
    if name == "xray":
        latest_html = latest_file(DATA_DIR / "xray", "*.html")
        latest_json = latest_file(DATA_DIR / "xray", "*.json")
        artifacts = [artifact_info(latest_html), artifact_info(latest_json)]
        artifacts = [item for item in artifacts if item]
        return {
            "status": "ok" if artifacts else "unknown",
            "findings": len(load_json_records(latest_json)) if latest_json else None,
            "artifacts": artifacts,
            "notes": "",
        }
    return {"status": "unknown", "findings": None, "artifacts": [], "notes": ""}


def xray_preview(limit=10):
    latest_json = latest_file(DATA_DIR / "xray", "*.json")
    preview = []
    for record in load_json_records(latest_json)[:limit]:
        plugin = record.get("plugin", "xray")
        target = record.get("target", {}).get("url", "")
        if plugin and target:
            preview.append(f"{plugin} [+] {target}")
    return preview


def amass():
    input_file = INPUT_DIR / "amass_domains.txt"
    output_file = DATA_DIR / "amass" / "domain.txt"
    remove_file(output_file)

    seed_domains = read_nonempty_lines(input_file)
    if not seed_domains:
        create_empty_file(output_file)
        record_module(
            "amass",
            "skipped",
            findings=0,
            artifacts=[artifact_info(output_file)],
            notes="No domain-style targets for amass",
        )
        return

    command = (
        f"{quote(BIN_DIR / 'amass')} enum -passive "
        f"-df {quote(input_file)} "
        f"-config {quote(BASE_DIR / 'config' / 'amass.ini')} "
        f"-o {quote(output_file)}"
    )
    returncode, _ = run_command(command)

    discovered_domains = []
    for domain in seed_domains + read_nonempty_lines(output_file):
        normalized_domain = normalize_host(domain)
        if should_use_amass(normalized_domain):
            discovered_domains.append(normalized_domain)

    discovered_domains = dedupe_preserve_order(discovered_domains)
    write_lines(output_file, discovered_domains)

    status = "ok" if returncode == 0 else "failed"
    notes = ""
    if returncode != 0:
        notes = f"amass exit code {returncode}"
    elif len(discovered_domains) == len(seed_domains):
        notes = "No additional subdomains discovered"

    record_module(
        "amass",
        status,
        findings=len(discovered_domains),
        artifacts=[artifact_info(output_file)],
        notes=notes,
    )


def httpx():
    output_file = root_url_file()
    input_file = DATA_DIR / "httpx" / "input.txt"
    remove_file(output_file)

    all_targets = dedupe_preserve_order(
        read_nonempty_lines(INPUT_DIR / "probe_targets.txt") + read_nonempty_lines(DATA_DIR / "amass" / "domain.txt")
    )
    write_lines(input_file, all_targets)

    if not all_targets:
        create_empty_file(output_file)
        record_module(
            "httpx",
            "skipped",
            findings=0,
            artifacts=[artifact_info(output_file)],
            notes="No valid targets for httpx",
        )
        return

    command = (
        f"{quote(BIN_DIR / 'httpx')} -t 50 -rl 150 -fc 404 "
        f"-l {quote(input_file)} "
        f"-o {quote(output_file)}"
    )
    returncode, _ = run_command(command)

    alive_urls = []
    for url in read_nonempty_lines(output_file):
        normalized_url = normalize_url(url)
        if normalized_url:
            alive_urls.append(normalized_url)

    alive_urls = dedupe_preserve_order(alive_urls)
    write_lines(output_file, alive_urls)

    record_module(
        "httpx",
        "ok" if returncode == 0 else "failed",
        findings=len(alive_urls),
        artifacts=[artifact_info(output_file), artifact_info(input_file)],
        notes="" if returncode == 0 else f"httpx exit code {returncode}",
    )


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        for attribute in ("href", "src", "action"):
            value = attrs_dict.get(attribute)
            if value:
                self.links.append(value.strip())

        if tag.lower() == "meta":
            http_equiv = attrs_dict.get("http-equiv", "")
            content = attrs_dict.get("content", "")
            if http_equiv.lower() == "refresh":
                match = re.search(r"url\s*=\s*(.+)", content, flags=re.IGNORECASE)
                if match:
                    self.links.append(match.group(1).strip().strip("'\""))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def build_http_opener():
    cookie_jar = CookieJar()
    ssl_context = ssl._create_unverified_context()
    return build_opener(HTTPCookieProcessor(cookie_jar), HTTPSHandler(context=ssl_context))


def is_html_like_content(content_type):
    content_type = (content_type or "").lower()
    return "html" in content_type or "xml" in content_type


def fetch_page(opener, url):
    request = Request(
        url,
        headers={
            "User-Agent": HTTP_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    try:
        with opener.open(request, timeout=CRAWLER_TIMEOUT_SECONDS) as response:
            final_url = normalize_url(response.geturl())
            content_type = response.headers.get("Content-Type", "")
            body = response.read(1024 * 1024).decode("utf-8", errors="ignore")
            return final_url, content_type, body
    except (HTTPError, URLError, TimeoutError, OSError):
        return None, "", ""


def sanitize_link(raw_link):
    if not raw_link:
        return None
    candidate = raw_link.strip()
    lowered = candidate.lower()
    if lowered.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None
    if candidate.startswith("#"):
        return None
    return candidate


def crawl_seed_urls(seed_url):
    normalized_seed = normalize_url(seed_url)
    if not normalized_seed:
        return []

    opener = build_http_opener()
    queue = deque([(normalized_seed, 0)])
    visited = set()
    discovered = []

    while queue and len(visited) < CRAWLER_MAX_VISITS_PER_SEED:
        current_url, depth = queue.popleft()
        current_url = normalize_url(current_url)
        if not current_url or current_url in visited or not is_same_scan_scope(current_url, normalized_seed):
            continue

        visited.add(current_url)
        final_url, content_type, body = fetch_page(opener, current_url)
        if not final_url or not is_same_scan_scope(final_url, normalized_seed):
            continue

        if is_probably_page(final_url):
            discovered.append(final_url)

        if depth >= CRAWLER_MAX_DEPTH or not body or not is_html_like_content(content_type):
            continue

        extractor = LinkExtractor()
        try:
            extractor.feed(body)
        except Exception:
            continue

        for raw_link in extractor.links:
            link = sanitize_link(raw_link)
            if not link:
                continue

            candidate = normalize_url(urljoin(final_url, link))
            if not candidate or not is_same_scan_scope(candidate, normalized_seed):
                continue

            if is_probably_page(candidate):
                discovered.append(candidate)

            if depth + 1 <= CRAWLER_MAX_DEPTH and candidate not in visited and is_probably_page(candidate):
                queue.append((candidate, depth + 1))

    return dedupe_preserve_order(discovered)


def url_discovery():
    roots = read_nonempty_lines(root_url_file())
    output_file = crawler_url_file()
    remove_file(output_file)

    if not roots:
        create_empty_file(output_file)
        create_empty_file(scan_target_file())
        record_module(
            "url_discovery",
            "skipped",
            findings=0,
            artifacts=[artifact_info(output_file), artifact_info(scan_target_file())],
            notes="No alive root URLs available for crawling",
        )
        return

    discovered_urls = []
    for root_url in roots:
        for discovered_url in crawl_seed_urls(root_url):
            if discovered_url != normalize_url(root_url):
                discovered_urls.append(discovered_url)

    discovered_urls = dedupe_preserve_order(discovered_urls)
    write_lines(output_file, discovered_urls)
    merged_urls = merge_scan_targets()

    record_module(
        "url_discovery",
        "ok",
        findings=len(discovered_urls),
        artifacts=[artifact_info(output_file), artifact_info(scan_target_file())],
        notes=f"final scan targets: {len(merged_urls)}",
    )


def current_scan_targets():
    return read_nonempty_lines(scan_target_file())


def ensure_scan_targets():
    targets = current_scan_targets()
    if targets:
        return scan_target_file(), targets

    roots = read_nonempty_lines(root_url_file())
    if roots:
        write_lines(scan_target_file(), roots)
        return scan_target_file(), roots

    return scan_target_file(), []


def POC_bomber():
    output_file = DATA_DIR / "POC-bomber" / "poc.txt"
    remove_file(output_file)
    target_file, targets = ensure_scan_targets()
    if not targets:
        create_empty_file(output_file)
        record_module(
            "POC-bomber",
            "skipped",
            findings=0,
            artifacts=[artifact_info(output_file)],
            notes="No URLs available for POC-bomber",
        )
        return

    command = f"python3 pocbomber.py -f {quote(target_file)} -o {quote(output_file)}"
    returncode, _ = run_command(command, cwd=BASE_DIR / "web" / "POC-bomber")

    if not output_file.exists() and returncode == 0:
        create_empty_file(output_file)

    record_module(
        "POC-bomber",
        "ok" if returncode == 0 else "failed",
        findings=count_lines(output_file),
        artifacts=[artifact_info(output_file)],
        notes=f"targets: {len(targets)}" if returncode == 0 else f"POC-bomber exit code {returncode}",
    )


def saucerframe():
    output_file = DATA_DIR / "saucerframe" / "poc.txt"
    remove_file(output_file)
    target_file, targets = ensure_scan_targets()
    if not targets:
        create_empty_file(output_file)
        record_module(
            "saucerframe",
            "skipped",
            findings=0,
            artifacts=[artifact_info(output_file)],
            notes="No URLs available for saucerframe",
        )
        return

    command = (
        f"python3 saucerframe.py -s all -t 300 -eG -v 2 "
        f"-iF {quote(target_file)} "
        f"-o {quote(output_file)}"
    )
    returncode, _ = run_command(command, cwd=BASE_DIR / "web" / "saucerframe")

    if not output_file.exists() and returncode == 0:
        create_empty_file(output_file)

    record_module(
        "saucerframe",
        "ok" if returncode == 0 else "failed",
        findings=count_lines(output_file),
        artifacts=[artifact_info(output_file)],
        notes=f"targets: {len(targets)}" if returncode == 0 else f"saucerframe exit code {returncode}",
    )


def afrog():
    workdir = DATA_DIR / "afrog"
    report_dir = workdir / "reports"
    output_file = report_dir / "result.html"
    ensure_dir(report_dir)
    remove_file(output_file)

    target_file, targets = ensure_scan_targets()
    if not targets:
        create_empty_file(output_file)
        record_module(
            "afrog",
            "skipped",
            findings=None,
            artifacts=[artifact_info(output_file)],
            notes="No URLs available for afrog",
        )
        return

    command = f"{quote(BIN_DIR / 'afrog')} -silent -T {quote(target_file)} -o result.html"
    returncode, _ = run_command(command, cwd=workdir)

    if not output_file.exists() and returncode == 0:
        create_empty_file(output_file)

    record_module(
        "afrog",
        "ok" if returncode == 0 else "failed",
        findings=None,
        artifacts=[artifact_info(output_file)],
        notes=f"targets: {len(targets)}" if returncode == 0 else f"afrog exit code {returncode}",
    )


def nuclei():
    output_file = DATA_DIR / "nuclei" / "poc.txt"
    remove_file(output_file)
    target_file, targets = ensure_scan_targets()
    if not targets:
        create_empty_file(output_file)
        record_module(
            "nuclei",
            "skipped",
            findings=0,
            artifacts=[artifact_info(output_file)],
            notes="No URLs available for nuclei",
        )
        return

    command = (
        f"{quote(BIN_DIR / 'nuclei')} -silent -disable-update-check "
        f"-t {quote(BASE_DIR / 'web' / 'nuclei-templates' / 'cves')},"
        f"{quote(BASE_DIR / 'web' / 'nuclei-templates' / 'cnvd')} "
        f"-severity medium,high,critical -retries 1 -rl 150 "
        f"-list {quote(target_file)} "
        f"-o {quote(output_file)}"
    )
    returncode, _ = run_command(command)

    if not output_file.exists() and returncode == 0:
        create_empty_file(output_file)

    record_module(
        "nuclei",
        "ok" if returncode == 0 else "failed",
        findings=count_lines(output_file),
        artifacts=[artifact_info(output_file)],
        notes=f"targets: {len(targets)}" if returncode == 0 else f"nuclei exit code {returncode}",
    )


def is_clean_ffuf_discovery(fuzz_name):
    if not fuzz_name:
        return False
    lowered = fuzz_name.lower()
    suspicious_fragments = ["<", ">", "\"", "'", "(", ")", "{", "}", "javascript:", "%3c", "%3e", "://"]
    if any(fragment in lowered for fragment in suspicious_fragments):
        return False
    if "?" in fuzz_name or "&" in fuzz_name or "=" in fuzz_name:
        return False
    return True


def fuzz():
    output_json = DATA_DIR / "fuzz" / "data.json"
    output_log = DATA_DIR / "fuzz" / "url.log"
    output_urls = fuzz_url_file()
    temp_json = DATA_DIR / "fuzz" / "single.json"

    remove_file(output_json)
    remove_file(output_log)
    remove_file(output_urls)
    remove_file(temp_json)

    all_urls = read_nonempty_lines(root_url_file())
    if not all_urls:
        create_empty_file(output_json)
        create_empty_file(output_log)
        create_empty_file(output_urls)
        record_module(
            "fuzz",
            "skipped",
            findings=0,
            artifacts=[artifact_info(output_log), artifact_info(output_json), artifact_info(output_urls)],
            notes="No alive root URLs available for ffuf",
        )
        return

    aggregated_records = []
    log_lines = []
    discovered_urls = []
    last_returncode = 0

    for url in all_urls:
        normalized_base = normalize_url(url)
        if not normalized_base:
            continue

        fuzz_target = normalized_base.rstrip("/") + "/FUZZ"
        command = (
            f"{quote(BIN_DIR / 'ffuf')} -t 200 "
            f"-w {quote(BASE_DIR / 'web' / 'fuzz' / 'dict' / 'content-dirsearch-0.9w.txt')} "
            f"-ac -of json -o {quote(temp_json)} "
            f"-u {shlex.quote(fuzz_target)}"
        )
        last_returncode, _ = run_command(command)

        for data in load_json_records(temp_json):
            aggregated_records.append(data)
            for result in data.get("results", []):
                fuzz_name = result.get("input", {}).get("FUZZ", "")
                fuzz_url = normalize_url(result.get("url", ""))
                if fuzz_name and fuzz_url:
                    log_lines.append(f"{fuzz_name} [+] {fuzz_url}")
                    if is_clean_ffuf_discovery(fuzz_name) and is_probably_page(fuzz_url):
                        discovered_urls.append(fuzz_url)

    write_text(output_json, json.dumps(aggregated_records, ensure_ascii=False, indent=2))
    write_lines(output_log, dedupe_preserve_order(log_lines))
    write_lines(output_urls, dedupe_preserve_order(discovered_urls))

    merged_urls = merge_scan_targets()

    record_module(
        "fuzz",
        "ok" if last_returncode == 0 else "failed",
        findings=count_lines(output_urls),
        artifacts=[artifact_info(output_log), artifact_info(output_json), artifact_info(output_urls)],
        notes=(
            f"child URLs merged into scan targets: {len(merged_urls)}"
            if last_returncode == 0
            else f"ffuf exit code {last_returncode}"
        ),
    )


def cdn_dig():
    output_file = DATA_DIR / "dig" / "cdn.txt"
    remove_file(output_file)

    domains = read_nonempty_lines(DATA_DIR / "amass" / "domain.txt")
    if not domains:
        create_empty_file(output_file)
        record_module(
            "cdn_dig",
            "skipped",
            findings=0,
            artifacts=[artifact_info(output_file)],
            notes="No domains available for dig",
        )
        return

    results = []
    for domain in domains:
        process = subprocess.run(
            ["dig", "+noall", "+answer", domain],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
        )
        ip_matches = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", process.stdout)
        if len(ip_matches) == 1:
            results.append(domain)

    write_lines(output_file, dedupe_preserve_order(results))
    record_module(
        "cdn_dig",
        "ok",
        findings=count_lines(output_file),
        artifacts=[artifact_info(output_file)],
    )


def dnsx_ip():
    output_file = DATA_DIR / "dnsx" / "ip.txt"
    remove_file(output_file)

    input_file = DATA_DIR / "dig" / "cdn.txt"
    if count_lines(input_file) == 0:
        create_empty_file(output_file)
        record_module(
            "dnsx",
            "skipped",
            findings=0,
            artifacts=[artifact_info(output_file)],
            notes="No CDN-filtered domains available for dnsx",
        )
        return

    command = (
        f"{quote(BIN_DIR / 'dnsx')} -a -resp-only "
        f"-l {quote(input_file)} "
        f"-o {quote(output_file)}"
    )
    returncode, _ = run_command(command)

    if not output_file.exists() and returncode == 0:
        create_empty_file(output_file)

    record_module(
        "dnsx",
        "ok" if returncode == 0 else "failed",
        findings=count_lines(output_file),
        artifacts=[artifact_info(output_file)],
        notes="" if returncode == 0 else f"dnsx exit code {returncode}",
    )


def ipcdn():
    ips_file = DATA_DIR / "ipcdn" / "ips.txt"
    ip_file = DATA_DIR / "ipcdn" / "ip.txt"
    remove_file(ips_file)
    remove_file(ip_file)

    dnsx_file = DATA_DIR / "dnsx" / "ip.txt"
    if count_lines(dnsx_file) == 0:
        create_empty_file(ips_file)
        create_empty_file(ip_file)
        record_module(
            "ipcdn",
            "skipped",
            findings=0,
            artifacts=[artifact_info(ips_file), artifact_info(ip_file)],
            notes="No dnsx IP results available for ipcdn",
        )
        return

    command_ips = (
        f"cat {quote(dnsx_file)} | "
        f"{quote(BIN_DIR / 'qsreplace')} -a > {quote(ips_file)}"
    )
    command_ipcdn = (
        f"cat {quote(dnsx_file)} | "
        f"{quote(BIN_DIR / 'ipcdn')} -m not > {quote(ip_file)}"
    )
    returncode_ips, _ = run_command(command_ips)
    returncode_ipcdn, _ = run_command(command_ipcdn)

    if not ips_file.exists() and returncode_ips == 0:
        create_empty_file(ips_file)
    if not ip_file.exists() and returncode_ipcdn == 0:
        create_empty_file(ip_file)

    status = "ok" if returncode_ips == 0 and returncode_ipcdn == 0 else "failed"
    notes = []
    if returncode_ips != 0:
        notes.append(f"qsreplace exit code {returncode_ips}")
    if returncode_ipcdn != 0:
        notes.append(f"ipcdn exit code {returncode_ipcdn}")

    record_module(
        "ipcdn",
        status,
        findings=count_lines(ip_file),
        artifacts=[artifact_info(ips_file), artifact_info(ip_file)],
        notes="; ".join(notes),
    )


def txport():
    output_file = DATA_DIR / "txport" / "hosts.txt"
    remove_file(output_file)

    ip_file = DATA_DIR / "ipcdn" / "ip.txt"
    if count_lines(ip_file) == 0:
        create_empty_file(output_file)
        record_module(
            "txport",
            "skipped",
            findings=0,
            artifacts=[artifact_info(output_file)],
            notes="No IP targets available for txport",
        )
        return

    command = (
        f"{quote(BIN_DIR / 'txport')} -p 1-65535 "
        f"-l {quote(ip_file)} "
        f"-o {quote(output_file)}"
    )
    returncode, _ = run_command(command)

    if not output_file.exists() and returncode == 0:
        create_empty_file(output_file)

    record_module(
        "txport",
        "ok" if returncode == 0 else "failed",
        findings=count_lines(output_file),
        artifacts=[artifact_info(output_file)],
        notes="" if returncode == 0 else f"txport exit code {returncode}",
    )


def find_libpcap_candidate():
    candidates = [
        Path("/usr/lib/libpcap.so.0.8"),
        Path("/usr/lib/libpcap.so.1"),
        Path("/usr/lib64/libpcap.so.0.8"),
        Path("/usr/lib64/libpcap.so.1"),
        Path("/lib/libpcap.so.0.8"),
        Path("/lib/libpcap.so.1"),
        Path("/lib64/libpcap.so.0.8"),
        Path("/lib64/libpcap.so.1"),
        Path("/usr/lib/x86_64-linux-gnu/libpcap.so.0.8"),
        Path("/usr/lib/x86_64-linux-gnu/libpcap.so.1"),
        Path("/lib/x86_64-linux-gnu/libpcap.so.0.8"),
        Path("/lib/x86_64-linux-gnu/libpcap.so.1"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def prepare_xray_env():
    if not XRAY_BINARY.exists():
        raise FileNotFoundError(f"xray binary not found: {XRAY_BINARY}")

    current_mode = XRAY_BINARY.stat().st_mode
    XRAY_BINARY.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    compat_link = XRAY_LIB_DIR / "libpcap.so.0.8"
    libpcap_candidate = find_libpcap_candidate()
    if libpcap_candidate is None:
        raise RuntimeError("libpcap runtime library was not found, xray cannot start")
    if not compat_link.exists():
        compat_link.symlink_to(libpcap_candidate)

    env = os.environ.copy()
    existing = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = f"{XRAY_LIB_DIR}:{existing}" if existing else str(XRAY_LIB_DIR)
    return env


def xray():
    target_file, targets = ensure_scan_targets()
    if not targets:
        record_module("xray", "skipped", findings=0, notes="No URLs available for xray")
        return

    timestamp = times()
    html_output = DATA_DIR / "xray" / f"{timestamp}.html"
    json_output = DATA_DIR / "xray" / f"{timestamp}.json"
    remove_file(html_output)
    remove_file(json_output)

    try:
        env = prepare_xray_env()
    except Exception as exc:
        record_module("xray", "failed", findings=None, notes=str(exc))
        return

    command = (
        f"./xray webscan "
        f"--url-file {quote(target_file)} "
        f"--html-output {quote(html_output)} "
        f"--json-output {quote(json_output)}"
    )
    returncode, _ = run_command(command, cwd=XRAY_DIR, env=env)
    records = load_json_records(json_output)
    status = "ok" if returncode == 0 and (html_output.exists() or json_output.exists()) else "failed"
    notes = f"targets: {len(targets)}" if returncode == 0 else f"xray exit code {returncode}"
    record_module(
        "xray",
        status,
        findings=len(records),
        artifacts=[artifact_info(html_output), artifact_info(json_output)],
        notes=notes,
    )


def build_report_data():
    root_urls = set(read_nonempty_lines(root_url_file()))
    final_scan_urls = set(read_nonempty_lines(scan_target_file()))
    child_urls = final_scan_urls - root_urls

    previews = {
        "url_discovery": read_preview(scan_target_file()),
        "fuzz": read_preview(DATA_DIR / "fuzz" / "url.log"),
        "nuclei": read_preview(DATA_DIR / "nuclei" / "poc.txt"),
        "POC-bomber": read_preview(DATA_DIR / "POC-bomber" / "poc.txt"),
        "saucerframe": read_preview(DATA_DIR / "saucerframe" / "poc.txt"),
        "txport": read_preview(DATA_DIR / "txport" / "hosts.txt"),
        "xray": xray_preview(),
    }
    modules = []
    module_order = [
        "amass",
        "httpx",
        "url_discovery",
        "fuzz",
        "POC-bomber",
        "saucerframe",
        "afrog",
        "nuclei",
        "cdn_dig",
        "dnsx",
        "ipcdn",
        "txport",
        "xray",
    ]
    for name in module_order:
        module = MODULE_RESULTS.get(name, infer_module_result(name))
        modules.append(
            {
                "name": name,
                "status": module["status"],
                "findings": module["findings"],
                "artifacts": module["artifacts"],
                "notes": module["notes"],
            }
        )
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "targets": {
            "raw_input_count": count_lines(BASE_DIR / "domain.txt"),
            "host_target_count": count_lines(INPUT_DIR / "hosts.txt"),
            "domain_seed_count": count_lines(INPUT_DIR / "amass_domains.txt"),
            "resolved_domain_count": count_lines(DATA_DIR / "amass" / "domain.txt"),
            "alive_root_url_count": count_lines(root_url_file()),
            "discovered_child_url_count": len(child_urls),
            "final_scan_url_count": len(final_scan_urls),
        },
        "modules": modules,
        "previews": previews,
    }


def build_markdown_report(report):
    lines = [
        "# MScan Summary Report",
        "",
        f"- Generated At: {report['generated_at']}",
        f"- Raw Targets: {report['targets']['raw_input_count']}",
        f"- Parsed Hosts: {report['targets']['host_target_count']}",
        f"- Domain Seeds: {report['targets']['domain_seed_count']}",
        f"- Resolved Domains: {report['targets']['resolved_domain_count']}",
        f"- Alive Root URLs: {report['targets']['alive_root_url_count']}",
        f"- Discovered Child URLs: {report['targets']['discovered_child_url_count']}",
        f"- Final Scan URLs: {report['targets']['final_scan_url_count']}",
        "",
        "## Module Summary",
        "",
        "| Module | Status | Findings | Artifacts | Notes |",
        "| --- | --- | ---: | --- | --- |",
    ]

    for module in report["modules"]:
        findings = module["findings"] if module["findings"] is not None else "-"
        artifacts = "<br>".join(item["path"] for item in module["artifacts"]) if module["artifacts"] else "-"
        notes = module["notes"] or "-"
        lines.append(f"| {module['name']} | {module['status']} | {findings} | {artifacts} | {notes} |")

    lines.extend(
        [
            "",
            "## Findings Preview",
            "",
        ]
    )

    for name, preview in report["previews"].items():
        lines.append(f"### {name}")
        lines.append("")
        if preview:
            lines.append("```text")
            lines.extend(preview)
            lines.append("```")
        else:
            lines.append("No findings captured.")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def generate_report():
    report = build_report_data()
    timestamp = times()
    markdown = build_markdown_report(report)
    json_report = json.dumps(report, ensure_ascii=False, indent=2)

    timestamped_md = REPORTS_DIR / f"report_{timestamp}.md"
    timestamped_json = REPORTS_DIR / f"report_{timestamp}.json"
    latest_md = REPORTS_DIR / "latest.md"
    latest_json = REPORTS_DIR / "latest.json"

    write_text(timestamped_md, markdown)
    write_text(timestamped_json, json_report)
    write_text(latest_md, markdown)
    write_text(latest_json, json_report)

    record_module(
        "report",
        "ok",
        findings=None,
        artifacts=[
            artifact_info(timestamped_md),
            artifact_info(timestamped_json),
            artifact_info(latest_md),
            artifact_info(latest_json),
        ],
        notes="Summary report generated",
    )
    print(f"[+] report written to {relative_path(latest_md)}", flush=True)


def run_step(name, func):
    print(f"\n=== {name} ===", flush=True)
    try:
        func()
    except Exception as exc:
        record_module(name, "failed", findings=None, notes=str(exc))
        print(f"[!] {name} failed: {exc}", flush=True)


def main():
    ensure_runtime_dirs()
    prepare_targets()
    steps = [
        ("amass", amass),
        ("httpx", httpx),
        ("url_discovery", url_discovery),
        ("fuzz", fuzz),
        ("POC-bomber", POC_bomber),
        ("saucerframe", saucerframe),
        ("afrog", afrog),
        ("nuclei", nuclei),
        ("cdn_dig", cdn_dig),
        ("dnsx", dnsx_ip),
        ("ipcdn", ipcdn),
        ("txport", txport),
        ("xray", xray),
    ]

    for name, func in steps:
        run_step(name, func)

    generate_report()


if __name__ == "__main__":
    print("start\n", flush=True)
    main()
