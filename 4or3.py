#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
4or3 — Fast & Low-FP 403 Bypasser (Python CLI)

Author/Credits: Thayner Kesley
Links:
  - https://app.intigriti.com/researcher/profile/thaynerkesley
  - https://github.com/ThaynerKesley
  - https://www.linkedin.com/in/thayner/
Contact: thayner.contato@gmail.com

Design goals:
  • Fast and lightweight (async httpx, connection reuse, optional HTTP/2)
  • Lower false positives (baseline 403, body hash, content-length delta, optional title diff, confirmations)
  • Safe-by-default strategies; “extended/unsafe” only when explicitly requested
  • Intuitive CLI (-h/--help, -v/--verbose, -H/--header multi)

Notes:
  • No destructive methods by default. Default methods: GET, HEAD.
  • JSONL output for tooling, pretty table for humans.
  • Built-in rate limiter and jitter.

Usage examples:
  4or3 -u https://example.com/admin -v --pretty
  4or3 -l targets.txt -H "X-Intigriti-Username: thaynerkesley@intigriti.me" --limit-rps 5 -o results.jsonl
  4or3 -u https://example.com/secret --encodings extended --method-tricks extended --confirm 3 -vv --pretty
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import hashlib
import json
import os
import random
import re
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

try:
    import httpx
except Exception as e:
    print("[!] Missing dependency: httpx. Install with: pip install httpx", file=sys.stderr)
    raise

__VERSION__ = "0.1.1"

# -----------------------------
# Utilities
# -----------------------------

def color(s: str, code: str, enabled: bool) -> str:
    if not enabled:
        return s
    return f"\033[{code}m{s}\033[0m"


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_header_kv(header: str) -> Tuple[str, str]:
    if ":" not in header:
        raise ValueError("Header must be in 'Key: Value' format")
    k, v = header.split(":", 1)
    return k.strip(), v.strip()


def blake2s(data: bytes) -> str:
    return hashlib.blake2s(data or b"", digest_size=16).hexdigest()


def extract_title(html: bytes) -> Optional[str]:
    try:
        text = html.decode("utf-8", errors="ignore")
    except Exception:
        return None
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()

# -----------------------------
# Rate Limiter
# -----------------------------

class RateLimiter:
    """Simple token bucket limiter (global across tasks)."""

    def __init__(self, rate_per_sec: float):
        self.rate = float(rate_per_sec)
        self._tokens = self.rate
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        if self.rate <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.rate, self._tokens + elapsed * self.rate)
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                need = (1 - self._tokens) / self.rate
                await asyncio.sleep(max(need, 0.001))

# -----------------------------
# Data models
# -----------------------------

@dataclasses.dataclass
class RespFP:
    status: int
    length: int
    hash: str
    title: Optional[str]


@dataclasses.dataclass
class Finding:
    target: str
    variant: Dict[str, Any]
    method: str
    status: int
    length: int
    delta_pct: float
    confirmed: bool
    retries: int
    headers: Dict[str, str]
    chain: List[str]
    ts: str

# -----------------------------
# Bypass strategies
# -----------------------------

SAFE_HEADER_PAYLOADS = [
    ("X-Original-URL", "path"),
    ("X-Rewrite-URL", "path"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("Forwarded", "for=127.0.0.1;proto=https"),
]

EXTENDED_HEADER_PAYLOADS = [
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Host", "127.0.0.1"),
    ("X-Forwarded-Host", "127.0.0.1"),
]


def path_variants(path: str, mode: str) -> List[str]:
    """Generate path payload variants. mode in {safe, extended}."""
    if not path or path == "/":
        return []
    segs = path.rstrip("/").split("/")
    last = segs[-1] if segs else ""
    base = "/".join(segs[:-1])
    base = ("/" + base) if base and not base.startswith("/") else (base or "")

    safe_payloads = [
        f"%2e/{last}",
        f"{last}/.",
        f"./{last}/./",
        f"{last}%20/",
        f"/{last}//",
        f"{last}/",
    ]
    extended_payloads = [
        f"%20{last}%20/",
        f"{last}..;/",
        f"{last}?",
        f"{last}??",
        f"{last}/.randomstring",
    ]

    variants = safe_payloads[:]
    if mode == "extended":
        variants += extended_payloads

    # Stitch into full paths
    out = []
    for p in variants:
        if base.endswith("/"):
            out.append(base + p)
        elif base:
            out.append(base + "/" + p)
        else:
            out.append("/" + p.lstrip("/"))
    return out

# -----------------------------
# HTTP Engine
# -----------------------------

class Engine:
    def __init__(
        self,
        *,
        timeout: float,
        retries: int,
        limit_rps: float,
        jitter_ms: int,
        http2: bool,
        verbose: int,
        ua: Optional[str],
        no_color: bool,
    ):
        self.timeout = timeout
        self.retries = max(0, retries)
        self.limiter = RateLimiter(limit_rps)
        self.jitter_ms = max(0, jitter_ms)
        self.verbose = verbose
        self.ua = ua
        self.http2 = http2
        self.no_color = no_color
        limits = httpx.Limits(max_keepalive_connections=100, max_connections=100)
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            limits=limits,
            follow_redirects=True,
            http2=http2,
        )

    async def close(self):
        await self.client.aclose()

    async def request(self, method: str, url: str, headers: List[Tuple[str, str]]) -> httpx.Response:
        for attempt in range(self.retries + 1):
            try:
                await self.limiter.acquire()
                if self.jitter_ms:
                    await asyncio.sleep(random.uniform(0, self.jitter_ms) / 1000.0)
                hdict: Dict[str, str] = {}
                for k, v in headers:
                    hdict[k] = v
                if self.ua:
                    hdict.setdefault("User-Agent", self.ua)
                return await self.client.request(method, url, headers=hdict)
            except Exception as e:
                if attempt >= self.retries:
                    raise
                await asyncio.sleep(0.25 * (attempt + 1))

# -----------------------------
# Scanner
# -----------------------------

class Scanner:
    def __init__(
        self,
        engine: Engine,
        *,
        methods: List[str],
        status_allow: List[int],
        min_delta: float,
        confirm: int,
        title_check: bool,
        simhash: bool,  # placeholder flag
        max_variants: int,
        pretty: bool,
        output_file: Optional[str],
        verbose: int,
        color_enabled: bool,
    ):
        self.e = engine
        self.methods = methods
        self.status_allow = status_allow
        self.min_delta = min_delta
        self.confirm = max(0, confirm)
        self.title_check = title_check
        self.simhash = simhash
        self.max_variants = max_variants
        self.pretty = pretty
        self.out = open(output_file, "a", encoding="utf-8") if output_file else None
        self.verbose = verbose
        self.color_enabled = color_enabled

    def log(self, msg: str, level: int = 1):
        if self.verbose >= level:
            print(msg)

    async def get_baseline(self, url: str, base_headers: List[Tuple[str, str]]) -> Tuple[RespFP, str]:
        method = "GET" if "GET" in self.methods else self.methods[0]
        r = await self.e.request(method, url, base_headers)
        body = r.content or b""
        fp = RespFP(status=r.status_code, length=len(body), hash=blake2s(body), title=extract_title(body))
        return fp, method

    @staticmethod
    def build_url_with_path(url: str, new_path: str) -> str:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))

    @staticmethod
    def split_path(path: str) -> Tuple[str, str]:
        if not path or path == "/":
            return "", ""
        p = path.rstrip("/")
        base = p.rsplit("/", 1)[0] if "/" in p else ""
        last = p.rsplit("/", 1)[1] if "/" in p else p
        if base and not base.startswith("/"):
            base = "/" + base
        return base, last

    def allowed_hit(self, baseline: RespFP, resp: httpx.Response) -> Tuple[bool, float, Optional[str]]:
        body = resp.content or b""
        status_ok = resp.status_code in self.status_allow
        # Delta against baseline
        bl = max(baseline.length, 1)
        delta_pct = abs(len(body) - baseline.length) * 100.0 / float(bl)
        title = extract_title(body)
        # Title difference is informative; if enabled and same title, reduce confidence
        title_diff = (baseline.title or "") != (title or "") if self.title_check else True
        ok = status_ok and (delta_pct >= self.min_delta or title_diff or baseline.status != resp.status_code)
        return ok, delta_pct, title

    async def confirm_hit(self, method: str, url: str, headers: List[Tuple[str, str]], baseline: RespFP) -> Tuple[bool, httpx.Response, float, Optional[str]]:
        last_resp: Optional[httpx.Response] = None
        last_delta = 0.0
        last_title: Optional[str] = None
        for i in range(self.confirm):
            r = await self.e.request(method, url, headers)
            ok, delta, title = self.allowed_hit(baseline, r)
            last_resp, last_delta, last_title = r, delta, title
            if not ok:
                return False, r, delta, title
            await asyncio.sleep(0.05)
        return True, last_resp, last_delta, last_title

    def emit_finding(self, f: Finding):
        if self.pretty:
            status_col = color(str(f.status), "92" if f.status in (200, 204, 206) else "93", self.color_enabled)
            print(f"[HIT] {f.target}  ->  {status_col}  Δ{f.delta_pct:.1f}%  method={f.method}  variant={f.variant}")
        if self.out:
            self.out.write(json.dumps(dataclasses.asdict(f), ensure_ascii=False) + "\n")
            self.out.flush()

    async def scan_one(self, url: str, base_headers: List[Tuple[str, str]], *, paths_mode: str, enc_mode: str, method_tricks: str) -> None:
        self.log(f"[*] Baseline: {url}", 1)
        baseline, base_method = await self.get_baseline(url, base_headers)
        if baseline.status != 403:
            self.log(color(f"[!] Baseline status is {baseline.status}, not 403 — continuing anyway", "33", self.color_enabled), 1)

        # Build variants (prioritize cheap ones)
        parts = urlsplit(url)
        base, last = self.split_path(parts.path)
        # PATH variants
        path_payloads = path_variants(parts.path, paths_mode)

        # HEADER variants (safe/extended)
        header_payloads = SAFE_HEADER_PAYLOADS[:]
        if method_tricks in ("extended", "unsafe"):
            header_payloads += EXTENDED_HEADER_PAYLOADS

        # Method variants
        methods: List[str] = [m for m in self.methods]
        if method_tricks in ("extended", "unsafe") and "OPTIONS" not in methods:
            methods.append("OPTIONS")

        # Generate plan
        plan: List[Tuple[str, str, List[Tuple[str, str]], Dict[str, Any]]] = []

        # 1) PATH tricks (same headers, baseline method first)
        for p in path_payloads:
            new_url = self.build_url_with_path(url, p)
            plan.append((base_method, new_url, base_headers, {"type": "path", "payload": p}))

        # 2) HEADER tricks (may tweak path similar to original Jython logic)
        for hk, hv in header_payloads:
            new_headers = base_headers[:]
            # Handle special ones that need original path value
            if hk in ("X-Original-URL", "X-Rewrite-URL"):
                # Jython logic: X-Original-URL => append junk, X-Rewrite-URL => replace with "/"
                if hk == "X-Original-URL":
                    new_path = parts.path.rstrip("/") + "4nyth1ng"
                    new_url = self.build_url_with_path(url, new_path)
                    new_headers = new_headers + [(hk, parts.path)]
                else:  # X-Rewrite-URL
                    new_url = self.build_url_with_path(url, "/")
                    new_headers = new_headers + [(hk, parts.path)]
            else:
                new_url = url
                new_headers = new_headers + [(hk, hv)]
            plan.append((base_method, new_url, new_headers, {"type": "header", "key": hk, "value": hv}))

        # 3) Method flips (GET<->HEAD) on original URL
        if method_tricks != "off":
            if base_method == "GET" and "HEAD" in methods:
                plan.append(("HEAD", url, base_headers, {"type": "method", "from": "GET", "to": "HEAD"}))
            if base_method == "HEAD" and "GET" in methods:
                plan.append(("GET", url, base_headers, {"type": "method", "from": "HEAD", "to": "GET"}))

        # Cap variants if requested
        if self.max_variants > 0:
            plan = plan[: self.max_variants]

        # Execute plan sequentially (per target) for fewer FPs and easier throttling
        for idx, (method, tgt, hdrs, meta) in enumerate(plan, 1):
            self.log(f"[*] {idx}/{len(plan)} {method} {tgt} {meta}", 2)
            try:
                r = await self.e.request(method, tgt, hdrs)
            except Exception as e:
                self.log(color(f"[!] Request error: {e}", "31", self.color_enabled), 1)
                continue

            ok, delta, title = self.allowed_hit(baseline, r)
            if not ok:
                continue

            # Confirm
            confirmed, last_resp, cdelta, ctitle = await self.confirm_hit(method, tgt, hdrs, baseline)
            f = Finding(
                target=tgt,
                variant=meta,
                method=method,
                status=last_resp.status_code,
                length=len(last_resp.content or b""),
                delta_pct=cdelta,
                confirmed=confirmed,
                retries=self.e.retries,
                headers={k.lower(): v for k, v in last_resp.headers.items()},
                chain=["baseline", f"{meta}"],
                ts=now_iso(),
            )
            self.emit_finding(f)
            # Optional: short-circuit on confirmed hit? Keep exploring by default.

    async def run(self, targets: List[str], base_headers: List[Tuple[str, str]], *, paths_mode: str, enc_mode: str, method_tricks: str, workers: int):
        sem = asyncio.Semaphore(max(1, workers))

        async def worker(url: str):
            async with sem:
                try:
                    await self.scan_one(url, base_headers, paths_mode=paths_mode, enc_mode=enc_mode, method_tricks=method_tricks)
                except Exception as e:
                    self.log(color(f"[!] Error scanning {url}: {e}", "31", self.color_enabled), 0)

        await asyncio.gather(*(worker(u) for u in targets))

    def close(self):
        if self.out:
            self.out.close()

# -----------------------------
# CLI
# -----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="4or3",
        description="4or3 — Fast & Low-FP 403 Bypasser",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    req = p.add_argument_group("Target")
    req.add_argument("-u", "--url", help="Single target URL (e.g. https://site.tld/secret)")
    req.add_argument("-l", "--list", help="File with URLs (one per line)")

    hdr = p.add_argument_group("Headers")
    hdr.add_argument("-H", "--header", action="append", default=[], help="Add header, e.g. -H 'X-Intigriti-Username: you@intigriti.me' (repeatable)")
    hdr.add_argument("--header-set", choices=["none", "cdn", "reverseproxy"], default="none", help="Built-in header set to include")
    hdr.add_argument("--ua", help="Custom User-Agent")

    strat = p.add_argument_group("Strategies")
    strat.add_argument("--paths", choices=["safe", "extended"], default="safe", help="Path tricks to try (default: safe)")
    strat.add_argument("--encodings", choices=["light", "extended", "off"], default="light", help="Encoding strategies (placeholder switch)")
    strat.add_argument("--method-tricks", choices=["off", "safe", "extended", "unsafe"], default="safe", help="HTTP method variations (default: safe)")
    strat.add_argument("--max-variants", type=int, default=0, help="Cap the number of variants per target (0 = no cap)")

    det = p.add_argument_group("Detection & FP control")
    det.add_argument("--status-allow", default="200,204,206,301,302,307,308", help="Comma list of status codes considered potential bypass")
    det.add_argument("--min-delta", type=float, default=15.0, help="Min %% body length delta vs baseline to consider different (default: 15)")
    det.add_argument("--title-check", action="store_true", help="Compare <title> differences to reduce FPs")
    det.add_argument("--confirm", type=int, default=2, help="Confirmation requests for hits (default: 2)")
    det.add_argument("--simhash", action="store_true", help="Enable lightweight body-similarity heuristic (placeholder)")

    net = p.add_argument_group("Networking")
    net.add_argument("--methods", default="GET,HEAD", help="HTTP methods to use (comma). Default: GET,HEAD")
    net.add_argument("--timeout", type=float, default=10.0, help="Request timeout (seconds)")
    net.add_argument("--retries", type=int, default=1, help="Retries on network errors (default: 1)")
    net.add_argument("--limit-rps", type=float, default=0.0, help="Global rate limit (requests per second); 0 disables")
    net.add_argument("--jitter", type=int, default=0, help="Random delay jitter in milliseconds")
    net.add_argument("--http2", action="store_true", help="Enable HTTP/2 if supported by server")
    net.add_argument("--workers", type=int, default=16, help="Concurrent targets (default: 16)")

    io = p.add_argument_group("Output")
    io.add_argument("-o", "--output", help="Write JSONL results to file")
    io.add_argument("--pretty", action="store_true", help="Pretty console output")
    io.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    io.add_argument("-v", "--verbose", action="count", default=0, help="Verbose logging; repeat for more detail")

    p.add_argument("--dry-run", action="store_true", help="Show what would be sent; do not send requests")
    p.add_argument("--version", action="version", version=f"4or3 {__VERSION__}")

    return p


def build_targets(args: argparse.Namespace) -> List[str]:
    urls: List[str] = []
    if args.url:
        urls.append(args.url.strip())
    if args.list:
        with open(args.list, "r", encoding="utf-8") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#"):
                    urls.append(s)
    if not urls:
        raise SystemExit("No targets provided. Use -u or -l.")
    return urls


def build_headers(args: argparse.Namespace) -> List[Tuple[str, str]]:
    headers: List[Tuple[str, str]] = []
    # header set presets
    if args.header_set == "cdn":
        headers += [("X-Forwarded-For", "127.0.0.1"), ("X-Real-IP", "127.0.0.1")]
    elif args.header_set == "reverseproxy":
        headers += [("Forwarded", "for=127.0.0.1;proto=https"), ("X-Forwarded-Proto", "https")]

    for h in args.header or []:
        k, v = parse_header_kv(h)
        headers.append((k, v))
    return headers


async def main_async(args: argparse.Namespace) -> int:
    if args.dry_run:
        print("[*] Dry run: no requests will be sent.")

    color_enabled = not args.no_color and sys.stdout.isatty()

    methods = [m.strip().upper() for m in (args.methods or "").split(",") if m.strip()]
    if not methods:
        methods = ["GET", "HEAD"]

    status_allow = []
    for s in (args.status_allow or "").split(","):
        s = s.strip()
        if s:
            with contextlib.suppress(ValueError):
                status_allow.append(int(s))
    if not status_allow:
        status_allow = [200, 204, 206, 301, 302, 307, 308]

    headers = build_headers(args)
    targets = build_targets(args)

    engine = Engine(
        timeout=args.timeout,
        retries=args.retries,
        limit_rps=args.limit_rps,
        jitter_ms=args.jitter,
        http2=args.http2,
        verbose=args.verbose,
        ua=args.ua,
        no_color=args.no_color,
    )

    if args.dry_run:
        print("[*] Targets:")
        for u in targets:
            print("    ", u)
        print("[*] Base headers:")
        for k, v in headers:
            print(f"     - {k}: {v}")
        print("[*] Methods:", methods)
        print("[*] Paths mode:", args.paths, ", Encodings:", args.encodings, ", Method tricks:", args.method_tricks)
        await engine.close()
        return 0

    scanner = Scanner(
        engine,
        methods=methods,
        status_allow=status_allow,
        min_delta=args.min_delta,
        confirm=args.confirm,
        title_check=args.title_check,
        simhash=args.simhash,
        max_variants=args.max_variants,
        pretty=args.pretty,
        output_file=args.output,
        verbose=args.verbose,
        color_enabled=color_enabled,
    )

    try:
        await scanner.run(
            targets,
            headers,
            paths_mode=args.paths,
            enc_mode=args.encodings,
            method_tricks=args.method_tricks,
            workers=args.workers,
        )
    finally:
        scanner.close()
        await engine.close()

    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())