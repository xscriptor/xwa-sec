import asyncio
from typing import Dict, List, Set

import dns.resolver
import httpx
import tldextract

from ..target import normalize_target_domain
from ..types import LogCallback


COMMON_PREFIXES = ["www", "api", "app", "admin", "dev", "staging", "beta", "docs", "cdn", "static"]
MAX_DISCOVERED_HOSTS = 200


def _registrable_domain(host: str) -> str:
    extracted = tldextract.extract(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return host.lower()


def _sanitize_host(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    return candidate


async def run(target: str, log: LogCallback) -> Dict[str, object]:
    target_host = normalize_target_domain(target)
    domain = _registrable_domain(target_host)
    discovered: Set[str] = set()

    await log(f"[subdomains] querying certificate transparency logs for {domain} (target={target_host})")

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            response = await client.get(url)
            if response.status_code == 200:
                entries = response.json()
                for cert in entries:
                    names = cert.get("name_value", "").split("\n")
                    for name in names:
                        candidate = _sanitize_host(name)
                        if candidate.endswith(f".{domain}"):
                            discovered.add(candidate)
    except Exception as exc:
        await log(f"  fail ct logs: {str(exc)[:80]}")

    probe_candidates = set(discovered)
    if not probe_candidates:
        await log("  no ct entries returned, probing common prefixes")
        probe_candidates = {f"{prefix}.{domain}" for prefix in COMMON_PREFIXES}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    active: Dict[str, List[str]] = {}
    for subdomain in sorted(probe_candidates):
        resolved_ips: Set[str] = set()
        for record_type in ("A", "AAAA"):
            try:
                query = await asyncio.to_thread(resolver.resolve, subdomain, record_type)
                resolved_ips.update(str(rdata) for rdata in query)
            except Exception:
                continue

        if resolved_ips:
            ip_list = sorted(resolved_ips)
            active[subdomain] = ip_list
            discovered.add(subdomain)
            await log(f"  ok {subdomain}: {', '.join(ip_list)}")

    discovered_hosts = sorted(discovered)
    active_count = len(active)
    discovered_count = len(discovered_hosts)

    await log(f"[subdomains] active={active_count} discovered={discovered_count}")
    return {
        "total_found": discovered_count,
        "active": active,
        "active_count": active_count,
        "discovered_count": discovered_count,
        "discovered_hosts": discovered_hosts[:MAX_DISCOVERED_HOSTS],
    }
