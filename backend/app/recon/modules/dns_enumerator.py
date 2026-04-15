import asyncio
from typing import Dict, List

import dns.exception
import dns.resolver

from ..target import normalize_target_domain
from ..types import LogCallback


DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


async def run(target: str, log: LogCallback) -> Dict[str, List[str]]:
    domain = normalize_target_domain(target)
    results: Dict[str, List[str]] = {record_type: [] for record_type in DNS_TYPES}

    resolver = dns.resolver.Resolver()
    resolver.cache = None  # Disable cache for fresh lookups
    resolver.timeout = 3
    resolver.lifetime = 3

    for record_type in DNS_TYPES:
        try:
            await log(f"[dns] querying {record_type} for {domain}")
            query = await asyncio.to_thread(resolver.resolve, domain, record_type)
            for rdata in query:
                value = str(rdata)
                results[record_type].append(value)
                await log(f"  ok {record_type}: {value}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            await log(f"  miss {record_type}: no record")
        except Exception as exc:
            await log(f"  fail {record_type}: {str(exc)[:80]}")

    return results
