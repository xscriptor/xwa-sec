from urllib.parse import urlparse


def normalize_target_domain(target: str) -> str:
    stripped = target.strip()
    if not stripped:
        return ""

    if "://" not in stripped:
        return stripped.split("/")[0].strip().lower()

    parsed = urlparse(stripped)
    return (parsed.netloc or parsed.path).split("/")[0].strip().lower()


def ensure_base_url(target: str) -> str:
    stripped = target.strip()
    if not stripped:
        return ""

    if stripped.startswith("http://") or stripped.startswith("https://"):
        return stripped

    return f"https://{normalize_target_domain(stripped)}"
