import subprocess
import ipaddress
from typing import List, Dict, Any, Set
import logging

logging.basicConfig(level=logging.INFO)


# -------------------------------
# Получаем список ASN по ORG
# -------------------------------
def get_asns_by_org(org_id: str) -> List[str]:
    try:
        result = subprocess.run(
            ["wsl", "whois", "-h", "whois.ripe.net", "-T", "aut-num", "-i", "org", org_id],
            capture_output=True, text=True, timeout=60, check=True
        )
    except subprocess.SubprocessError as e:
        logging.error("Ошибка при получении ASN: %s", e)
        return []

    asns = []
    for line in result.stdout.splitlines():
        if line.startswith("aut-num:"):
            parts = line.split()
            if len(parts) > 1:
                asns.append(parts[1])
    return sorted(asns)


# -------------------------------
# Получаем org-name по ASN
# -------------------------------
def get_org_name_by_asn(asn: str) -> str:
    try:
        result = subprocess.run(
            ["wsl", "whois", "-h", "whois.ripe.net", asn],
            capture_output=True, text=True, timeout=60, check=True
        )
    except subprocess.SubprocessError as e:
        logging.error("Ошибка при получении org-name для %s: %s", asn, e)
        return ""

    for line in result.stdout.splitlines():
        if line.startswith("org-name:"):
            return line.split("org-name:")[1].strip()
    return ""


# -------------------------------
# Получаем префиксы по ASN через RADB
# -------------------------------
def get_prefixes_by_asn_radb(asn: str) -> Set[str]:
    try:
        result = subprocess.run(
            ["whois", "-h", "whois.radb.net", "-i", "origin", asn],
            capture_output=True, text=True, timeout=60, check=True
        )
    except subprocess.SubprocessError as e:
        logging.error("Ошибка при получении префиксов для %s: %s", asn, e)
        return set()

    prefixes = set()
    for line in result.stdout.splitlines():
        if line.startswith(("route:", "route6:")):
            parts = line.split()
            if len(parts) > 1:
                prefixes.add(parts[1])
    return prefixes


# -------------------------------
# Суммаризация префиксов
# -------------------------------
def summarize_prefixes(prefixes: Set[str]) -> List[ipaddress._BaseNetwork]:
    v4, v6 = [], []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
            (v6 if net.version == 6 else v4).append(net)
        except ValueError:
            logging.warning("Неверный префикс: %s", p)
    result = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
    return sorted(result)


# -------------------------------
# Главная функция
# -------------------------------
def get_provider_prefixes(org_id: str) -> List[Dict[str, Any]]:
    result = []
    logging.info("Сбор ASN для ORG: %s", org_id)
    asns = get_asns_by_org(org_id)
    logging.info("Найдено ASN: %s", asns)

    for asn in asns:
        logging.info("Обработка %s", asn)
        org_name = get_org_name_by_asn(asn)
        prefixes = get_prefixes_by_asn_radb(asn)
        summarized = summarize_prefixes(prefixes)
        result.append({
            "asn": asn,
            "org_name": org_name,
            "prefixes": summarized
        })
    return result


if __name__ == "__main__":
    provider_data = get_provider_prefixes("ORG-ES15-RIPE")
    '''provider_data = get_asns_by_org("ORG-ES15-RIPE")'''

    for entry in provider_data:
        '''print(f"{entry['asn']} - {entry['org_name']}")'''
        print(entry)
