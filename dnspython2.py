#!/usr/bin/env python3
import sys
import dns.resolver
import dns.message
import dns.query
import dns.exception
import re
import requests
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b
    "192.33.4.12",     # c
    "199.7.91.13",     # d
    "192.203.230.10",  # e
    "192.5.5.241",     # f
    "192.112.36.4",    # g
    "198.97.190.53",   # h
    "192.36.148.17",   # i
    "192.58.128.30",   # j
    "193.0.14.129",    # k
    "199.7.83.42",     # l
    "202.12.27.33"     # m
]

# Liste de tous les types DNS à interroger
ALL_RECORD_TYPES = [
    "A", "AAAA", "MX", "NS", "TXT",
    "CNAME", "SOA", "SRV", "CAA", "PTR"
]

# Regex pour le parsing des TXT
IPV4_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
IPV6_REGEX = r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
DOMAIN_REGEX = r"\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

STATIC_TLD_LIST = [
    "fr",
    "gouv.fr",
    "com",
    "net",
    "org",
    "info",
    "biz"
]

#Public Suffix List pour mise à jour dynamique
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

KNOWN_SRV_SERVICES = [
    # Messagerie / VoIP
    ("_sip", "_tcp"),
    ("_sip", "_udp"),
    ("_sips", "_tcp"),
    ("_xmpp-client", "_tcp"),
    ("_xmpp-server", "_tcp"),
    ("_jabber", "_tcp"),
    ("_imaps", "_tcp"),
    ("_submission", "_tcp"),

    # Annuaire / Auth
    ("_ldap", "_tcp"),
    ("_ldaps", "_tcp"),
    ("_kerberos", "_tcp"),
    ("_kerberos", "_udp"),
    ("_kpasswd", "_tcp"),
    ("_kpasswd", "_udp"),

    # Microsoft / Enterprise
    ("_sipinternal", "_tcp"),
    ("_sipinternaltls", "_tcp"),
    ("_sipfederationtls", "_tcp"),
    ("_autodiscover", "_tcp"),
    ("_msrpc", "_tcp"),
    ("_gc", "_tcp"),
    ("_gc", "_tcp"),

    # Web / Infra
    ("_http", "_tcp"),
    ("_https", "_tcp"),
    ("_ftp", "_tcp"),
    ("_ftps", "_tcp"),

    # Database
    ("_mysql", "_tcp"),
    ("_postgresql", "_tcp"),
    ("_mongodb", "_tcp"),

    # Autres
    ("_ntp", "_udp"),
    ("_dns", "_udp"),
    ("_dns", "_tcp"),
]


def pretty_banner(title: str):
    console.rule(f"[bold blue]{title}[/bold blue]")


def resolve_record(domain: str, record_type: str):
    """Résolution standard (récursive)."""
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, record_type)
        return answers
    except Exception as e:
        console.print(f"[red]Erreur lors de la résolution {record_type}: {e}[/red]")
        return None


def follow_cname(domain: str):
    """Suit la chaîne CNAME complète."""
    chain = []
    resolver = dns.resolver.Resolver()

    while True:
        try:
            ans = resolver.resolve(domain, "CNAME")
            target = ans[0].target.to_text()
            chain.append((domain, target))
            domain = target.rstrip(".")
        except dns.resolver.NoAnswer:
            break
        except Exception:
            break

    return chain


def iterative_resolution(domain: str):
    """Démonstration d'une résolution itérative simplifiée depuis les root servers."""
    pretty_banner("Résolution itérative (depuis les serveurs racine)")

    query = dns.message.make_query(domain, dns.rdatatype.A)

    for root in ROOT_SERVERS:
        console.print(f"[yellow]Interrogation du serveur racine {root}[/yellow]")

        try:
            response = dns.query.udp(query, root, timeout=2.0)

            ns_records = []
            for rr in response.additional:
                if rr.rdtype == dns.rdatatype.A:
                    ns_records.append(rr.items[0].address)

            if ns_records:
                console.print(f"→ Serveurs DNS trouvés : {ns_records}")
                return
        except Exception:
            continue

    console.print("[red]Impossible de continuer la résolution itérative (simplifiée).[/red]")


def parse_txt_generic(txt: str):
    """Parse générique pour trouver IP et domaines."""
    ipv4 = re.findall(IPV4_REGEX, txt)
    ipv6 = re.findall(IPV6_REGEX, txt)
    domains = re.findall(DOMAIN_REGEX, txt)

    return {
        "ipv4": set(ipv4),
        "ipv6": set(ipv6),
        "domains": set(domains)
    }


def parse_spf(txt: str):
    """Parse spécialisé SPF."""
    ips = []
    domains = []

    parts = txt.split()

    for part in parts:
        if part.startswith("ip4:") or part.startswith("ip6:"):
            ips.append(part.split(":", 1)[1])
        elif part.startswith("include:"):
            domains.append(part.split(":", 1)[1])

    return {
        "ips": ips,
        "domains": domains
    }


def parse_dmarc(txt: str):
    """Parse spécialisé DMARC."""
    domains = []

    fields = txt.split(";")
    for field in fields:
        field = field.strip()
        if field.startswith("rua=") or field.startswith("ruf="):
            value = field.split("=", 1)[1]
            domains.extend(re.findall(DOMAIN_REGEX, value))

    return {
        "domains": domains
    }


def parse_txt_record(txt: str):
    """Choisit le bon parseur TXT."""
    txt = txt.strip('"')
    txt_lower = txt.lower()

    if txt_lower.startswith("v=spf1"):
        return ("SPF", parse_spf(txt))

    if txt_lower.startswith("v=dmarc1"):
        return ("DMARC", parse_dmarc(txt))

    return ("GENERIC", parse_txt_generic(txt))


def format_parsed_txt(parsed_type: str, parsed_data: dict) -> str:
    """Formate proprement les résultats TXT pour l'affichage."""
    lines = []

    if parsed_type != "GENERIC":
        lines.append(f"[bold]{parsed_type}[/bold]")

    if "ips" in parsed_data and parsed_data["ips"]:
        lines.append("IPs :")
        for ip in parsed_data["ips"]:
            lines.append(f"  • {ip}")

    if "ipv4" in parsed_data and parsed_data["ipv4"]:
        lines.append("IPv4 :")
        for ip in parsed_data["ipv4"]:
            lines.append(f"  • {ip}")

    if "ipv6" in parsed_data and parsed_data["ipv6"]:
        lines.append("IPv6 :")
        for ip in parsed_data["ipv6"]:
            lines.append(f"  • {ip}")

    if "domains" in parsed_data and parsed_data["domains"]:
        lines.append("Domains :")
        for domain in parsed_data["domains"]:
            lines.append(f"  • {domain}")

    if not lines:
        return "No relevant data found"

    return "\n".join(lines)


def fetch_psl() -> list:
    """Télécharge et parse la public suffix list."""
    response = requests.get(PSL_URL, timeout=5)
    response.raise_for_status()

    tlds = []
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        tlds.append(line.lower())

    return tlds


def find_matching_tld(domain: str, tld_list: list) -> str | None:
    """Retourne le TLD le plus long qui correspond au domaine."""
    domain = domain.lower()

    matching = []
    for tld in tld_list:
        if domain.endswith("." + tld) or domain == tld:
            matching.append(tld)

    if not matching:
        return None

    # On prend le TLD le plus spécifique (le plus long)
    return max(matching, key=len)


def crawl_to_tld(domain: str, tld_list: list) -> list:
    """Déduit les domaines parents jusqu'au TLD (exclu)."""
    domain = domain.strip(".").lower()
    labels = domain.split(".")

    tld = find_matching_tld(domain, tld_list)
    if not tld:
        return []

    tld_parts = tld.split(".")
    stop_index = len(labels) - len(tld_parts)

    parents = []
    for i in range(1, stop_index):
        parent = ".".join(labels[i:])
        parents.append(parent)

    return parents


def scan_srv_records(domain: str):
    """Teste les services SRV connus pour un domaine."""
    pretty_banner("Scan des enregistrements SRV")

    resolver = dns.resolver.Resolver()
    found = []

    for service, proto in KNOWN_SRV_SERVICES:
        name = f"{service}.{proto}.{domain}"

        try:
            answers = resolver.resolve(name, "SRV")
            for r in answers:
                found.append({
                    "service": f"{service}.{proto}",
                    "priority": r.priority,
                    "weight": r.weight,
                    "port": r.port,
                    "target": r.target.to_text().rstrip(".")
                })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except Exception:
            continue

    return found


def reverse_dns(ip: str):
    """Résolution reverse DNS (PTR) d'une adresse IP."""
    try:
        result = dns.resolver.resolve_address(ip)
        return [r.to_text().rstrip(".") for r in result]
    except Exception:
        return []


def reverse_dns_from_domain(domain: str):
    pretty_banner("Reverse DNS")

    try:
        answers = dns.resolver.resolve(domain, "A")
    except Exception:
        console.print("[red]Impossible de résoudre le domaine en IP.[/red]")
        return

    table = Table(box=box.SIMPLE)
    table.add_column("IP")
    table.add_column("Reverse DNS (PTR)")

    for r in answers:
        ip = r.to_text()
        ptrs = reverse_dns(ip)

        if ptrs:
            for ptr in ptrs:
                table.add_row(ip, ptr)
        else:
            table.add_row(ip, "[grey]Aucun PTR[/grey]")

    console.print(table)


def display_parent_domains(domain: str, parents: list, tld: str):
    pretty_banner("Cartographie des domaines parents")

    if not parents:
        console.print("[yellow]Aucun domaine parent trouvé.[/yellow]")
        return

    table = Table(box=box.SIMPLE)
    table.add_column("Niveau")
    table.add_column("Domaine")

    for i, parent  in enumerate (parents, start=1):
        table.add_row(str(i), parent)

    console.print(f"[bold]TLD détecté :[/bold] {tld}")
    console.print(table)



def display_srv_results(results: list):
    if not results:
        console.print("[yellow]Aucun service SRV trouvé.[/yellow]")
        return

    table = Table(box=box.SIMPLE)
    table.add_column("Service")
    table.add_column("Priority")
    table.add_column("Weight")
    table.add_column("Port")
    table.add_column("Target")

    for r in results:
        table.add_row(
            r["service"],
            str(r["priority"]),
            str(r["weight"]),
            str(r["port"]),
            r["target"]
        )

    console.print(table)


def display_results(domain: str, record_type: str, answers):
    """Affiche les résultats DNS sous forme de tableau."""
    pretty_banner(f"Résultats : {domain} ({record_type})")

    table = Table(box=box.SIMPLE, show_lines=True)
    table.add_column("Type")
    table.add_column("Résultat")

    if answers is None:
        table.add_row(record_type, "Aucun résultat")
        console.print(table)
        return

    for r in answers:
        if record_type == "TXT":
           parsed_type, parsed_data = parse_txt_record(r.to_text())

           formatted = format_parsed_txt(parsed_type, parsed_data)

           table.add_row(
               f"TXT ({parsed_type})",
               f"{r.to_text()}\n\n{formatted}"
           )

        else:
           table.add_row(record_type, r.to_text())

    console.print(table)


def resolve_all_records(domain: str):
    """Résout absolument tous les types DNS définis dans ALL_RECORD_TYPES."""
    pretty_banner(f"Toutes les entrées DNS pour {domain}")

    for rtype in ALL_RECORD_TYPES:
        console.print(f"[cyan]→ Résolution {rtype}[/cyan]")
        answers = resolve_record(domain, rtype)
        display_results(domain, rtype, answers)

def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage: python dns_explorer.py <domaine> [type|ALL][/red]")
        sys.exit(1)

    domain = sys.argv[1]
    record_type = sys.argv[2].upper() if len(sys.argv) > 2 else "A"

    pretty_banner("Explorateur DNS Amélioré")

    # Chargement de la liste des TLD
    try:
        TLD_LIST = fetch_psl()
        console.print("[green]Public Suffix List trouvée.[/green]")
    except Exception:
        console.print("[yellow]Impossible de trouver la PSL, utilisation de la liste statique.[/yellow]")
        TLD_LIST = STATIC_TLD_LIST

    # Crawl vers le TLD
    tld = find_matching_tld(domain, TLD_LIST)
    parents = crawl_to_tld(domain, TLD_LIST)

    display_parent_domains(domain, parents, tld)

    # Chaîne CNAME
    cname_chain = follow_cname(domain)
    if cname_chain:
        table = Table(title="Chaîne CNAME", box=box.SIMPLE)
        table.add_column("Alias")
        table.add_column("Cible")
        for alias, target in cname_chain:
            table.add_row(alias, target)
        console.print(table)

    # Résolution des types DNS
    if record_type == "ALL":
        resolve_all_records(domain)
    else:
        answers = resolve_record(domain, record_type)
        display_results(domain, record_type, answers)

    # Démonstration itérative
    iterative_resolution(domain)

    # Scan SRV
    srv_results = scan_srv_records(domain)
    display_srv_results(srv_results)

    # Reverse DNS
    reverse_dns_from_domain(domain)

if __name__ == "__main__":
    main()