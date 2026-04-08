#!/usr/bin/env python3
import sys
import argparse
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

# To ensure complete DNS information discovery
ALL_RECORD_TYPES = [
    "A", "AAAA", "MX", "NS", "TXT",
    "CNAME", "SOA", "SRV", "CAA", "PTR"
]

# To extract structured data from free-form text records
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

# To keep TLD list up-to-date without code changes
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

KNOWN_SRV_SERVICES = [
    # To discover messaging and communication services
    ("_sip", "_tcp"),
    ("_sip", "_udp"),
    ("_sips", "_tcp"),
    ("_xmpp-client", "_tcp"),
    ("_xmpp-server", "_tcp"),
    ("_jabber", "_tcp"),
    ("_imaps", "_tcp"),
    ("_submission", "_tcp"),

    # To find authentication and directory services
    ("_ldap", "_tcp"),
    ("_ldaps", "_tcp"),
    ("_kerberos", "_tcp"),
    ("_kerberos", "_udp"),
    ("_kpasswd", "_tcp"),
    ("_kpasswd", "_udp"),

    # To detect Microsoft enterprise infrastructure
    ("_sipinternal", "_tcp"),
    ("_sipinternaltls", "_tcp"),
    ("_sipfederationtls", "_tcp"),
    ("_autodiscover", "_tcp"),
    ("_msrpc", "_tcp"),
    ("_gc", "_tcp"),

    # To identify web and file transfer services
    ("_http", "_tcp"),
    ("_https", "_tcp"),
    ("_ftp", "_tcp"),
    ("_ftps", "_tcp"),

    # To locate database servers
    ("_mysql", "_tcp"),
    ("_postgresql", "_tcp"),
    ("_mongodb", "_tcp"),

    # To find infrastructure services
    ("_ntp", "_udp"),
    ("_dns", "_udp"),
    ("_dns", "_tcp"),
]


def pretty_banner(title: str):
    console.rule(f"[bold blue]{title}[/bold blue]")


def resolve_record(domain: str, record_type: str):
    """Standard recursive DNS resolution."""
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, record_type)
        return answers
    except Exception as e:
        console.print(f"[red]Error resolving {record_type}: {e}[/red]")
        return None


def follow_cname(domain: str):
    """Follow complete CNAME chain."""
    chain = []
    resolver = dns.resolver.Resolver()

    # We keep track of already visited domains
    already_seen = set()
    already_seen.add(domain)

    while True:
        try:
            ans = resolver.resolve(domain, "CNAME")
            target = ans[0].target.to_text()
            target_clean = target.rstrip(".")

            if target_clean in already_seen:
                console.print(f"[red]⚠ Infinite CNAME loop detected: {target_clean} already visited, stopping.[/red]")
                break

            chain.append((domain, target))
            already_seen.add(target_clean)
            domain = target_clean

        except dns.resolver.NoAnswer:
            break
        except Exception:
            break

    return chain


def iterative_resolution(domain: str):
    """Simplified iterative resolution demonstration from root servers."""
    pretty_banner("Iterative resolution (from root servers)")

    current_server = ROOT_SERVERS[0]
    console.print(f"[yellow]Starting with root server: {current_server}[/yellow]")

    for step_number in range(3):
        console.print(f"\n--- Step {step_number + 1} ---")

        query = dns.message.make_query(domain, dns.rdatatype.A)

        try:
            response = dns.query.udp(query, current_server, timeout=2.0)

            if response.answer:
                console.print("[green]✓ FINAL ANSWER FOUND![/green]")
                console.print(f"Result: {response.answer[0]}")
                return

            console.print("Not yet the answer, looking for next server...")

            next_server_found = False

            for record in response.additional:
                if record.rdtype == dns.rdatatype.A:
                    for item in record:
                        current_server = item.address
                        console.print(f"→ Next server: {current_server}")
                        next_server_found = True
                        break
                if next_server_found:
                    break

            if not next_server_found:
                console.print("[red]No next server found, stopping.[/red]")
                return

        except Exception as error:
            console.print(f"[red]Error: {error}[/red]")
            return

    console.print("[yellow]Maximum of 3 steps reached, stopping.[/yellow]")


def parse_txt_generic(txt: str):
    """Generic parser to find IPs and domains."""
    ipv4 = re.findall(IPV4_REGEX, txt)
    ipv6 = re.findall(IPV6_REGEX, txt)
    domains = re.findall(DOMAIN_REGEX, txt)

    return {
        "ipv4": set(ipv4),
        "ipv6": set(ipv6),
        "domains": set(domains)
    }


def parse_spf(txt: str):
    """Specialized SPF parser."""
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
    """Specialized DMARC parser."""
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
    """Choose the appropriate TXT parser."""
    txt = txt.strip('"')
    txt_lower = txt.lower()

    if txt_lower.startswith("v=spf1"):
        return ("SPF", parse_spf(txt))

    if txt_lower.startswith("v=dmarc1"):
        return ("DMARC", parse_dmarc(txt))

    return ("GENERIC", parse_txt_generic(txt))


def format_parsed_txt(parsed_type: str, parsed_data: dict) -> str:
    """Format TXT results for display."""
    lines = []

    if parsed_type != "GENERIC":
        lines.append(f"[bold]{parsed_type}[/bold]")

    if "ips" in parsed_data and parsed_data["ips"]:
        lines.append("IPs:")
        for ip in parsed_data["ips"]:
            lines.append(f"  • {ip}")

    if "ipv4" in parsed_data and parsed_data["ipv4"]:
        lines.append("IPv4:")
        for ip in parsed_data["ipv4"]:
            lines.append(f"  • {ip}")

    if "ipv6" in parsed_data and parsed_data["ipv6"]:
        lines.append("IPv6:")
        for ip in parsed_data["ipv6"]:
            lines.append(f"  • {ip}")

    if "domains" in parsed_data and parsed_data["domains"]:
        lines.append("Domains:")
        for domain in parsed_data["domains"]:
            lines.append(f"  • {domain}")

    if not lines:
        return "No relevant data found"

    return "\n".join(lines)


def fetch_psl() -> list:
    """Download and parse the public suffix list."""
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
    """Return the longest matching TLD for the domain."""
    domain = domain.lower()

    matching = []
    for tld in tld_list:
        if domain.endswith("." + tld) or domain == tld:
            matching.append(tld)

    if not matching:
        return None

    # To handle complex TLDs like .co.uk correctly
    return max(matching, key=len)


def crawl_to_tld(domain: str, tld_list: list) -> list:
    """Derive parent domains up to the TLD (excluded)."""
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
    """Test known SRV services for a domain."""
    pretty_banner("SRV Records Scan")

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
    """Reverse DNS (PTR) resolution of an IP address."""
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
        console.print("[red]Unable to resolve domain to IP.[/red]")
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
            table.add_row(ip, "[grey]No PTR[/grey]")

    console.print(table)


def display_parent_domains(domain: str, parents: list, tld: str):
    pretty_banner("Parent Domains Mapping")

    if not parents:
        console.print("[yellow]No parent domains found.[/yellow]")
        return

    table = Table(box=box.SIMPLE)
    table.add_column("Level")
    table.add_column("Domain")

    for i, parent  in enumerate (parents, start=1):
        table.add_row(str(i), parent)

    console.print(f"[bold]Detected TLD:[/bold] {tld}")
    console.print(table)



def display_srv_results(results: list):
    if not results:
        console.print("[yellow]No SRV services found.[/yellow]")
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
    """Display DNS results as a table."""
    pretty_banner(f"Results: {domain} ({record_type})")

    table = Table(box=box.SIMPLE, show_lines=True)
    table.add_column("Type")
    table.add_column("Result")

    if answers is None:
        table.add_row(record_type, "No result")
        console.print(table)
        return

    answers_list = list(answers)

    if not answers_list:
        table.add_row(record_type, "No result")
        console.print(table)
        return

    for r in answers_list:
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
    """Resolve all DNS types defined in ALL_RECORD_TYPES."""
    pretty_banner(f"All DNS entries for {domain}")

    for rtype in ALL_RECORD_TYPES:
        console.print(f"[cyan]→ Resolving {rtype}[/cyan]")
        answers = resolve_record(domain, rtype)
        display_results(domain, rtype, answers)

def main():
    parser = argparse.ArgumentParser(description="Advanced DNS Explorer")
    parser.add_argument("domain", help="Domain name to query")
    parser.add_argument("--type", default="A", help="DNS record type (default: A)")

    args = parser.parse_args()

    domain = args.domain
    record_type = args.type.upper()

    pretty_banner("Advanced DNS Explorer")

    # To accurately identify domain boundaries
    try:
        TLD_LIST = fetch_psl()
        console.print("[green]Public Suffix List found.[/green]")
    except Exception:
        console.print("[yellow]Unable to fetch PSL, using static list.[/yellow]")
        TLD_LIST = STATIC_TLD_LIST

    # To show domain hierarchy structure
    tld = find_matching_tld(domain, TLD_LIST)
    parents = crawl_to_tld(domain, TLD_LIST)

    display_parent_domains(domain, parents, tld)

    # To follow redirect chains
    cname_chain = follow_cname(domain)
    if cname_chain:
        table = Table(title="CNAME Chain", box=box.SIMPLE)
        table.add_column("Alias")
        table.add_column("Target")
        for alias, target in cname_chain:
            table.add_row(alias, target)
        console.print(table)

    # To resolve requested DNS record types
    if record_type == "ALL":
        resolve_all_records(domain)
    else:
        answers = resolve_record(domain, record_type)
        display_results(domain, record_type, answers)

    # To demonstrate how DNS works internally
    iterative_resolution(domain)

    # To discover available network services
    srv_results = scan_srv_records(domain)
    display_srv_results(srv_results)

    # To identify server hostnames
    reverse_dns_from_domain(domain)

if __name__ == "__main__":
    main()