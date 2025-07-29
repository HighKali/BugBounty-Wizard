#!/usr/bin/env python3
"""
BugBounty Wizard - MultiTarget Edition
Potente, semplice, perfetto per bug bounty: ora con RECON MULTITARGET!
- Inserisci una keyword (es. GOOGLE): trova decine di domini reali associati e li analizza in automatico.
- OSINT, subdomain, port scan, fingerprint, quick OWASP check su tutti i domini trovati.
- Report aggregato e pronto per bug bounty.
"""

import os
import sys
import socket
import requests
import json
import time
import threading
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

ASCII = f"""{Fore.MAGENTA}
██████╗ ██╗   ██╗ ██████╗ ██████╗     ██████╗ ██╗   ██╗    ██╗    ██╗██╗███████╗██████╗ 
██╔══██╗██║   ██║██╔═══██╗██╔══██╗    ██╔══██╗██║   ██║    ██║    ██║██║██╔════╝██╔══██╗
██████╔╝██║   ██║██║   ██║██████╔╝    ██████╔╝██║   ██║    ██║ █╗ ██║██║█████╗  ██████╔╝
██╔═══╝ ██║   ██║██║   ██║██╔═══╝     ██╔═══╝ ██║   ██║    ██║███╗██║██║██╔══╝  ██╔══██╗
██║     ╚██████╔╝╚██████╔╝██║         ██║     ╚██████╔╝    ╚███╔███╔╝██║███████╗██║  ██║
╚═╝      ╚═════╝  ╚═════╝ ╚═╝         ╚═╝      ╚═════╝      ╚══╝╚══╝ ╚═╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
"""

OWASP_TOP10 = [
    "A01: Broken Access Control",
    "A02: Cryptographic Failures",
    "A03: Injection",
    "A04: Insecure Design",
    "A05: Security Misconfiguration",
    "A06: Vulnerable and Outdated Components",
    "A07: Identification and Authentication Failures",
    "A08: Software and Data Integrity Failures",
    "A09: Security Logging and Monitoring Failures",
    "A10: Server-Side Request Forgery"
]

def cyber_print(msg, color=Fore.CYAN, delay=0.01):
    for c in msg:
        print(color + c, end="", flush=True)
        time.sleep(delay)
    print(Style.RESET_ALL, end="")

def menu():
    os.system("clear")
    print(ASCII)
    print(Fore.GREEN + "[1] OSINT Target")
    print("[2] Subdomain Discovery")
    print("[3] Port & Service Scan (Fast)")
    print("[4] OWASP Top 10 Quick Checks")
    print("[5] HTTP(S) Fingerprint & Banner Grab")
    print("[6] Automated Report for Submission")
    print("[7] Bug Bounty Tips & Tricks")
    print("[8] Recon MultiTarget (espansione e analisi da keyword)")
    print("[0] Exit" + Style.RESET_ALL)
    cyber_print("\nSelect an option: ", Fore.YELLOW)
    return input().strip()

def osint_target(domain):
    result = {}
    cyber_print(f"\n[+] WHOIS & DNS for {domain}...\n", Fore.MAGENTA)
    try:
        import whois
        w = whois.whois(domain)
        result["whois"] = str(w)
    except Exception as e:
        result["whois"] = f"WHOIS failed: {e}"
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'A')
        result["dns_A"] = [r.address for r in answers]
    except Exception as e:
        result["dns_A"] = f"DNS A failed: {e}"
    return result

def subdomain_discovery(domain):
    cyber_print(f"\n[+] Subdomain scan for {domain}...\n", Fore.MAGENTA)
    found = []
    common = [
        "www", "mail", "webmail", "ftp", "dev", "test", "admin", "api", "portal",
        "app", "blog", "vpn", "stage", "staging", "mx", "owa", "remote", "sso"
    ]
    for sub in common:
        host = f"{sub}.{domain}"
        try:
            socket.gethostbyname(host)
            found.append(host)
        except:
            pass
    return found if found else ["No common subdomains found."]

def fast_port_scan(domain_or_ip):
    cyber_print(f"\n[+] Fast TCP scan on {domain_or_ip}...\n", Fore.MAGENTA)
    open_ports = []
    def scan(port):
        try:
            s = socket.socket()
            s.settimeout(0.2)
            s.connect((domain_or_ip, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    threads = []
    for port in [21,22,23,25,53,80,110,111,139,143,443,445,993,995,3306,3389,8080,8443]:
        t = threading.Thread(target=scan, args=(port,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return open_ports

def owasp_check(domain):
    cyber_print(f"\n[+] HTTP(s) quick checks for OWASP Top 10 on {domain}...\n", Fore.MAGENTA)
    url = f"http://{domain}"
    https_url = f"https://{domain}"
    findings = {}
    try:
        r = requests.get(url, timeout=3)
        findings["http_status"] = r.status_code
        findings["cookies"] = r.cookies.get_dict()
        findings["headers"] = dict(r.headers)
        findings["has_x_frame"] = "X-Frame-Options" in r.headers
        findings["has_csp"] = "Content-Security-Policy" in r.headers
        findings["has_hsts"] = "Strict-Transport-Security" in r.headers
    except Exception as e:
        findings["http_error"] = str(e)
    try:
        r = requests.get(https_url, timeout=3, verify=False)
        findings["https_status"] = r.status_code
        findings["https_headers"] = dict(r.headers)
    except Exception as e:
        findings["https_error"] = str(e)
    findings["OWASP_TOP10"] = OWASP_TOP10
    return findings

def http_fingerprint(domain):
    cyber_print(f"\n[+] HTTP(S) fingerprint & banner for {domain}...\n", Fore.MAGENTA)
    url = f"http://{domain}"
    https_url = f"https://{domain}"
    banners = {}
    for u in [url, https_url]:
        try:
            r = requests.get(u, timeout=3, verify=False)
            banners[u] = dict(r.headers)
        except:
            banners[u] = "No response"
    return banners

def auto_report(domain, osint, subs, ports, owasp, banners):
    cyber_print("\n[+] Generating bug bounty report...\n", Fore.LIGHTGREEN_EX)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fname = f"bugbounty_report_{domain}_{now.replace(' ','_').replace(':','-')}.txt"
    with open(fname, "w") as f:
        f.write("# Bug Bounty Automated Recon Report\n")
        f.write(f"Target: {domain}\nGenerated: {now}\n\n")
        f.write("## OSINT\n")
        f.write(json.dumps(osint, indent=2, ensure_ascii=False) + "\n\n")
        f.write("## Subdomain Discovery\n")
        f.write("\n".join(subs) + "\n\n")
        f.write("## Open Ports (Fast)\n")
        f.write(json.dumps(ports, indent=2) + "\n\n")
        f.write("## OWASP Top 10 Quick Checks\n")
        f.write(json.dumps(owasp, indent=2, ensure_ascii=False) + "\n\n")
        f.write("## HTTP(S) Banners\n")
        f.write(json.dumps(banners, indent=2, ensure_ascii=False) + "\n\n")
        f.write("## Bug Bounty Wizard Pro Tips\n")
        for tip in pro_tips():
            f.write("- " + tip + "\n")
    cyber_print(f"\n[✓] Report pronto: {fname}\n", Fore.LIGHTGREEN_EX, 0.01)

def pro_tips():
    return [
        "Leggi sempre il regolamento del programma prima di agire!",
        "Automatizza la raccolta info, ma verifica manualmente i falsi positivi.",
        "Cerca endpoint non documentati, vecchie versioni, subdomini abbandonati.",
        "Testa sempre per default creds/login bypass.",
        "Sfrutta le info HTTP header per capire la piattaforma, framework e possibili CVE.",
        "Prova tecniche di parameter pollution, IDOR, bruteforce su endpoint critici.",
        "Scrivi report chiari, con prove e impatto reale.",
        "Non attaccare mai fuori scope!",
        "Usa strumenti come Burp Suite, ffuf, nuclei, waybackurls, subfinder per completare la tua ricognizione.",
        "Studia i report passati della piattaforma: molti bug tornano ciclicamente!"
    ]

def expand_and_analyze(keyword, max_domains=10):
    from urllib.parse import quote
    cyber_print(f"\n[+] Ricerca domini collegati a '{keyword}'...\n", Fore.MAGENTA)
    try:
        url = f"https://crt.sh/?q=%25{quote(keyword)}%25&output=json"
        resp = requests.get(url, timeout=10)
        results = resp.json()
        domains = set()
        for entry in results:
            name = entry.get('common_name') or entry.get('name_value')
            if name and keyword.lower() in name.lower():
                # rimuove wildcard e dup
                name = name.replace("*.","").lower().strip()
                domains.add(name)
            if len(domains) >= max_domains:
                break
        domains = list(domains)
    except Exception as e:
        cyber_print(f"Errore ricerca domini: {e}\n", Fore.RED)
        return

    if not domains:
        cyber_print("Nessun dominio trovato!\n", Fore.RED)
        return

    cyber_print(f"Trovati i seguenti domini:\n", Fore.CYAN)
    for i, d in enumerate(domains, 1):
        print(f"{i}. {d}")

    cyber_print(f"\nAvvio analisi automatica su {len(domains)} domini...\n", Fore.LIGHTGREEN_EX)
    all_reports = {}
    for domain in domains:
        try:
            osint = osint_target(domain)
            subs = subdomain_discovery(domain)
            target_ip = domain
            try: target_ip = socket.gethostbyname(domain)
            except: pass
            ports = fast_port_scan(target_ip)
            owasp = owasp_check(domain)
            banners = http_fingerprint(domain)
            all_reports[domain] = {
                "osint": osint,
                "subdomains": subs,
                "ports": ports,
                "owasp": owasp,
                "banners": banners
            }
            cyber_print(f"[✓] Analisi completata per {domain}\n", Fore.LIGHTCYAN_EX, 0.003)
        except Exception as e:
            cyber_print(f"[!] Errore su {domain}: {e}\n", Fore.RED)
    # Salva report aggregato
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    fname = f"multi_report_{keyword}_{now}.json"
    with open(fname, "w") as f:
        json.dump(all_reports, f, indent=2, ensure_ascii=False)
    cyber_print(f"\n[✓] Report multiplo salvato in: {fname}\n", Fore.LIGHTGREEN_EX, 0.01)

def main():
    cyber_print("Welcome to BugBounty Wizard!\n", Fore.LIGHTCYAN_EX, 0.02)
    cyber_print("Inserisci dominio target (esempio.com): ", Fore.YELLOW)
    domain = input().strip()
    osint = {}
    subs = []
    ports = []
    owasp = {}
    banners = {}
    while True:
        choice = menu()
        if choice == "1":
            osint = osint_target(domain)
            cyber_print(json.dumps(osint, indent=2, ensure_ascii=False), Fore.CYAN, 0.003)
        elif choice == "2":
            subs = subdomain_discovery(domain)
            cyber_print("\n".join(subs), Fore.CYAN, 0.003)
        elif choice == "3":
            target_ip = domain
            try:
                target_ip = socket.gethostbyname(domain)
            except:
                pass
            ports = fast_port_scan(target_ip)
            cyber_print("Open ports: " + ", ".join(map(str, ports)), Fore.CYAN, 0.003)
        elif choice == "4":
            owasp = owasp_check(domain)
            cyber_print(json.dumps(owasp, indent=2, ensure_ascii=False), Fore.LIGHTMAGENTA_EX, 0.003)
        elif choice == "5":
            banners = http_fingerprint(domain)
            cyber_print(json.dumps(banners, indent=2, ensure_ascii=False), Fore.LIGHTMAGENTA_EX, 0.003)
        elif choice == "6":
            auto_report(domain, osint, subs, ports, owasp, banners)
        elif choice == "7":
            cyber_print("\n".join(pro_tips()), Fore.LIGHTGREEN_EX, 0.02)
        elif choice == "8":
            cyber_print("Inserisci la keyword/brand (es: GOOGLE): ", Fore.YELLOW)
            kw = input().strip()
            cyber_print("Quanti domini vuoi analizzare? [10]: ", Fore.YELLOW)
            try: maxd = int(input().strip())
            except: maxd = 10
            expand_and_analyze(kw, maxd)
        elif choice == "0":
            cyber_print("\nBye & happy hacking!\n", Fore.LIGHTMAGENTA_EX, 0.01)
            break
        else:
            cyber_print("Scelta non valida\n", Fore.RED, 0.01)
        input(Fore.LIGHTMAGENTA_EX + "\nPremi INVIO per continuare...")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    try:
        main()
    except KeyboardInterrupt:
        cyber_print("\n[!] Interrupted by user.\n", Fore.RED)
        sys.exit(0)
