# BugBounty Wizard - MultiTarget Edition

Il massimo per bug bounty hunters: inserisci una keyword (es. GOOGLE) e il tool:
- Trova fino a decine di domini reali associati
- Analizza per ciascuno: OSINT, subdomain, port scan, fingerprint, OWASP check
- Report pronto per bug bounty, OSINT su grandi gruppi, ricerca vulnerabilità

## Funzionalità

- OSINT target singolo o multiplo
- Subdomain discovery
- Fast port scan
- OWASP Top 10 quick check
- Fingerprint HTTP(S)
- Report auto-formattato TXT e JSON
- Tips & tricks da veri bug hunter
- Espansione automatica da keyword: analizza tanti domini in una sola mossa!

## Installazione

```bash
sudo apt update
sudo apt install python3 python3-pip
pip3 install -r requirements.txt
```

## Uso

```bash
python3 bugbounty_wizard.py
```

## Avvertenze

- Usa solo su target autorizzati e secondo regolamento del programma!
- I report multipli sono in formato JSON, pronti per analisi/filtri/dashboard.

**Buona caccia al bug!**
