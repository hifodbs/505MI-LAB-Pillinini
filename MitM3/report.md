# MiTM3 Report

This report describes a local Man-in-the-Middle attack carried out by spoofing `alerenda.github.io` resolution using ARP/DNS-based redirection and serving attacker-controlled HTTP content.

## Tools

- `dig`
- `curl`
- Python 3 (`arp_request_all.py`, `http.server`)
- Docker / container shell access
- ARP poisoning techniques

## Environment

- Host: SEED-Ubuntu20.04
- Docker containers visible in the lab environment:
  - `local-dns-server-10.9.0.53`
  - `seed-attacker`
  - `user-10.9.0.5`
  - `seed-router`
  - `attacker-ns-10.9.0.153`
- Target domain: `alerenda.github.io`

## 1. Baseline verification

**Description:** Verify the legitimate DNS resolution and behavior of the target domain before attacking.

### Discovery

1. Run `dig +short alerenda.github.io` to check the real DNS addresses.
2. The legitimate response returned GitHub IP addresses:
   - `185.199.111.153`
   - `185.199.110.153`
   - `185.199.108.153`
   - `185.199.109.153`
3. Run `curl alerenda.github.io` and observe the normal GitHub redirect response:
   - `301 Moved Permanently`
   - `Server: nginx`
4. This confirms the domain is normally served by GitHub and is not locally controlled.

> Screenshot: `img/image.png`

## 2. Attack setup and discovery

**Description:** Spoof the victim's network resolution so the target domain resolves to an attacker-controlled address.

### Discovery

1. The attacker configured the local network environment by adding an IP alias to `eth0`:
   - `ip addr add 10.9.0.53/32 dev eth0`
2. The attacker executed an ARP poisoning script:
   - `python3 arp_request_all.py`
3. The attacker also launched a local HTTP server to serve the spoofed page:
   - `python3 -m http.server 80`
4. On the victim side, `arp -n` showed the attacker address present in the ARP table.
5. The victim's DNS lookup for `alerenda.github.io` was altered:
   - `dig +short alerenda.github.io` returned `10.9.0.1`
6. When the victim fetched the site with `curl`, the response came from the attacker-controlled host:
   - A custom HTML page with `<h1>This page has been successfully redirected.</h1>`

> Screenshot: `img/image2.png`

## 3. Exploitation

1. The attack demonstrates successful local redirection of a legitimate domain to an attacker-controlled IP.
2. By poisoning ARP and controlling DNS resolution on the victim's subnet, the attacker intercepted the request for `alerenda.github.io`.
3. The attacker served a spoofed HTTP page instead of the legitimate GitHub-hosted site.
4. This method allows content injection, phishing, or traffic redirection even when the victim requests a valid domain name.

## 4. Impact

- The victim is redirected from a legitimate website to attacker-controlled content.
- The attacker can present fake or malicious pages, capture sensitive input, or stage downstream attacks.
- Local network trust is broken because ARP/DNS spoofing can override normal name resolution.
- This attack is especially dangerous when users accept HTTP content or visit sites without strong TLS enforcement.

## 5. Remediation

- Enforce HTTPS for all traffic and use valid certificates.
- Deploy HSTS to prevent protocol downgrade attacks and force secure connections.
- Use network-level protections to detect and block ARP spoofing:
  - static ARP entries where appropriate
  - DHCP/ARP inspection
  - port security and network segmentation
- Harden DNS by using authenticated DNS resolvers, DNSSEC, or trusted DNS infrastructure.
- Monitor for unexpected domain resolution changes on critical hosts.

## 6. Notes

- This exercise shows that even a legitimate domain can be hijacked in a compromised local network.
- Defense in depth is required: secure transport (HTTPS/HSTS) plus network protections.
