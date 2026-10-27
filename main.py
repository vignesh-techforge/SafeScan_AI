from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.utils import secure_filename
from email import policy
from email.parser import Parser
from urllib.parse import urlparse, parse_qs, unquote
from difflib import SequenceMatcher
import os
import sqlite3
import json
import re
import socket
import ssl
import ipaddress
import requests
from bs4 import BeautifulSoup

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.urandom(32).hex()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "database.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024

REQUEST_HEADERS = {
    "User-Agent": "SafeScan-AI-Security-Research/1.0"
}

KNOWN_OFFICIAL_DOMAINS = {
    "tcs": ["tcs.com"],
    "tata consultancy services": ["tcs.com"],
    "microsoft": ["microsoft.com"],
    "google": ["google.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "paypal": ["paypal.com"],
    "instagram": ["instagram.com"],
    "facebook": ["facebook.com", "fb.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com"]
}


def init_database():
    with sqlite3.connect(DATABASE, timeout=15) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module TEXT NOT NULL,
                input_data TEXT NOT NULL,
                verdict TEXT NOT NULL,
                findings TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module TEXT NOT NULL,
                verdict TEXT NOT NULL,
                rating INTEGER NOT NULL,
                feedback_text TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                integrity_hash TEXT NOT NULL
            )
        """)

        connection.commit()


init_database()


def save_analysis(module, input_data, verdict, findings, metadata):
    with sqlite3.connect(DATABASE, timeout=15) as connection:
        connection.execute("""
            INSERT INTO analysis_history
            (module, input_data, verdict, findings, metadata)
            VALUES (?, ?, ?, ?, ?)
        """, (
            module,
            input_data,
            verdict,
            json.dumps(findings, default=str),
            json.dumps(metadata, default=str)
        ))
        connection.commit()


def normalize_domain(domain):
    if not domain:
        return ""

    domain = domain.lower().strip().split("@")[-1]

    if domain.startswith("[") and "]" in domain:
        domain = domain[1:domain.index("]")]
    elif domain.count(":") == 1:
        domain = domain.split(":")[0]

    return domain[4:] if domain.startswith("www.") else domain


def domain_matches(domain, official_domain):
    domain = normalize_domain(domain)
    official_domain = normalize_domain(official_domain)

    return (
        domain == official_domain
        or domain.endswith("." + official_domain)
    )


def identify_claimed_organization(text):
    text_lower = text.lower()

    for organization, domains in KNOWN_OFFICIAL_DOMAINS.items():
        if organization in text_lower:
            return organization, domains

    return None, []


def request_json(url, timeout=8):
    try:
        response = requests.get(
            url,
            headers=REQUEST_HEADERS,
            timeout=timeout
        )

        if response.ok:
            return response.json()

    except (requests.RequestException, ValueError):
        pass

    return None


def get_domain_creation_information(domain):
    data = {
        "Domain Registration Status": "Unavailable",
        "Domain Creation Date": "Not Available",
        "Domain Creation Time": "Not Available",
        "Domain Updated Date": "Not Available",
        "Domain Expiry Date": "Not Available",
        "Registrar": "Not Available",
        "Domain Status": "Not Available",
        "Name Servers": "Not Available",
        "RDAP Source": "Not Available"
    }

    domain = normalize_domain(domain)

    if not domain:
        return data

    rdap = request_json("https://rdap.org/domain/" + domain)

    if not rdap:
        return data

    data["Domain Registration Status"] = "RDAP data found"
    data["RDAP Source"] = "RDAP"

    for event in rdap.get("events", []):
        action = str(event.get("eventAction", "")).lower()
        date = event.get("eventDate")

        if not date:
            continue

        if action == "registration":
            data["Domain Creation Date"] = date[:10]
            data["Domain Creation Time"] = date
        elif action in (
            "last changed",
            "last update of rdap database"
        ):
            data["Domain Updated Date"] = date
        elif action == "expiration":
            data["Domain Expiry Date"] = date

    for entity in rdap.get("entities", []):
        if "registrar" not in entity.get("roles", []):
            continue

        vcard = entity.get("vcardArray", [None, []])

        if len(vcard) > 1:
            for item in vcard[1]:
                if len(item) >= 4 and item[0] == "fn":
                    data["Registrar"] = item[3]
                    break

    statuses = rdap.get("status")

    if statuses:
        data["Domain Status"] = ", ".join(map(str, statuses))

    nameservers = []

    for server in rdap.get("nameservers", []):
        name = server.get("ldhName") or server.get("unicodeName")

        if name:
            nameservers.append(name)

    if nameservers:
        data["Name Servers"] = ", ".join(nameservers)

    return data


def dns_query(name, record_type):
    try:
        response = requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": name, "type": record_type},
            headers={
                "Accept": "application/dns-json",
                **REQUEST_HEADERS
            },
            timeout=7
        )

        if response.ok:
            answers = response.json().get("Answer", [])

            return [
                str(item.get("data", ""))
                for item in answers
                if item.get("data")
            ]

    except (requests.RequestException, ValueError):
        pass

    return []


def get_dns_information(domain):
    metadata = {}

    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        values = dns_query(domain, record_type)

        metadata["DNS " + record_type] = (
            ", ".join(values) if values else "Not Available"
        )

    return metadata


def get_ip_information(domain):
    metadata = {
        "Resolved IPv4": "Not Available",
        "Resolved IPv6": "Not Available",
        "Reverse DNS": "Not Available",
        "IP RDAP Organization": "Not Available",
        "IP RDAP ASN": "Not Available"
    }

    ips = set()

    try:
        for item in socket.getaddrinfo(domain, None):
            ips.add(item[4][0])
    except socket.gaierror:
        pass

    ipv4 = [address for address in ips if ":" not in address]
    ipv6 = [address for address in ips if ":" in address]

    if ipv4:
        metadata["Resolved IPv4"] = ", ".join(ipv4)

    if ipv6:
        metadata["Resolved IPv6"] = ", ".join(ipv6)

    first_ip = next(iter(ips), None)

    if first_ip:
        try:
            metadata["Reverse DNS"] = socket.gethostbyaddr(first_ip)[0]
        except (socket.herror, socket.gaierror):
            pass

        rdap = request_json("https://rdap.org/ip/" + first_ip)

        if rdap:
            metadata["IP RDAP ASN"] = rdap.get(
                "handle",
                "Not Available"
            )

            for entity in rdap.get("entities", []):
                vcard = entity.get("vcardArray", [None, []])

                if len(vcard) > 1:
                    for item in vcard[1]:
                        if len(item) >= 4 and item[0] == "fn":
                            metadata["IP RDAP Organization"] = item[3]
                            break

                if metadata["IP RDAP Organization"] != "Not Available":
                    break

    return metadata


def get_ssl_information(hostname):
    information = {
        "SSL Available": False,
        "SSL Issuer": "Not Available",
        "SSL Subject": "Not Available",
        "SSL Valid From": "Not Available",
        "SSL Valid Until": "Not Available",
        "SSL SANs": "Not Available",
        "SSL Status": "Not Available"
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=5
        ) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:
                certificate = secure_socket.getpeercert()

                information["SSL Available"] = True

                issuer = certificate.get("issuer", [])
                subject = certificate.get("subject", [])

                information["SSL Issuer"] = ", ".join(
                    part[0][1] for part in issuer if part
                ) or "Not Available"

                information["SSL Subject"] = ", ".join(
                    part[0][1] for part in subject if part
                ) or "Not Available"

                information["SSL Valid From"] = certificate.get(
                    "notBefore",
                    "Not Available"
                )

                information["SSL Valid Until"] = certificate.get(
                    "notAfter",
                    "Not Available"
                )

                sans = [
                    item[1]
                    for item in certificate.get("subjectAltName", [])
                    if len(item) > 1
                ]

                information["SSL SANs"] = (
                    ", ".join(sans) if sans else "Not Available"
                )

                information["SSL Status"] = (
                    "Valid during connection verification"
                )

    except Exception:
        pass

    return information


def get_url_structure(parsed, original_url):
    query = parse_qs(parsed.query, keep_blank_values=True)

    try:
        decoded_url = unquote(original_url)
    except Exception:
        decoded_url = original_url

    try:
        port = parsed.port
    except ValueError:
        port = None

    metadata = {
        "URL Length": len(original_url),
        "Hostname": parsed.hostname or "Not Available",
        "Port": port or (
            "443" if parsed.scheme == "https" else "80"
        ),
        "Path": parsed.path or "/",
        "Query Parameters": len(query),
        "Query Parameter Names": ", ".join(query.keys()) if query else "None",
        "Fragment Present": "Yes" if parsed.fragment else "No",
        "Username in URL": "Yes" if parsed.username else "No",
        "Password in URL": "Yes" if parsed.password else "No",
        "Percent Encoding Present": "Yes" if "%" in original_url else "No",
        "Punycode / IDN Present": (
            "Yes" if "xn--" in (parsed.hostname or "").lower() else "No"
        ),
        "IP Address URL": "No",
        "Decoded URL": decoded_url
    }

    try:
        if parsed.hostname:
            ipaddress.ip_address(parsed.hostname)
            metadata["IP Address URL"] = "Yes"
    except ValueError:
        pass

    return metadata


def get_page_metadata(soup):
    metadata = {
        "Meta Description": "Not Available",
        "Meta Keywords": "Not Available",
        "Author": "Not Available",
        "Publisher": "Not Available",
        "Web Page Created Date": "Not Available",
        "Web Page Published Date": "Not Available",
        "Web Page Modified Date": "Not Available",
        "OpenGraph Title": "Not Available",
        "OpenGraph Description": "Not Available",
        "OpenGraph URL": "Not Available",
        "OpenGraph Site Name": "Not Available",
        "Canonical URL": "Not Available",
        "Robots Meta": "Not Available",
        "Page Language": "Not Available",
        "Page Charset": "Not Available",
        "JSON-LD Detected": "No",
        "Sitemap Reference": "Not Available"
    }

    def meta_value(*keys):
        for key in keys:
            tag = soup.find("meta", attrs={"name": key})

            if tag and tag.get("content"):
                return tag["content"].strip()

            tag = soup.find("meta", attrs={"property": key})

            if tag and tag.get("content"):
                return tag["content"].strip()

        return "Not Available"

    metadata["Meta Description"] = meta_value("description")
    metadata["Meta Keywords"] = meta_value("keywords")
    metadata["Author"] = meta_value("author", "article:author")
    metadata["Publisher"] = meta_value("publisher", "article:publisher")
    metadata["OpenGraph Title"] = meta_value("og:title")
    metadata["OpenGraph Description"] = meta_value("og:description")
    metadata["OpenGraph URL"] = meta_value("og:url")
    metadata["OpenGraph Site Name"] = meta_value("og:site_name")

    canonical = soup.find(
        "link",
        rel=lambda value: value and "canonical" in value
    )

    if canonical and canonical.get("href"):
        metadata["Canonical URL"] = canonical["href"]

    robots = soup.find("meta", attrs={"name": "robots"})

    if robots and robots.get("content"):
        metadata["Robots Meta"] = robots["content"]

    if soup.html and soup.html.get("lang"):
        metadata["Page Language"] = soup.html["lang"]

    charset = soup.find("meta", charset=True)

    if charset:
        metadata["Page Charset"] = charset.get(
            "charset",
            "Not Available"
        )
    else:
        content_type = soup.find(
            "meta",
            attrs={"http-equiv": re.compile("^content-type$", re.I)}
        )

        if content_type:
            metadata["Page Charset"] = content_type.get(
                "content",
                "Not Available"
            )

    json_ld = []

    for script in soup.find_all(
        "script",
        type="application/ld+json"
    ):
        if script.string:
            try:
                json_ld.append(json.loads(script.string))
            except (ValueError, TypeError):
                continue

    if json_ld:
        metadata["JSON-LD Detected"] = "Yes"

        for item in json_ld:
            objects = item if isinstance(item, list) else [item]

            for obj in objects:
                if not isinstance(obj, dict):
                    continue

                for key, label in (
                    ("dateCreated", "Web Page Created Date"),
                    ("datePublished", "Web Page Published Date"),
                    ("dateModified", "Web Page Modified Date"),
                    ("author", "Author"),
                    ("publisher", "Publisher")
                ):
                    if metadata[label] == "Not Available" and obj.get(key):
                        value = obj[key]

                        if isinstance(value, dict):
                            value = value.get("name") or value.get("url")

                        metadata[label] = str(value)

    sitemap = soup.find(
        "link",
        rel=lambda value: value and "sitemap" in value
    )

    if sitemap and sitemap.get("href"):
        metadata["Sitemap Reference"] = sitemap["href"]

    return metadata


def get_security_information(response):
    headers = response.headers

    names = [
        ("HSTS", "Strict-Transport-Security"),
        ("Content Security Policy", "Content-Security-Policy"),
        ("X-Frame-Options", "X-Frame-Options"),
        ("X-Content-Type-Options", "X-Content-Type-Options"),
        ("Referrer Policy", "Referrer-Policy"),
        ("Permissions Policy", "Permissions-Policy")
    ]

    metadata = {}

    for label, header in names:
        metadata["Security Header - " + label] = headers.get(
            header,
            "Not Present"
        )

    metadata["Server"] = headers.get("Server", "Not Available")
    metadata["X-Powered-By"] = headers.get("X-Powered-By", "Not Available")
    metadata["Content-Type"] = headers.get("Content-Type", "Not Available")
    metadata["Content-Length"] = headers.get("Content-Length", "Not Available")
    metadata["Set-Cookie Present"] = "Yes" if headers.get("Set-Cookie") else "No"

    return metadata


def get_page_technical_information(soup):
    scripts = soup.find_all("script")
    links = soup.find_all("a", href=True)
    images = soup.find_all("img")
    iframes = soup.find_all("iframe")
    forms = soup.find_all("form")

    password_fields = soup.find_all(
        "input",
        attrs={"type": re.compile("^password$", re.I)}
    )

    external_links = sum(
        1 for tag in links
        if tag.get("href", "").startswith(("http://", "https://"))
    )

    external_scripts = sum(
        1 for tag in scripts
        if tag.get("src", "").startswith(("http://", "https://"))
    )

    return {
        "Forms Detected": len(forms),
        "Password Fields": len(password_fields),
        "Links Detected": len(links),
        "External Links": external_links,
        "Scripts Detected": len(scripts),
        "External Scripts": external_scripts,
        "Images Detected": len(images),
        "Iframes Detected": len(iframes)
    }


def detect_technologies(response, soup):
    text = response.text.lower()
    technologies = []

    server = response.headers.get("Server", "")
    powered = response.headers.get("X-Powered-By", "")

    for name, markers in {
        "WordPress": ["wp-content", "wp-includes"],
        "Shopify": ["cdn.shopify.com", "shopify"],
        "React": ["react", "_reactroot"],
        "Next.js": ["_next/static", "__next_data__"],
        "Vue.js": ["vue.js", "vue@"],
        "Angular": ["ng-version", "angular"],
        "Bootstrap": ["bootstrap"],
        "Cloudflare": ["cloudflare", "cf-ray"],
        "PHP": ["php"]
    }.items():
        if any(marker in text for marker in markers):
            technologies.append(name)

    if server:
        technologies.append("Server: " + server)

    if powered:
        technologies.append("X-Powered-By: " + powered)

    return (
        ", ".join(dict.fromkeys(technologies))
        if technologies
        else "No common technology indicator detected"
    )


def get_typosquatting_information(domain, claimed_org=None):
    metadata = {
        "Typosquatting Check": "Not Applicable",
        "Domain Similarity": "Not Available"
    }

    if not claimed_org:
        return metadata

    official_domains = KNOWN_OFFICIAL_DOMAINS.get(claimed_org, [])

    if not official_domains:
        return metadata

    best = 0
    best_domain = ""

    for official in official_domains:
        similarity = SequenceMatcher(
            None,
            normalize_domain(domain),
            normalize_domain(official)
        ).ratio()

        if similarity > best:
            best = similarity
            best_domain = official

    metadata["Domain Similarity"] = f"{best:.2f} compared with {best_domain}"

    if (
        normalize_domain(domain) == normalize_domain(best_domain)
        or domain_matches(domain, best_domain)
    ):
        metadata["Typosquatting Check"] = "No mismatch detected"
    elif best >= 0.70:
        metadata["Typosquatting Check"] = "Possible look-alike domain"
    else:
        metadata["Typosquatting Check"] = "No strong similarity detected"

    return metadata


def investigate_url(url):
    metadata = {}
    findings = []

    original_input = url.strip()

    if not re.match(r"^https?://", original_input, re.I):
        original_input = "https://" + original_input

    try:
        parsed = urlparse(original_input)
        domain = normalize_domain(parsed.hostname or "")
        metadata["Submitted URL"] = original_input
        metadata["Original Domain"] = domain
        metadata["Protocol"] = parsed.scheme.upper()
        metadata.update(get_url_structure(parsed, original_input))
    except (ValueError, TypeError):
        return {
            "metadata": metadata,
            "findings": ["The submitted value is not a valid URL."],
            "reason": "The URL could not be technically verified.",
            "verdict": "Unable to Verify"
        }

    if not domain:
        return {
            "metadata": metadata,
            "findings": ["The submitted value does not contain a valid domain."],
            "reason": "The URL could not be technically verified.",
            "verdict": "Unable to Verify"
        }

    metadata.update(get_domain_creation_information(domain))
    metadata.update(get_dns_information(domain))
    metadata.update(get_ip_information(domain))

    ssl_info = get_ssl_information(domain)
    metadata.update(ssl_info)

    if ssl_info["SSL Available"]:
        findings.append("A TLS connection was established for the domain.")
    else:
        findings.append("A TLS certificate could not be independently verified.")

    try:
        response = requests.get(
            original_input,
            headers=REQUEST_HEADERS,
            timeout=12,
            allow_redirects=True
        )

        final_url = response.url
        final_parsed = urlparse(final_url)
        final_domain = normalize_domain(final_parsed.hostname or "")

        metadata["HTTP Status"] = response.status_code
        metadata["Final URL"] = final_url
        metadata["Final Domain"] = final_domain
        metadata["Redirect Count"] = len(response.history)
        metadata["Redirect Chain"] = " -> ".join(
            [original_input]
            + [item.url for item in response.history]
            + [final_url]
        )

        metadata.update(get_security_information(response))

        soup = BeautifulSoup(response.text, "html.parser")

        metadata["Page Title"] = (
            soup.title.get_text(" ", strip=True)
            if soup.title else "Not Available"
        )

        metadata.update(get_page_metadata(soup))
        metadata.update(get_page_technical_information(soup))
        metadata["Technology Indicators"] = detect_technologies(response, soup)

        if final_domain != domain:
            findings.append("The submitted URL redirects to a different domain.")
        else:
            findings.append("The final destination remains on the submitted domain.")

        if response.status_code >= 400:
            findings.append(
                f"The destination returned HTTP status {response.status_code}."
            )

        if metadata["Password Fields"] > 0:
            findings.append("The destination contains password input fields.")

        if metadata["Iframes Detected"] > 0:
            findings.append("The destination contains iframe elements.")

    except requests.RequestException as error:
        metadata["Connection Status"] = "Unable to Connect"
        metadata["Technical Error"] = str(error)

        return {
            "metadata": metadata,
            "findings": [
                "The destination could not be reached for independent verification."
            ],
            "reason": (
                "There was insufficient technical evidence to verify "
                "the destination."
            ),
            "verdict": "Unable to Verify"
        }

    claimed_org, official_domains = identify_claimed_organization(
        original_input + " "
        + metadata.get("Page Title", "") + " "
        + metadata.get("Meta Description", "")
    )

    if not claimed_org:
        for organization, domains in KNOWN_OFFICIAL_DOMAINS.items():
            if any(domain_matches(final_domain, official) for official in domains):
                claimed_org = organization
                official_domains = domains
                break

    if claimed_org:
        metadata["Claimed Organization"] = claimed_org
        metadata["Expected Official Domain"] = ", ".join(official_domains)

        metadata.update(
            get_typosquatting_information(final_domain, claimed_org)
        )

        official_match = any(
            domain_matches(final_domain, official_domain)
            for official_domain in official_domains
        )

        if official_match:
            findings.append(
                "The destination domain matches the known official domain "
                "associated with the identified organization."
            )
        else:
            findings.append(
                "The destination claims association with " + claimed_org
                + ", but the verified destination domain does not match "
                "the known official domain."
            )

            return {
                "metadata": metadata,
                "findings": findings,
                "reason": (
                    "The claimed organization and verified destination "
                    "domain do not match."
                ),
                "verdict": "Suspicious"
            }

    else:
        metadata["Organization Verification"] = (
            "No recognized organization identified"
        )

    suspicious = []

    if metadata.get("IP Address URL") == "Yes":
        suspicious.append("The URL uses an IP address instead of a domain name.")

    if metadata.get("Username in URL") == "Yes":
        suspicious.append("The URL contains a username component.")

    if metadata.get("Password in URL") == "Yes":
        suspicious.append("The URL contains a password component.")

    if metadata.get("Punycode / IDN Present") == "Yes":
        suspicious.append("The hostname contains punycode/IDN notation.")

    if metadata.get("Redirect Count", 0) > 3:
        suspicious.append("The URL uses multiple redirects.")

    findings.extend(suspicious)

    if response.status_code >= 400:
        verdict = "Suspicious"
        reason = "The destination returned an unsuccessful HTTP response."

    elif suspicious and not claimed_org:
        verdict = "Suspicious"
        reason = (
            "Technical URL indicators require caution, although they "
            "do not by themselves prove malicious intent."
        )

    else:
        verdict = "Likely Legitimate"
        reason = (
            "The destination was reachable, no verified organization "
            "identity mismatch was detected, and the available technical "
            "evidence did not identify a clear malicious indicator."
        )

    return {
        "metadata": metadata,
        "findings": findings,
        "reason": reason,
        "verdict": verdict
    }


def investigate_message(message):
    metadata = {}
    findings = []
    secondary_signals = []
    strong_mismatch = False

    parsed_message = Parser(policy=policy.default).parsestr(message)

    header_names = [
        "From", "To", "Cc", "Reply-To", "Return-Path",
        "Date", "Subject", "Message-ID", "Authentication-Results"
    ]

    for name in header_names:
        value = parsed_message.get(name)

        if value:
            metadata["Header - " + name] = value

    email_addresses = re.findall(
        r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
        message
    )

    metadata["Email Addresses Found"] = len(email_addresses)

    sender_email = email_addresses[0].lower().strip() if email_addresses else None
    sender_domain = sender_email.split("@")[-1] if sender_email else None

    if sender_email:
        metadata["Sender Email"] = sender_email
        metadata["Sender Domain"] = sender_domain
        findings.append(
            "A sender email address was identified and its domain was "
            "extracted for identity verification."
        )
    else:
        metadata["Sender Verification"] = "No sender email address was provided."

    reply_to = parsed_message.get("Reply-To")

    if reply_to:
        reply_domains = re.findall(
            r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
            reply_to
        )

        if reply_domains:
            metadata["Reply-To Domain"] = (
                reply_domains[0].split("@")[-1].lower()
            )

    claimed_org, official_domains = identify_claimed_organization(message)

    if claimed_org:
        metadata["Claimed Organization"] = claimed_org
        metadata["Expected Official Domain"] = ", ".join(official_domains)

        if sender_domain:
            sender_matches = any(
                domain_matches(sender_domain, domain)
                for domain in official_domains
            )

            metadata["Sender Identity Check"] = (
                "MATCH" if sender_matches else "MISMATCH"
            )

            if sender_matches:
                findings.append(
                    "The sender domain matches the known official domain "
                    "associated with the claimed organization."
                )
            else:
                findings.append(
                    "The sender domain does not match the known official "
                    "domain of the claimed organization."
                )
                strong_mismatch = True
    else:
        metadata["Organization Verification"] = (
            "No recognized organization identified"
        )

    received = parsed_message.get_all("Received", [])

    metadata["Received Headers"] = json.dumps(received, default=str)
    metadata["Received Header Count"] = len(received)

    auth = parsed_message.get("Authentication-Results")

    if auth:
        lower_auth = auth.lower()

        metadata["SPF Result"] = (
            "pass" if "spf=pass" in lower_auth
            else "fail" if "spf=fail" in lower_auth
            else "Not Clearly Reported"
        )

        metadata["DKIM Result"] = (
            "pass" if "dkim=pass" in lower_auth
            else "fail" if "dkim=fail" in lower_auth
            else "Not Clearly Reported"
        )

        metadata["DMARC Result"] = (
            "pass" if "dmarc=pass" in lower_auth
            else "fail" if "dmarc=fail" in lower_auth
            else "Not Clearly Reported"
        )
    else:
        metadata["SPF Result"] = "Not Available"
        metadata["DKIM Result"] = "Not Available"
        metadata["DMARC Result"] = "Not Available"

    links = re.findall(r"https?://[^\s<>\"]+", message)
    metadata["Links Detected"] = len(links)

    link_reports = []

    for link in links[:10]:
        clean_link = link.rstrip(".,!?;:)")

        result = investigate_url(clean_link)
        url_meta = result.get("metadata", {})

        link_reports.append({
            "Submitted URL": clean_link,
            "Original Domain": url_meta.get("Original Domain", "Unavailable"),
            "Final Domain": url_meta.get("Final Domain", "Unavailable"),
            "HTTP Status": url_meta.get("HTTP Status", "Unavailable"),
            "HTTPS": url_meta.get("SSL Available", "Unavailable"),
            "Redirect Count": url_meta.get("Redirect Count", "Unavailable"),
            "Domain Creation Date": url_meta.get(
                "Domain Creation Date",
                "Not Available"
            ),
            "Web Page Published Date": url_meta.get(
                "Web Page Published Date",
                "Not Available"
            ),
            "Page Title": url_meta.get("Page Title", "Unavailable"),
            "URL Verdict": result.get("verdict", "Unable to Verify")
        })

        for finding in result.get("findings", []):
            findings.append("URL Investigation: " + finding)

        final_domain = url_meta.get("Final Domain", "")

        if claimed_org and final_domain:
            if not any(
                domain_matches(final_domain, domain)
                for domain in official_domains
            ):
                strong_mismatch = True

    metadata["URL Investigation"] = json.dumps(
        link_reports,
        indent=2,
        default=str
    )

    patterns = [
        "urgent", "immediately", "verify your account",
        "account suspended", "confirm your password",
        "enter your password", "otp", "one time password",
        "click here", "limited time", "within 24 hours"
    ]

    lower_message = message.lower()
    detected = [pattern for pattern in patterns if pattern in lower_message]

    if detected:
        secondary_signals.extend(detected)
        metadata["Language Signals"] = ", ".join(detected)

    if parsed_message.is_multipart():
        metadata["MIME Type"] = parsed_message.get_content_type()
        metadata["Multipart Message"] = "Yes"

        metadata["Attachment Count"] = sum(
            1 for part in parsed_message.walk()
            if part.get_content_disposition() == "attachment"
        )

        attachments = [
            part.get_filename() or "Unnamed attachment"
            for part in parsed_message.walk()
            if part.get_content_disposition() == "attachment"
        ]

        metadata["Attachments"] = (
            ", ".join(attachments) if attachments else "None"
        )
    else:
        metadata["MIME Type"] = parsed_message.get_content_type()
        metadata["Multipart Message"] = "No"
        metadata["Attachment Count"] = 0

    if strong_mismatch:
        if secondary_signals:
            findings.append(
                "Additional language signals detected: "
                + ", ".join(secondary_signals)
                + ". These are supporting indicators only."
            )

        return {
            "metadata": metadata,
            "findings": findings,
            "reason": (
                "The primary conclusion is based on sender and "
                "destination domain identity evidence."
            ),
            "verdict": "Suspicious"
        }

    if claimed_org and sender_domain and any(
        domain_matches(sender_domain, domain)
        for domain in official_domains
    ):
        return {
            "metadata": metadata,
            "findings": findings,
            "reason": (
                "The sender domain matches the known official domain "
                "of the claimed organization. No verified identity "
                "mismatch was detected."
            ),
            "verdict": "Likely Legitimate"
        }

    if secondary_signals:
        findings.append(
            "Secondary language signals detected: "
            + ", ".join(secondary_signals)
            + ". These are additional context only."
        )

    return {
        "metadata": metadata,
        "findings": findings,
        "reason": (
            "Independent evidence was insufficient to establish a "
            "reliable security conclusion. Language patterns alone "
            "are not treated as proof."
        ),
        "verdict": "Unable to Verify"
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/modules")
def modules():
    return render_template("modules.html")


@app.route("/submit-feedback", methods=["POST"])
def submit_feedback():
    module = request.form.get("module", "").strip()
    verdict = request.form.get("verdict", "").strip()
    rating = request.form.get("rating", "").strip()
    feedback_text = request.form.get("feedback_text", "").strip()

    if not module or not verdict or rating not in ["1", "2", "3", "4", "5"]:
        return "Invalid feedback submission", 400

    from datetime import datetime
    import hashlib

    created_at = datetime.now().strftime("%Y-%m-%d %I:%M %p")
    data = f"{module}|{verdict}|{rating}|{feedback_text}|{created_at}"

    integrity_hash = hashlib.sha256(
        data.encode("utf-8")
    ).hexdigest()

    with sqlite3.connect(DATABASE, timeout=15) as connection:
        connection.execute("""
            INSERT INTO feedback (
                module, verdict, rating, feedback_text,
                created_at, integrity_hash
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            module,
            verdict,
            int(rating),
            feedback_text,
            created_at,
            integrity_hash
        ))

        connection.commit()

    return jsonify({"success": True})


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if (
            os.getenv("ADMIN_USERNAME")
            and os.getenv("ADMIN_PASSWORD")
            and username == os.getenv("ADMIN_USERNAME")
            and password == os.getenv("ADMIN_PASSWORD")
        ):
            session["admin_logged_in"] = True
            return redirect("/feedback-history")

        return render_template(
            "admin_login.html",
            error="Invalid username or password"
        )

    return render_template("admin_login.html")


@app.route("/feedback-history")
def feedback_history():
    if not session.get("admin_logged_in"):
        return redirect("/admin-login")

    with sqlite3.connect(DATABASE, timeout=15) as connection:
        connection.row_factory = sqlite3.Row

        feedback = connection.execute("""
            SELECT id, module, verdict, rating,
                   feedback_text, created_at
            FROM feedback
            ORDER BY id DESC
        """).fetchall()

    return render_template(
        "feedback_history.html",
        feedback=feedback,
        is_admin=True
    )


@app.route("/Terms & Privacy")
def terms_privacy():
    return render_template("terms_privacy.html")


@app.route("/urlshield", methods=["GET", "POST"])
def urlshield():
    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if not url:
            flash("Please enter a URL.")
            return redirect(url_for("urlshield"))

        try:
            analysis = investigate_url(url)

            save_analysis(
                "URLShield AI",
                url,
                analysis["verdict"],
                analysis["findings"],
                analysis["metadata"]
            )

            return render_template(
                "result.html",
                module="URLShield AI",
                input_data=url,
                analysis=analysis
            )

        except Exception:
            app.logger.exception("URLShield analysis failed")
            return (
                "URL analysis failed due to a server-side error. "
                "Please try again with a valid URL.",
                500
            )

    return render_template("urlshield.html")


@app.route("/mailguard", methods=["GET", "POST"])
def mailguard():
    if request.method == "POST":
        message = request.form.get("email_text", "").strip()

        if not message:
            flash("Please enter the complete email or message.")
            return redirect(url_for("mailguard"))

        try:
            analysis = investigate_message(message)

            save_analysis(
                "MailGuard AI",
                message,
                analysis["verdict"],
                analysis["findings"],
                analysis["metadata"]
            )

            return render_template(
                "result.html",
                module="MailGuard AI",
                input_data=message,
                analysis=analysis
            )

        except Exception:
            app.logger.exception("MailGuard analysis failed")
            return "Email analysis failed due to a server-side error.", 500

    return render_template("mailguard.html")


@app.route("/qrshield", methods=["GET", "POST"])
def qrshield():
    if request.method == "POST":
        qr_file = request.files.get("qr_file")

        if not qr_file or qr_file.filename == "":
            flash("Please select a QR code image.")
            return redirect(url_for("qrshield"))

        filename = secure_filename(qr_file.filename)

        if not filename:
            flash("Please select a valid QR code image.")
            return redirect(url_for("qrshield"))

        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        qr_file.save(file_path)

        try:
            import cv2

            detector = cv2.QRCodeDetector()
            image = cv2.imread(file_path)

            if image is None:
                raise ValueError("QR image could not be read.")

            decoded_data = request.form.get("qr_payload", "").strip()

            if not decoded_data:
                decoded_data, points, _ = detector.detectAndDecode(image)

            if not decoded_data:
                analysis = {
                    "metadata": {
                        "File Name": filename,
                        "QR Status": "No readable QR payload detected"
                    },
                    "findings": [
                        "The QR image was received, but no readable QR content was detected."
                    ],
                    "reason": (
                        "The QR code could not be decoded, so its hidden "
                        "content cannot be independently investigated."
                    ),
                    "verdict": "Unable to Verify"
                }

                return render_template(
                    "result.html",
                    module="QRShield AI",
                    input_data=filename,
                    analysis=analysis
                )

            metadata = {
                "File Name": filename,
                "QR Status": "Successfully Decoded",
                "Decoded Content": decoded_data,
                "QR Payload Length": len(decoded_data)
            }

            findings = []

            if re.match(r"^https?://", decoded_data, re.I):
                metadata["Content Type"] = "Website URL"
                findings.append("The QR code contains an external website URL.")

                url_analysis = investigate_url(decoded_data)

                for key, value in url_analysis["metadata"].items():
                    metadata["URL - " + key] = value

                findings.extend(
                    "URL Investigation: " + item
                    for item in url_analysis["findings"]
                )

                verdict = url_analysis["verdict"]

                reason = (
                    "The QR code was successfully decoded and its hidden "
                    "website destination was independently investigated. "
                    + url_analysis["reason"]
                )

            elif decoded_data.lower().startswith("mailto:"):
                email = decoded_data[7:]

                metadata["Content Type"] = "Email Address"
                metadata["Email Destination"] = email

                findings.append("The QR code contains an email destination.")

                verdict = "Requires Verification"
                reason = (
                    "The email destination was decoded, but the QR payload "
                    "alone cannot independently confirm ownership."
                )

            elif decoded_data.lower().startswith("tel:"):
                phone = decoded_data[4:]

                metadata["Content Type"] = "Phone Number"
                metadata["Phone Number"] = phone

                findings.append("The QR code contains a telephone number.")

                verdict = "Requires Verification"
                reason = (
                    "The phone number was decoded, but ownership cannot be "
                    "independently confirmed from the QR payload alone."
                )

            elif decoded_data.lower().startswith("upi://"):
                metadata["Content Type"] = "UPI Payment"

                parsed_upi = urlparse(decoded_data)
                upi_data = parse_qs(parsed_upi.query)

                metadata["UPI ID"] = upi_data.get("pa", ["Not Available"])[0]
                metadata["Payee Name"] = upi_data.get("pn", ["Not Available"])[0]
                metadata["Amount"] = upi_data.get("am", ["Not Available"])[0]
                metadata["Currency"] = upi_data.get("cu", ["Not Available"])[0]

                findings.append("The QR code contains a UPI payment destination.")
                findings.append("Payment destination information was extracted from the QR payload.")

                verdict = "Requires Verification"
                reason = (
                    "The payment destination was decoded, but the QR code "
                    "alone cannot independently prove the recipient's legitimacy."
                )

            elif decoded_data.startswith("WIFI:"):
                metadata["Content Type"] = "Wi-Fi Configuration"

                wifi_fields = {}

                for item in decoded_data[5:].split(";"):
                    if ":" in item:
                        key, value = item.split(":", 1)
                        wifi_fields[key] = value

                metadata["Wi-Fi SSID"] = wifi_fields.get("S", "Not Available")
                metadata["Wi-Fi Security"] = wifi_fields.get("T", "Not Available")
                metadata["Hidden Network"] = wifi_fields.get("H", "Not Available")

                findings.append("The QR code contains Wi-Fi configuration information.")

                verdict = "Informational"
                reason = (
                    "The QR code contains Wi-Fi configuration data and "
                    "no external website destination was detected."
                )

            else:
                metadata["Content Type"] = "Plain Text / Other Data"

                findings.append(
                    "The QR code contains text or another data format "
                    "rather than a directly recognized external destination."
                )

                verdict = "No External Threat Identified"
                reason = (
                    "The QR code was successfully decoded and no external "
                    "website destination was detected."
                )

            save_analysis(
                "QRShield AI",
                decoded_data,
                verdict,
                findings,
                metadata
            )

            return render_template(
                "result.html",
                module="QRShield AI",
                input_data=decoded_data,
                analysis={
                    "metadata": metadata,
                    "findings": findings,
                    "reason": reason,
                    "verdict": verdict
                }
            )

        except Exception as error:
            app.logger.exception("QRShield analysis failed")

            return render_template(
                "result.html",
                module="QRShield AI",
                input_data=filename,
                analysis={
                    "metadata": {
                        "File Name": filename,
                        "QR Status": "Analysis Error",
                        "Technical Error": str(error)
                    },
                    "findings": [
                        "The QR code could not be completely analyzed."
                    ],
                    "reason": (
                        "An unexpected technical error occurred while "
                        "processing the QR code."
                    ),
                    "verdict": "Unable to Verify"
                }
            )

    return render_template("qrshield.html")


@app.errorhandler(413)
def file_too_large(error):
    flash("File size is too large. Maximum allowed size is 200 MB.")
    return redirect(url_for("qrshield"))


@app.route("/reviews")
def public_reviews():
    with sqlite3.connect(DATABASE, timeout=15) as connection:
        connection.row_factory = sqlite3.Row

        feedback = connection.execute("""
            SELECT module, verdict, rating,
                   feedback_text, created_at
            FROM feedback
            ORDER BY id DESC
        """).fetchall()

    return render_template(
        "public_reviews.html",
        feedback=feedback
    )


@app.route("/delete-all-feedback", methods=["POST"])
def delete_all_feedback():
    if not session.get("admin_logged_in"):
        return "Unauthorized", 403

    with sqlite3.connect(DATABASE, timeout=15) as connection:
        connection.execute("DELETE FROM feedback")
        connection.commit()

    flash("All feedback records have been deleted.")
    return redirect("/feedback-history")


@app.route("/delete-feedback/<int:feedback_id>", methods=["POST"])
def delete_feedback(feedback_id):
    if not session.get("admin_logged_in"):
        return "Unauthorized", 403

    with sqlite3.connect(DATABASE, timeout=15) as connection:
        cursor = connection.execute(
            "DELETE FROM feedback WHERE id = ?",
            (feedback_id,)
        )
        connection.commit()

    if cursor.rowcount == 0:
        return "Feedback not found", 404

    return redirect("/feedback-history")


if __name__ == "__main__":
    init_database()
    app.run(host="0.0.0.0", port=5000, debug=True)
