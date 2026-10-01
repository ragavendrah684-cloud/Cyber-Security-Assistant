import ipaddress
import re
import socket
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from scanner.security_check import check_security


app = FastAPI(
    title="Cybersecurity Assistant",
    description=(
        "Basic, non-invasive website URL analysis and authorized TCP port "
        "checks for defensive and educational use."
    ),
    version="1.0.0",
)


# ============================================================
# CORS CONFIGURATION
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # Local development
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:5173",
        "http://127.0.0.1:5173",

        # Deployed frontend
        "https://cyber-security-assistant-frontend.vercel.app",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ============================================================
# CONFIGURATION
# ============================================================

MAX_PORTS = 50
SOCKET_TIMEOUT_SECONDS = 0.4

COMMON_PORTS = {80, 443}

SUSPICIOUS_TERMS = {
    "account",
    "bank",
    "login",
    "password",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}

SHORTENER_HOSTS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "t.co",
    "tinyurl.com",
}


# ============================================================
# REQUEST MODELS
# ============================================================

class SecurityCheckRequest(BaseModel):
    """A URL to assess using offline, non-invasive heuristics."""

    url: str = Field(
        description="An HTTP or HTTPS URL; the server does not fetch the URL.",
        max_length=2048,
    )


class PortScanRequest(BaseModel):
    """A bounded TCP port check for a host the requester may test."""

    host: str = Field(
        description="A hostname or IP address, without a URL scheme.",
        max_length=253,
    )

    ports: str = Field(
        description="Comma-separated TCP ports from 1 to 65535; up to 50.",
        max_length=255,
    )

    confirm_authorized: bool = Field(
        description="Must be true to confirm permission to scan this host."
    )


# ============================================================
# URL SECURITY ANALYSIS
# ============================================================

def analyze_url(url: str) -> dict:
    """Inspect URL text only; never make a network request to the target."""

    cleaned_url = url.strip()

    if not cleaned_url or any(character.isspace() for character in cleaned_url):
        raise HTTPException(
            status_code=400,
            detail="Enter a valid URL without spaces.",
        )

    try:
        parsed_url = urlsplit(cleaned_url)
        hostname = parsed_url.hostname
        port = parsed_url.port

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail="The URL contains an invalid host or port.",
        ) from error

    protocol = parsed_url.scheme.lower()

    if protocol not in {"http", "https"} or not parsed_url.netloc or not hostname:
        raise HTTPException(
            status_code=400,
            detail="Enter a complete URL that starts with http:// or https://.",
        )

    authority = parsed_url.netloc.rsplit("@", 1)[-1]

    if authority.endswith(":") or not is_valid_url_hostname(hostname):
        raise HTTPException(
            status_code=400,
            detail="The URL contains an invalid hostname or port.",
        )

    warnings = []

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True

        warnings.append(
            "The URL uses an IP address instead of a domain name."
        )

    except ValueError:
        is_ip_address = False

    hostname_parts = hostname.rstrip(".").split(".")

    if len(hostname_parts) > 4:
        warnings.append(
            "The hostname has an unusually large number of subdomains."
        )

    if "xn--" in hostname.lower():
        warnings.append(
            "The hostname contains an internationalized (punycode) label."
        )

    if hostname.lower() in SHORTENER_HOSTS:
        warnings.append(
            "The URL uses a link-shortening service, which hides its destination."
        )

    if port is not None and port not in COMMON_PORTS:
        warnings.append(
            f"The URL uses the non-standard web port {port}."
        )

    if parsed_url.username is not None or parsed_url.password is not None:
        warnings.append(
            "The URL contains user-information before the hostname."
        )

    if len(cleaned_url) > 200:
        warnings.append(
            "The URL is unusually long."
        )

    if "\\" in cleaned_url or re.search(
        r"%[0-9a-fA-F]{2}",
        cleaned_url,
    ):
        warnings.append(
            "The URL contains backslashes or percent-encoded characters."
        )

    hostname_labels = [
        label.lower()
        for label in hostname_parts
    ]

    if any(
        term in label
        for label in hostname_labels
        for term in SUSPICIOUS_TERMS
    ):
        warnings.append(
            "The hostname includes wording sometimes seen in phishing links."
        )

    if sum(
        character.isdigit()
        for character in hostname
    ) >= 6:
        warnings.append(
            "The hostname contains an unusually high number of digits."
        )

    if protocol == "http":
        warnings.append(
            "The URL uses HTTP, so the connection does not provide HTTPS transport encryption."
        )

    # ========================================================
    # RISK LEVEL
    # ========================================================

    if len(warnings) >= 4:
        risk_level = "High"
        summary = (
            "Potentially suspicious: several indicators were detected."
        )

    elif warnings:
        risk_level = "Medium"
        summary = (
            "Some security indicators were detected."
        )

    else:
        risk_level = "Low"
        summary = (
            "No obvious indicators were detected by these basic checks."
        )

    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    recommendations = [
        "Treat this as a basic heuristic analysis, not a guarantee of safety.",
        "Verify the destination through a trusted source before entering information or downloading files.",
    ]

    if protocol == "http":
        recommendations.append(
            "Prefer the site's HTTPS address when it is available."
        )

    if is_ip_address or hostname.lower() in SHORTENER_HOSTS:
        recommendations.append(
            "Confirm the destination domain independently before continuing."
        )

    return {
        "url": cleaned_url,
        "hostname": hostname,
        "protocol": protocol,
        "risk_level": risk_level,
        "summary": summary,
        "warnings": warnings,
        "recommendations": recommendations,
    }


# ============================================================
# HOSTNAME VALIDATION
# ============================================================

def is_valid_url_hostname(hostname: str) -> bool:
    """Validate an IP literal or DNS-style hostname without resolving it."""

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        pass

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")

    except UnicodeError:
        return False

    if ascii_hostname.endswith("."):
        ascii_hostname = ascii_hostname[:-1]

    if not ascii_hostname or len(ascii_hostname) > 253:
        return False

    return all(
        len(label) <= 63
        and re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?",
            label,
        )
        for label in ascii_hostname.split(".")
    )


# ============================================================
# HOST VALIDATION
# ============================================================

def validate_host(host: str) -> str:
    """Return a normalized, syntactically valid IP address or hostname."""

    normalized_host = host.strip().rstrip(".")

    if not normalized_host or normalized_host != host.strip():
        raise HTTPException(
            status_code=400,
            detail="Enter a valid host or IP address without spaces.",
        )

    try:
        return str(ipaddress.ip_address(normalized_host))

    except ValueError:
        pass

    if (
        len(normalized_host) > 253
        or not re.fullmatch(
            r"[A-Za-z0-9.-]+",
            normalized_host,
        )
    ):
        raise HTTPException(
            status_code=400,
            detail="Enter a valid hostname or IP address.",
        )

    labels = normalized_host.split(".")

    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        raise HTTPException(
            status_code=400,
            detail="Enter a valid hostname or IP address.",
        )

    return normalized_host


# ============================================================
# PORT PARSING
# ============================================================

def parse_ports(port_text: str) -> list[int]:
    """Parse a bounded comma-separated list of unique TCP ports."""

    pieces = [
        piece.strip()
        for piece in port_text.split(",")
    ]

    if not pieces or any(
        not piece.isdigit()
        for piece in pieces
    ):
        raise HTTPException(
            status_code=400,
            detail="Ports must be comma-separated numbers.",
        )

    ports = [
        int(piece)
        for piece in pieces
    ]

    if any(
        port < 1 or port > 65535
        for port in ports
    ):
        raise HTTPException(
            status_code=400,
            detail="Ports must be between 1 and 65535.",
        )

    if len(ports) > MAX_PORTS:
        raise HTTPException(
            status_code=400,
            detail=f"Scan no more than {MAX_PORTS} ports at a time.",
        )

    if len(set(ports)) != len(ports):
        raise HTTPException(
            status_code=400,
            detail="Do not include duplicate ports.",
        )

    return ports


# ============================================================
# TCP PORT SCANNER
# ============================================================

def scan_tcp_ports(host: str, ports: list[int]) -> dict:
    """Check each requested TCP port using a short connection timeout."""

    open_ports = []
    closed_ports = []
    errors = []

    for port in ports:
        try:
            with socket.create_connection(
                (host, port),
                timeout=SOCKET_TIMEOUT_SECONDS,
            ):
                open_ports.append(port)

        except ConnectionRefusedError:
            closed_ports.append(port)

        except (socket.timeout, TimeoutError):
            errors.append(
                {
                    "port": port,
                    "error": (
                        "Connection timed out; "
                        "port state could not be determined."
                    ),
                }
            )

        except OSError:
            errors.append(
                {
                    "port": port,
                    "error": "The connection could not be completed.",
                }
            )

    return {
        "host": host,
        "scanned_ports": ports,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "errors": errors,
    }


# ============================================================
# API ROUTES
# ============================================================

@app.get("/")
def home():
    return {
        "app": "CyberSecurity Assistant",
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }


@app.get("/scan")
def scan():
    return check_security()


@app.post(
    "/security-check",
    summary="Check basic security indicators in a URL",
    description=(
        "Analyzes URL text without visiting the destination. Results are "
        "heuristic and cannot guarantee that a URL is safe."
    ),
)
def security_check(request: SecurityCheckRequest):
    return analyze_url(request.url)


@app.post(
    "/scan",
    summary="Check selected TCP ports on an authorized host",
    description=(
        "Performs bounded TCP connection checks only. Confirm that you own "
        "the host or have explicit permission before requesting a scan."
    ),
)
def scan_ports(request: PortScanRequest):
    if not request.confirm_authorized:
        raise HTTPException(
            status_code=400,
            detail=(
                "Confirm that you own this host or have explicit "
                "permission to test it."
            ),
        )

    host = validate_host(request.host)
    ports = parse_ports(request.ports)

    return scan_tcp_ports(host, ports)
