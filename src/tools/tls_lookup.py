from __future__ import annotations

import socket
import ssl


def fetch_tls_certificate(domain: str) -> dict:
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
    except Exception as exc:
        return {"domain": domain, "error": str(exc)}

    return {
        "domain": domain,
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
        "subject_alt_names": cert.get("subjectAltName", [])[:20],
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
    }