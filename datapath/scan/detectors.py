"""Passive, read-only detectors (spec 4, safe mode).

Every detector here inspects a response a normal user would already receive —
headers, cookies, error bodies — and infers a misconfiguration WITHOUT sending
crafted input. They are all SideEffectClass.PASSIVE. Nothing here attempts
exploitation; confirmation-grade (active) checks are a later phase.

Each detector takes (url, HttpResponse) and returns a list[Finding].
"""

from __future__ import annotations

import re

from .egress import HttpResponse
from .findings import Finding

# Signatures of verbose error / stack-trace leakage (A05).
_ERROR_SIGNATURES = (
    "Traceback (most recent call last)",
    "Exception in thread",
    "java.lang.",
    "org.springframework.",
    "System.NullReferenceException",
    "Microsoft .NET Framework",
    "Warning: ",            # PHP
    "Fatal error: ",        # PHP
    "SQLSTATE[",            # PDO
    "ORA-0",                # Oracle
    "You have an error in your SQL syntax",
)


def detect_security_headers(url: str, resp: HttpResponse) -> list[Finding]:
    findings: list[Finding] = []
    is_https = url.lower().startswith("https://")

    if resp.header("Content-Security-Policy") is None:
        findings.append(Finding(
            check_id="missing-csp",
            title="Content-Security-Policy ausente",
            owasp="A05:2021 Security Misconfiguration",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            affected_url=url,
            evidence="Resposta sem cabeçalho Content-Security-Policy.",
            description="Sem CSP, o navegador não tem defesa em profundidade "
                        "contra injeção de scripts (XSS).",
            fix="Defina um Content-Security-Policy restritivo (ex.: default-src "
                "'self'; object-src 'none'; frame-ancestors 'none').",
        ))

    if resp.header("X-Content-Type-Options") is None:
        findings.append(Finding(
            check_id="missing-xcto",
            title="X-Content-Type-Options ausente",
            owasp="A05:2021 Security Misconfiguration",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            affected_url=url,
            evidence="Resposta sem 'X-Content-Type-Options: nosniff'.",
            fix="Envie 'X-Content-Type-Options: nosniff' em todas as respostas.",
        ))

    if is_https and resp.header("Strict-Transport-Security") is None:
        findings.append(Finding(
            check_id="missing-hsts",
            title="Strict-Transport-Security (HSTS) ausente",
            owasp="A05:2021 Security Misconfiguration",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            affected_url=url,
            evidence="Site HTTPS sem cabeçalho HSTS.",
            fix="Envie 'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains'.",
        ))

    if (resp.header("X-Frame-Options") is None
            and "frame-ancestors" not in (resp.header("Content-Security-Policy") or "")):
        findings.append(Finding(
            check_id="missing-framing",
            title="Proteção contra clickjacking ausente",
            owasp="A05:2021 Security Misconfiguration",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            affected_url=url,
            evidence="Sem X-Frame-Options nem 'frame-ancestors' no CSP.",
            fix="Use 'X-Frame-Options: DENY' ou 'frame-ancestors none' no CSP.",
        ))
    return findings


def detect_permissive_cors(url: str, resp: HttpResponse) -> list[Finding]:
    acao = resp.header("Access-Control-Allow-Origin")
    acac = (resp.header("Access-Control-Allow-Credentials") or "").lower()
    if acao == "*" and acac == "true":
        return [Finding(
            check_id="cors-wildcard-credentials",
            title="CORS permissivo com credenciais",
            owasp="A05:2021 Security Misconfiguration",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            affected_url=url,
            evidence="Access-Control-Allow-Origin: * com Allow-Credentials: true.",
            description="Qualquer site pode ler respostas autenticadas desta API.",
            fix="Nunca combine origin curinga com credenciais. Reflita apenas "
                "origens explicitamente permitidas numa allow-list.",
        )]
    if acao == "*":
        return [Finding(
            check_id="cors-wildcard",
            title="CORS com origem curinga",
            owasp="A05:2021 Security Misconfiguration",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            affected_url=url,
            evidence="Access-Control-Allow-Origin: *",
            fix="Restrinja as origens permitidas a uma allow-list explícita.",
        )]
    return []


def detect_verbose_errors(url: str, resp: HttpResponse) -> list[Finding]:
    text = resp.text(8192)
    for sig in _ERROR_SIGNATURES:
        if sig in text:
            snippet = _redact(text[max(0, text.find(sig)): text.find(sig) + 80])
            return [Finding(
                check_id="verbose-error",
                title="Mensagem de erro detalhada / stack trace exposta",
                owasp="A05:2021 Security Misconfiguration",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                affected_url=url,
                evidence=f"Assinatura de erro encontrada: {snippet!r}",
                description="Stack traces revelam tecnologia, caminhos e, às "
                            "vezes, trechos de consulta — úteis a um atacante.",
                fix="Desative erros detalhados em produção; retorne uma página "
                    "de erro genérica e registre o detalhe apenas internamente.",
            )]
    return []


def detect_directory_listing(url: str, resp: HttpResponse) -> list[Finding]:
    text = resp.text(2048)
    if "<title>Index of /" in text or ">Index of /" in text:
        return [Finding(
            check_id="directory-listing",
            title="Listagem de diretório habilitada",
            owasp="A05:2021 Security Misconfiguration",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            affected_url=url,
            evidence="Corpo contém 'Index of /'.",
            fix="Desative a listagem automática de diretórios no servidor web.",
        )]
    return []


def detect_insecure_cookies(url: str, resp: HttpResponse) -> list[Finding]:
    setc = resp.header("Set-Cookie")
    if not setc:
        return []
    low = setc.lower()
    problems = []
    if "secure" not in low:
        problems.append("sem atributo Secure")
    if "httponly" not in low:
        problems.append("sem atributo HttpOnly")
    if not problems:
        return []
    name = setc.split("=", 1)[0]
    return [Finding(
        check_id="insecure-cookie",
        title="Cookie de sessão sem atributos de segurança",
        owasp="A07:2021 Identification and Authentication Failures",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        affected_url=url,
        evidence=f"Cookie {name!r}: {', '.join(problems)}.",
        fix="Defina os cookies de sessão com Secure, HttpOnly e SameSite.",
    )]


def detect_tech_fingerprint(url: str, resp: HttpResponse) -> list[Finding]:
    bits = []
    for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
        v = resp.header(h)
        if v:
            bits.append(f"{h}: {v}")
    if not bits:
        return []
    return [Finding(
        check_id="tech-disclosure",
        title="Divulgação de tecnologia/versão em cabeçalhos",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        affected_url=url,
        evidence="; ".join(bits),
        description="Cabeçalhos revelam servidor/framework e versão, ajudando "
                    "um atacante a buscar vulnerabilidades conhecidas.",
        fix="Remova ou minimize os cabeçalhos Server / X-Powered-By.",
    )]


ALL_DETECTORS = (
    detect_security_headers,
    detect_permissive_cors,
    detect_verbose_errors,
    detect_directory_listing,
    detect_insecure_cookies,
    detect_tech_fingerprint,
)


def run_all(url: str, resp: HttpResponse) -> list[Finding]:
    out: list[Finding] = []
    for det in ALL_DETECTORS:
        out.extend(det(url, resp))
    return out


_PII_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def _redact(s: str) -> str:
    s = _PII_EMAIL.sub("[email]", s)
    return " ".join(s.split())
