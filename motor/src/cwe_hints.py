#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cwe_hints.py

Structured CWE → exposure preconditions used by Q2 (and helpful to Q3).
Each entry approximates how the weakness is typically exploited so we can
bias *exposure/reachability* without overruling stronger evidence (dynamic
finding, verified, public URL, etc.).

Fields:
- vector: 'N' (Network), 'A' (Adjacent), 'L' (Local), 'P' (Physical)
- ui:     whether User Interaction is typically required
- pr:     privileges typically required: 'N' (None), 'L' (Low), 'H' (High)
- kind:   coarse category (rce, inj, ssrf, auth, traversal, xxe, xss, csrf,
          info, dos, upload, redirect, crypto, session, exposure, misconfig, perm)

Notes:
- These are pragmatic defaults for ranking; refine as you see patterns in your data.
- You can safely extend this dict; unknown CWEs fall back to family heuristics.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple
import re


@dataclass(frozen=True)
class CweHint:
    vector: str = 'N'   # 'N'|'A'|'L'|'P'
    ui: bool = False
    pr: str = 'N'       # 'N'|'L'|'H'
    kind: str = 'unknown'


# --- Canonical, hand-curated hints (expand freely) ---------------------------------

CWE_HINTS: Dict[str, CweHint] = {
    # RCE / Code Injection
    '78':  CweHint('N', False, 'N', 'rce'),    # OS Command Injection
    '77':  CweHint('N', False, 'N', 'rce'),    # Command Injection
    '94':  CweHint('N', False, 'N', 'rce'),    # Code Injection
    '98':  CweHint('N', False, 'N', 'rce'),    # PHP file include / remote include
    '502': CweHint('N', False, 'N', 'rce'),    # Deserialization of Untrusted Data

    # Injection (DB/ORM/LDAP/etc.)
    '89':  CweHint('N', False, 'N', 'inj'),    # SQL Injection
    '564': CweHint('N', False, 'N', 'inj'),    # SQL Injection (Hibernate/ORM)
    '90':  CweHint('N', False, 'N', 'inj'),    # LDAP Injection
    '644': CweHint('N', False, 'N', 'inj'),    # XPath Injection
    '943': CweHint('N', False, 'N', 'inj'),    # Improper Neutralization in Data Query

    # SSRF
    '918': CweHint('N', False, 'N', 'ssrf'),

    # Authn/Authz
    '287': CweHint('N', False, 'N', 'auth'),   # Improper Authentication
    '306': CweHint('N', False, 'N', 'auth'),   # Missing Authentication for Critical Function
    '862': CweHint('N', False, 'N', 'auth'),   # Missing Authorization
    '863': CweHint('N', False, 'N', 'auth'),   # Incorrect Authorization
    '522': CweHint('N', False, 'N', 'auth'),   # Insufficiently Protected Credentials
    '521': CweHint('N', False, 'N', 'auth'),   # Weak Password Requirements
    '613': CweHint('N', False, 'N', 'session'),# Insufficient Session Expiration
    '614': CweHint('N', False, 'N', 'session'),# Sensitive Cookie without 'Secure'

    # Path traversal / file system
    '22':  CweHint('N', False, 'N', 'traversal'),
    '23':  CweHint('N', False, 'N', 'traversal'),
    '35':  CweHint('N', False, 'N', 'traversal'),
    '73':  CweHint('N', False, 'N', 'traversal'), # External Control of File Name or Path

    # File upload / storage
    '434': CweHint('N', False, 'N', 'upload'),    # Unrestricted File Upload
    '552': CweHint('N', False, 'N', 'exposure'),  # Files/Dirs Accessible to External Parties (⚠ critic for you)
    '548': CweHint('N', False, 'N', 'exposure'),  # Info Exposure Through Directory Listing
    '276': CweHint('N', False, 'N', 'perm'),      # Incorrect Default Permissions
    '732': CweHint('N', False, 'N', 'perm'),      # Incorrect Permission Assignment for Resource

    # XML / XXE
    '611': CweHint('N', False, 'N', 'xxe'),
    '827': CweHint('N', False, 'N', 'xxe'),

    # XSS
    '79':  CweHint('N', True,  'N', 'xss'),
    '80':  CweHint('N', True,  'N', 'xss'),
    '116': CweHint('N', True,  'N', 'xss'),       # Improper Encoding/Escaping of Output

    # CSRF
    '352': CweHint('N', True,  'L', 'csrf'),

    # Redirects
    '601': CweHint('N', True,  'N', 'redirect'),  # Open Redirect

    # Information exposure / logging / transport
    '200': CweHint('N', False, 'N', 'info'),      # General Information Exposure
    '209': CweHint('N', False, 'N', 'info'),      # Info Exposure Through Error Message
    '319': CweHint('N', False, 'N', 'info'),      # Cleartext Transmission of Sensitive Info
    '532': CweHint('N', False, 'N', 'info'),      # Info Exposure Through Log Files
    '359': CweHint('N', False, 'N', 'info'),      # Exposure of Private Info
    '922': CweHint('N', False, 'N', 'info'),      # Insecure Storage of Sensitive Information

    # Cryptography
    '321': CweHint('N', False, 'N', 'crypto'),    # Use of Hard-coded Cryptographic Key
    '326': CweHint('N', False, 'N', 'crypto'),    # Inadequate Encryption Strength
    '327': CweHint('N', False, 'N', 'crypto'),    # Use of Broken or Risky Crypto Algorithm
    '330': CweHint('N', False, 'N', 'crypto'),    # Use of Insufficiently Random Values
    '331': CweHint('N', False, 'N', 'crypto'),    # Insufficient Entropy
    '337': CweHint('N', False, 'N', 'crypto'),    # Predictable PRNG
    '338': CweHint('N', False, 'N', 'crypto'),    # Weak PRNG

    # Memory safety (context-dependent; may be remote if service-facing)
    '119': CweHint('N', False, 'N', 'rce'),       # Improper Restriction of Operations within Memory Buffer
    '120': CweHint('N', False, 'N', 'rce'),       # Classic Buffer Overflow
    '125': CweHint('N', False, 'N', 'dos'),       # Out-of-bounds Read (often info/DoS)
    '787': CweHint('N', False, 'N', 'rce'),       # Out-of-bounds Write
    '476': CweHint('N', False, 'N', 'dos'),       # NULL Pointer Dereference

    # DoS / Resource exhaustion
    '400': CweHint('N', False, 'N', 'dos'),
    '770': CweHint('N', False, 'N', 'dos'),
    '834': CweHint('N', False, 'N', 'dos'),       # Excessive Iteration / Unbounded Loop

    # Misconfiguration / insecure defaults
    '16':  CweHint('N', False, 'N', 'misconfig'), # Configuration
    '1188':CweHint('N', False, 'N', 'misconfig'), # Insecure Default Initialization (generic)
}


# --- Family fallbacks (pattern → default hint) -------------------------------------

CWE_FAMILY_FALLBACKS: List[Tuple[re.Pattern, CweHint]] = [
    (re.compile(r'^(2\d{2})$'), CweHint('N', False, 'N', 'info')),     # 2xx → Information exposure-ish
    (re.compile(r'^(3[0-9]{2})$'), CweHint('N', False, 'N', 'crypto')),# 3xx crypto-ish
    (re.compile(r'^(4[0-9]{2})$'), CweHint('N', False, 'N', 'upload')),# 4xx file/upload-ish
    (re.compile(r'^(5[0-9]{2})$'), CweHint('N', False, 'N', 'exposure')),# 5xx access/exposure-ish
    (re.compile(r'^(6[0-9]{2})$'), CweHint('N', False, 'N', 'xxe')),   # 6xx XML/XXE-ish
    (re.compile(r'^(7[0-9]{2})$'), CweHint('N', False, 'N', 'dos')),   # 7xx availability/memory
    (re.compile(r'^(9[0-9]{2})$'), CweHint('N', False, 'N', 'auth')),  # 9xx auth/config-ish
]


# --- Helpers -----------------------------------------------------------------------

def normalize_cwe_code(raw: str) -> str:
    """Return only the numeric part: 'CWE-552' → '552'."""
    m = re.search(r'(\d{2,4})', str(raw))
    return m.group(1) if m else ''


def hint_for_cwe(code: str) -> CweHint:
    """
    Get best-effort hint for a single CWE numeric code.
    Falls back to family heuristics if exact code is unknown.
    """
    code = normalize_cwe_code(code)
    if not code:
        return CweHint()
    if code in CWE_HINTS:
        return CWE_HINTS[code]
    for pattern, fb in CWE_FAMILY_FALLBACKS:
        if pattern.match(code):
            return fb
    return CweHint()


def hints_from_text(text: str) -> List[CweHint]:
    """
    Parse all CWE codes from free text (e.g., title/description) and
    return their corresponding hints (deduplicated by code).
    """
    seen, hints = set(), []
    for m in re.findall(r'(?:CWE[-\s]?)(\d{2,4})|(?<!\d)(\d{2,4})(?!\d)', str(text), flags=re.IGNORECASE):
        code = (m[0] or m[1])
        code = normalize_cwe_code(code)
        if code and code not in seen:
            hints.append(hint_for_cwe(code))
            seen.add(code)
    return hints
