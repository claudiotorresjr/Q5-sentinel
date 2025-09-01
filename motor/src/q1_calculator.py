#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module Q1: Exploitability Score (0-100)

- Normalizes CVE IDs robustly (case/whitespace/extra text/lists/multiple CVEs).
- Pulls NVD 2.0 references and infers PoC/weaponization signals (Exploit-DB, Metasploit, PacketStorm, GitHub, Nuclei).
- Uses KEV and EPSS when available (loaded externally by the orchestrator).
"""

from genericpath import isfile
import json
import os
import re
import requests
import time
import logging
from typing import Dict, List, Tuple, Optional, Union
from datetime import datetime

logger = logging.getLogger(__name__)

GITHUB_TOKEN = ""  # optional
NVD_API_KEY = ""

# --- CVE normalization helpers ------------------------------------------------

_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)

def extract_cve_id(value: Union[str, List[str], None]) -> str:
    """Return a normalized CVE ID (e.g., 'CVE-2015-4852') from any input; else ''."""
    if value is None:
        return ""
    if isinstance(value, list):
        value = ",".join(map(str, value))
    s = str(value)
    m = _CVE_RE.search(s)
    return m.group(1).upper() if m else ""

# --- External fetcher ---------------------------------------------------------

class ExternalDataFetcher:
    """Fetches external data (KEV, EPSS, PoC hints)."""

    def __init__(self):
        self.kev_data: Dict[str, dict] = {}
        self.epss_data: Dict[str, dict] = {}
        self.poc_cache: Dict[str, dict] = {}
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'VulnPrioritizer/1.0'})

    def _headers_github(self):
        hdrs = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "VulnPrioritizer/1.0",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if GITHUB_TOKEN:
            hdrs["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        return hdrs

    def _headers_nvd(self):
        hdrs = {"User-Agent": "VulnPrioritizer/1.0"}
        if NVD_API_KEY:
            hdrs["apiKey"] = NVD_API_KEY
        return hdrs

    def _safe_json_get(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None, timeout: int = 20):
        try:
            cache_file = f"cache/{params.get('cveId','unknown')}.json"
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, "r") as f:
                        return json.load(f)
                except Exception as e:
                    logger.debug("Failed to load cache file %s: %s", cache_file, e)

            resp = self.session.get(url, params=params, headers=headers, timeout=timeout)

            # GitHub rate limit
            if "api.github.com" in url and resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
                logger.warning("GitHub rate limit reached; returning empty (set GITHUB_TOKEN to raise limits).")
                return None
            if resp.status_code == 200:
                with open(f"cache/{params.get('cveId','unknown')}.json", "w") as f:
                    json.dump(resp.json(), f)
                return resp.json()
        except Exception as e:
            logger.debug("_safe_json_get failed: %s", e)
        return None

    def _nvd_references(self, cve_id: str) -> Dict:
        """Query NVD 2.0 for references and mark exploit/PoC sources."""
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        js = self._safe_json_get(url, params={"cveId": cve_id}, headers=self._headers_nvd())
        out = {
            'has_exploit_ref': False,
            'has_exploitdb': False,
            'has_metasploit': False,
            'has_packetstorm': False,
            'has_github': False,
            'has_nuclei': False,
            'sources': [],
            'edb_ids': []
        }
        if not js:
            return out
        vulns = js.get("vulnerabilities", [])
        if not vulns:
            return out
        refs = []
        try:
            refs = vulns[0]['cve']['references']
        except Exception:
            pass
        for r in refs or []:
            u = r.get('url', '') or ''
            tags = [t.lower() for t in (r.get('tags') or [])]
            note = {'source': 'NVD', 'url': u, 'tags': tags}
            if any(t in tags for t in ('exploit', 'proof of concept', 'proof-of-concept', 'poc')):
                out['has_exploit_ref'] = True
            if 'exploit-db.com' in u:
                out['has_exploitdb'] = True
                m = re.search(r'/exploits/(\d+)', u)
                if m:
                    out['edb_ids'].append(int(m.group(1)))
            if 'metasploit' in u or 'rapid7.com' in u:
                out['has_metasploit'] = True
            if 'packetstormsecurity.com' in u:
                out['has_packetstorm'] = True
            if 'github.com' in u:
                out['has_github'] = True
                if 'projectdiscovery/nuclei-templates' in u or '/nuclei-templates' in u:
                    out['has_nuclei'] = True
            out['sources'].append(note)
        # dedupe EDB ids
        out['edb_ids'] = sorted(set(out['edb_ids']))
        return out

    def fetch_kev_catalog(self):
        """Load CISA KEV catalog."""
        try:
            logger.info("Loading CISA KEV catalog…")
            response = self.session.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=30
            )
            if response.status_code == 200:
                kev_json = response.json()
                for vuln in kev_json.get('vulnerabilities', []):
                    cve_id = extract_cve_id(vuln.get('cveID', ''))
                    if cve_id:
                        self.kev_data[cve_id] = {
                            'date_added': vuln.get('dateAdded'),
                            'vendor': vuln.get('vendorProject'),
                            'product': vuln.get('product'),
                            'known_ransomware': vuln.get('knownRansomwareCampaignUse', 'Unknown') == 'Known'
                        }
                logger.info("KEV loaded: %d CVEs", len(self.kev_data))
            else:
                logger.warning("Failed to fetch KEV: HTTP %s", response.status_code)
        except Exception as e:
            logger.error("Error fetching KEV: %s", e)

    def fetch_epss_scores(self, cve_list: List[str]):
        """Fetch EPSS scores for a list of CVEs (input may include mixed case)."""
        try:
            valid = []
            for cve in cve_list:
                c = extract_cve_id(cve)
                if c:
                    valid.append(c)
            if not valid:
                logger.info("No valid CVEs for EPSS")
                return
            logger.info("Fetching EPSS scores for %d CVEs…", len(valid))
            batch_size = 100
            for i in range(0, len(valid), batch_size):
                batch = valid[i:i+batch_size]
                cve_batch = ','.join(batch)
                response = self.session.get(
                    f"https://api.first.org/data/v1/epss?cve={cve_batch}",
                    timeout=30
                )
                if response.status_code == 200:
                    epss_json = response.json()
                    for item in epss_json.get('data', []):
                        c = extract_cve_id(item.get('cve'))
                        if c:
                            self.epss_data[c] = {
                                'epss': float(item.get('epss', 0)),
                                'percentile': float(item.get('percentile', 0))
                            }
                time.sleep(0.1)
            logger.info("EPSS loaded: %d scores", len(self.epss_data))
        except Exception as e:
            logger.error("Error fetching EPSS: %s", e)

    def check_poc_availability(self, cve_id: str, show_progress: bool = False) -> Dict:
        """
        Check PoC/exploit availability and maturity using multiple real sources:
        - NVD 2.0 references (Exploit/PoC tags, Exploit-DB, Metasploit, PacketStorm, GitHub, Nuclei).
        Returns a rich dict and caches by normalized CVE.
        """
        cve = extract_cve_id(cve_id)
        default = {'has_poc': False, 'poc_maturity': 0, 'sources': [], 'weaponized': False,
                   'repo_count': 0, 'stars_total': 0, 'last_seen': None, 'edb_ids': []}
        if not cve:
            return default

        if cve in self.poc_cache:
            return self.poc_cache[cve]

        out = dict(default)  # copy
        try:
            # 1) NVD references
            nvd = self._nvd_references(cve)
            out['sources'].extend(nvd['sources'])
            out['edb_ids'].extend(nvd.get('edb_ids', []))

            if nvd['has_exploit_ref']:
                out['has_poc'] = True
                out['poc_maturity'] = max(out['poc_maturity'], 70)

            if nvd.get('has_exploitdb'):
                out['weaponized'] = True
                out['has_poc'] = True
                out['poc_maturity'] = max(out['poc_maturity'], 90)

            if nvd.get('has_metasploit'):
                out['weaponized'] = True
                out['has_poc'] = True
                out['poc_maturity'] = max(out['poc_maturity'], 100)

            if nvd.get('has_nuclei'):
                out['has_poc'] = True
                out['poc_maturity'] = max(out['poc_maturity'], 55)

            # 2) Recency adjustment (kept as placeholder; set last_seen when adding GH search in future)
            if out['last_seen']:
                try:
                    dt = datetime.fromisoformat(str(out['last_seen']).replace('Z', '+00:00'))
                    years = (datetime.now(dt.tzinfo) - dt).days / 365.25
                    if years > 5:
                        out['poc_maturity'] = max(0, out['poc_maturity'] - 10)
                    elif years <= 1:
                        out['poc_maturity'] = min(100, out['poc_maturity'] + 5)
                except Exception:
                    pass

            # 3) KEV ransomware boost (if KEV already loaded)
            if cve in self.kev_data and self.kev_data[cve].get('known_ransomware'):
                out['poc_maturity'] = min(100, max(out['poc_maturity'], 95))

            self.poc_cache[cve] = out
            if not show_progress:
                time.sleep(0.15)

            logger.debug("PoC check %s -> has_poc=%s weaponized=%s maturity=%s",
                         cve, out['has_poc'], out['weaponized'], out['poc_maturity'])
        except Exception as e:
            logger.debug("Error checking PoC for %s: %s", cve, e)
            self.poc_cache[cve] = out

        return out

# --- Q1 calculation -----------------------------------------------------------
def calculate_q1_exploitability(vuln_data: Dict, external_fetcher) -> float:
    """
    Exploitability = 0.5*poc_maturity + 0.3*env_fit + 0.2*class_weight
    - poc_maturity: 0..100 from NVD refs / ExploitDB / Metasploit / Nuclei (already in check_poc_availability)
    - env_fit: runtime & domain proximity (runtime -> 80, dev/test -> 30; +10 for web_api/db/search)
    - class_weight: severity by CWE family (RCE/Auth > LPE > XSS/CSRF > Info/DoS)
    """
    cve = extract_cve_id(vuln_data.get('vulnerability_ids'))
    poc = external_fetcher.check_poc_availability(cve)
    poc_maturity = float(poc.get('poc_maturity', 0))

    # env_fit
    file_path = str(vuln_data.get('file_path','')).lower()
    is_dev = any(x in file_path for x in ('test/','tests/','spec/','mock/','dev-dependencies','devdependencies','example/','sample/','-test'))
    is_runtime = (not is_dev) and any(x in file_path for x in ('boot-inf/lib','web-inf/lib','/lib/', '.jar', '.war','node_modules','vendor/','site-packages','requirements.txt'))
    env_fit = 80 if is_runtime else 30

    domain_bonus = 0
    domain_text = " ".join([str(vuln_data.get('component_name','')), str(vuln_data.get('service',''))]).lower()
    if any(k in domain_text for k in ('spring','tomcat','nginx','apache','postgres','mysql','redis','elastic','solr')):
        domain_bonus = 10
    env_fit = min(100, env_fit + domain_bonus)

    # class_weight from CWE
    cwe = str(vuln_data.get('cwe',''))
    cwe_ids = re.findall(r'\d+', cwe)
    def _class_weight(ids):
        critical = {'78','77','94','502','74','89','564','918','287','306','862','863','22','23','35','611','827'}
        medium   = {'79','80','352'}
        low      = {'200','209','532','400','770'}
        if any(i in critical for i in ids): return 90
        if any(i in medium for i in ids):   return 60
        if any(i in low for i in ids):      return 40
        return 50
    class_weight = float(_class_weight(cwe_ids))

    # Score base com maturidade do PoC, adequação de ambiente e classe CWE
    q1 = 0.5 * poc_maturity + 0.3 * env_fit + 0.2 * class_weight

    # Refino com EPSS absoluto e percentil
    # Em vez de apenas bonificar percentis >80, incorporamos o valor bruto (0-1) e
    # o percentil para refletir melhor a probabilidade de exploração. O EPSS pode
    # adicionar até 20 pontos extras e o percentil até 10 pontos.
    epss_info = external_fetcher.epss_data.get(cve, {})
    epss_score = float(epss_info.get('epss', 0))  # valor absoluto 0..1
    epss_percentile = float(epss_info.get('percentile', 0))  # 0..100
    if epss_score > 0:
        # contribuições proporcionais: 20 * epss_score (max 20) + 0.1 * epss_percentile (max 10)
        epss_bonus = 20.0 * epss_score + 0.1 * epss_percentile
        q1 += epss_bonus

    return min(100, q1)
