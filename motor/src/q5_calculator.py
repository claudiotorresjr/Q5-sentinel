#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo Q5: Cálculo de Urgência (v6.5 — Q1..Q4-aware)
Q5: Urgência operacional (0-100)

Integrações chave:
- Usa Q1 (exploitability) para *gating* da ameaça (reduz urgência quando Q1 baixo e sem sinais).
- Usa Q2 (exposure) como fator de alcance prático da ameaça (refina threat).
- Usa Q3 (impact) como *cap/multiplier* suave (evita urgência alta para baixo impacto).
- Usa Q4 (fixability) como "nudge" tático (+ se fácil consertar, - leve se muito difícil).
- Management flags (risk_accepted / is_mitigated / false_p) reduzem urgência no fim.

Mantém:
- SLA como primeiro motor.
- EPSS (score+percentile), PoC real (via ExternalDataFetcher), KEV + recência.
- Age gating (idade só pesa se houver sinais); cooldown para CVEs antigas e frias.

Compatível com sua orquestração: calculate_q5_urgency(vuln_data, external_fetcher)
"""

from typing import Dict, Optional
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ---------------------------- helpers básicos --------------------------------
def _safe_bool(val) -> bool:
    return True if (val is True or str(val).lower() == 'true') else False

def _safe_float(val, default=None) -> Optional[float]:
    if val is None or str(val).lower() in ('nan', 'none', ''):
        return default
    try:
        return float(val)
    except Exception:
        return default

def _parse_date(s: Optional[str]) -> Optional[datetime]:
    if not s or str(s).lower() in ('nan', 'none', ''):
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(str(s), fmt)
        except Exception:
            continue
    return None

# -------------------------- exposição (Q2 hint leve) -------------------------
def _exposure_factor(vuln: Dict) -> float:
    """
    Retorna um fator [0.6..1.0] para *modular* a ameaça pela exposição.
    - Prefere q2_exposure (0..100) se presente no vuln_data.
    - Senão, heurística: URL pública/dinâmico/runtime/prod.
    """
    q2 = _safe_float(vuln.get('q2_exposure'), None)
    if q2 is not None:
        if q2 >= 60: return 1.00
        if q2 >= 40: return 0.90
        if q2 >= 20: return 0.85
        return 0.70

    url = str(vuln.get('url', '')).lower()
    dynamic = _safe_bool(vuln.get('dynamic_finding'))
    runtime = _safe_bool(vuln.get('is_runtime'))
    ctx = ' '.join([str(vuln.get('environment','')), str(vuln.get('service','')), url]).lower()
    is_prod = any(x in ctx for x in ['prod', 'production', 'prd', 'live'])
    publicish = any(x in url for x in ['http://','https://','.com','.org','.net','.io','public','external'])

    score = 0
    if publicish: score += 40
    if dynamic:   score += 30
    if runtime:   score += 20
    if is_prod:   score += 20

    if score >= 70: return 1.00
    if score >= 40: return 0.90
    if score >= 20: return 0.85
    return 0.70

# -------------------------- ameaça (EPSS/PoC/KEV) ----------------------------
def _threat_block(vuln: Dict, external_fetcher) -> Dict[str, float]:
    """
    Retorna:
      - score: 0..100 (contínuo)
      - tier: 'none'|'low'|'med'|'high'|'critical'
      - has_poc, has_kev, epss_score, epss_percentile
    Usa external_fetcher.{epss_data, kev_data, check_poc_availability}.
    """
    cve = str(vuln.get('vulnerability_ids', '')).strip()

    # EPSS (fetcher primeiro; fallback no JSON)
    epss_score = epss_percentile = 0.0
    if cve and getattr(external_fetcher, 'epss_data', None) and cve in external_fetcher.epss_data:
        e = external_fetcher.epss_data[cve] or {}
        epss_score = _safe_float(e.get('epss'), 0.0) or 0.0
        epss_percentile = _safe_float(e.get('percentile'), 0.0) or 0.0
    else:
        epss_score = _safe_float(vuln.get('epss_score'), 0.0) or 0.0
        p = _safe_float(vuln.get('epss_percentile'), 0.0)
        epss_percentile = p if (p is not None) else 0.0

    # PoC real (fonte confiável)
    has_poc = False
    if cve:
        poc = external_fetcher.check_poc_availability(cve)
        has_poc = bool(poc.get('has_poc', False))
    else:
        has_poc = _safe_bool(vuln.get('has_poc'))

    # KEV + recência + ransomware
    kev = False
    kev_recent = False
    known_ransom = False
    if cve and getattr(external_fetcher, 'kev_data', None) and cve in external_fetcher.kev_data:
        kev = True
        k = external_fetcher.kev_data[cve] or {}
        known_ransom = _safe_bool(k.get('known_ransomware'))
        d = _parse_date(k.get('date_added') or k.get('dateAdded'))
        if d:
            kev_recent = (datetime.utcnow() - d) <= timedelta(days=60)

    # Ameaça contínua 0..100: 65% score + 35% percentile
    threat = 100.0 * (0.65 * epss_score + 0.35 * (epss_percentile / 100.0))
    if has_poc:
        threat += 8.0
    if kev:
        threat = max(threat, 90.0)
        if kev_recent:
            threat += 5.0
    if known_ransom:
        threat = 100.0
    threat = float(max(0.0, min(100.0, threat)))

    # Tier
    if kev or known_ransom:
        tier = 'critical'
    elif threat >= 80:
        tier = 'high'
    elif threat >= 50 or has_poc:
        tier = 'med'
    elif threat >= 20:
        tier = 'low'
    else:
        tier = 'none'

    return {
        'score': threat,
        'tier': tier,
        'has_poc': has_poc,
        'has_kev': kev,
        'epss_score': epss_score,
        'epss_percentile': epss_percentile
    }

# ------------------------------ idade (gated) --------------------------------
def _age_urgency(vuln: Dict, tier: str) -> float:
    """
    Converte idade em 'urgência por envelhecimento', com *gating por ameaça*.
    Tier baixo limita o teto da idade; CVEs muito antigas sem sinais recebem cooldown adicional.
    """
    days = _safe_float(vuln.get('sla_age'), None)
    if days is None:
        return 0.0

    if days > 365*2: base = 20
    elif days > 365: base = 18
    elif days > 180: base = 16
    elif days > 90:  base = 12
    elif days > 30:  base = 8
    elif days > 7:   base = 4
    else:            base = 0

    caps = {'none': 10, 'low': 20, 'med': 25, 'high': 30, 'critical': 35}
    mult = {'none': 0.5, 'low': 0.7, 'med': 0.9, 'high': 1.0, 'critical': 1.1}
    capped = min(caps.get(tier, 20), int(base * mult.get(tier, 0.8)))

    if days >= 730 and tier in ('none', 'low'):
        capped = max(0, capped - 8)

    return float(capped)

# ---------------------------- urgência por SLA -------------------------------
def _sla_component(vuln: Dict) -> float:
    violates_sla = _safe_bool(vuln.get('violates_sla'))
    if violates_sla:
        return 100.0

    sla_days = _safe_float(vuln.get('sla_days_remaining'), None)
    if sla_days is None:
        return 25.0

    if sla_days < 0:
        return 100.0
    if sla_days <= 3:
        return 95.0
    if sla_days <= 7:
        return 90.0
    if sla_days <= 14:
        return 80.0
    if sla_days <= 30:
        return 70.0
    if sla_days <= 60:
        return 50.0
    if sla_days <= 90:
        return 30.0
    return 20.0

# -------------------------- integrações Q1/Q3/Q4 -----------------------------
def _exploit_factor_from_q1(q1: Optional[float], tier: str, has_poc: bool, has_kev: bool) -> float:
    """
    Fator multiplicador para a *ameaça* baseado no Q1.
    - Baixo Q1 e sem sinais → derruba ameaça (evita FP).
    - Q1 muito alto dá leve boost.
    """
    if q1 is None:
        return 1.0
    q1 = float(q1)
    if (not has_poc and not has_kev) and tier in ('none', 'low'):
        if q1 < 25:  return 0.75
        if q1 < 50:  return 0.90
        return 1.00
    # Sinais existem (PoC/KEV) → efeito suave
    if q1 >= 85:     return 1.07
    if q1 >= 70:     return 1.04
    if q1 < 30:      return 0.95
    return 1.00

def _impact_factor_from_q3(q3: Optional[float], has_kev: bool, sla_urgent: bool) -> float:
    """
    Fator multiplicador para a *ameaça* baseado no Q3 (impacto).
    - Q3 baixo reduz um pouco a parte de ameaça/idade.
    - Não derrubamos nada quando KEV ou SLA violado (manter urgência).
    """
    if q3 is None:
        return 1.0
    q3 = float(q3)
    if has_kev or sla_urgent:
        return 1.0
    if q3 < 30:   return 0.80
    if q3 < 50:   return 0.92
    if q3 < 70:   return 1.00
    if q3 >= 85:  return 1.06
    return 1.02

def _fixability_nudge_from_q4(q4: Optional[float]) -> float:
    """
    'Nudge' tático no Q5 final com base na facilidade de correção:
    - Muito fácil (>=80) → pequeno incentivo (3%).
    - Muito difícil (<=20) → leve freio (3%).
    """
    if q4 is None:
        return 1.0
    q4 = float(q4)
    if q4 >= 80: return 1.03
    if q4 <= 20: return 0.97
    return 1.00

# ------------------------------ função principal -----------------------------
def calculate_q5_urgency(vuln_data: Dict, external_fetcher) -> float:
    """
    Q5: Urgência operacional (0-100)

    Sinais:
    1) SLA (domina quando ameaça é baixa)
    2) Ameaça (EPSS contínuo + PoC + KEV + recência)
    3) Idade (gated por ameaça; cooldown p/ CVEs antigas e frias)
    4) Exposição leve (Q2 ou heurística) → modula a ameaça
    5) Integrações Q1/Q3/Q4 → reduzem FP e afinam a priorização
    """
    cve = vuln_data.get('vulnerability_ids', 'unknown')

    # --- 1) SLA
    sla_u = _sla_component(vuln_data)
    sla_urgent = _safe_bool(vuln_data.get('violates_sla')) or (_safe_float(vuln_data.get('sla_days_remaining'), 1) < 0)

    # --- 2) Ameaça bruta (EPSS/PoC/KEV)
    tb = _threat_block(vuln_data, external_fetcher)
    threat = tb['score']
    tier = tb['tier']
    has_poc = tb['has_poc']
    has_kev = tb['has_kev']

    # --- 3) Exposição modula ameaça (preferindo Q2)
    exp_factor = _exposure_factor(vuln_data)
    threat *= exp_factor
    threat = min(100.0, threat)

    # --- 4) Idade com gating
    age_u = _age_urgency(vuln_data, tier)

    # --- 5) Integrações Q1/Q3/Q4 (reduzem FP)
    q1 = _safe_float(vuln_data.get('q1_exploitability'), None)
    q3 = _safe_float(vuln_data.get('q3_impact'), None)
    q4 = _safe_float(vuln_data.get('q4_fixability'), None)

    # Exploitability (Q1) → modula ameaça
    threat *= _exploit_factor_from_q1(q1, tier, has_poc, has_kev)
    # Impact (Q3) → modula ameaça e envelhecimento (via fator aplicado ao bloco threat)
    threat *= _impact_factor_from_q3(q3, has_kev, sla_urgent)
    threat = min(100.0, max(0.0, threat))

    # --- 6) Pesos dinâmicos por tier
    if tier in ('none', 'low'):
        w_sla, w_thr, w_age = 0.65, 0.25, 0.10
    elif tier == 'critical':
        w_sla, w_thr, w_age = 0.45, 0.40, 0.15
    else:  # 'med'|'high'
        w_sla, w_thr, w_age = 0.50, 0.35, 0.15

    q5 = w_sla * sla_u + w_thr * threat + w_age * age_u

    # --- 7) Verificação/Confiança refinam confiança operacional
    verified = _safe_bool(vuln_data.get('verified'))
    dynamic  = _safe_bool(vuln_data.get('dynamic_finding'))
    if verified: q5 *= 1.04
    if dynamic:  q5 *= 1.03

    conf = _safe_float(vuln_data.get('scanner_confidence'), None)
    if conf is not None:
        conf01 = conf if conf <= 1 else conf / 100.0
        if conf01 < 0.5 and not has_kev and tier in ('none', 'low'):
            q5 *= 0.85  # queda de urgência quando confiança baixa e sem sinais

    # --- 8) Nudge tático por fixabilidade (Q4)
    q5 *= _fixability_nudge_from_q4(q4)

    # --- 9) Management overrides (redução de FP operacionais)
    if _safe_bool(vuln_data.get('risk_accepted')):
        q5 *= 0.30
    if _safe_bool(vuln_data.get('is_mitigated')):
        q5 *= 0.50
    if _safe_bool(vuln_data.get('false_p')):
        q5 *= 0.20

    # --- 10) Curto-circuitos e limites
    if sla_urgent:
        q5 = max(q5, 100.0)  # garante 100 quando SLA violado
    q5 = float(min(100.0, max(0.0, q5)))

    logger.debug(
        f"[Q5] {cve}: SLA={sla_u:.0f}, Tier={tier}, Threat(mod)={threat:.0f}, "
        f"Age={age_u:.0f}, Q1={q1}, Q3={q3}, Q4={q4}, ExpFac={exp_factor:.2f} → Final={q5:.0f}"
    )
    return q5
