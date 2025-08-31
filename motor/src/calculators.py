#!/usr/bin/env python3
"""
Módulo de calculadoras para o sistema de priorização de vulnerabilidades

Contém as classes responsáveis pelos cálculos de RPI e lógica de desempate

Autor: Security Analytics Team
Data: 2025
Versão: 6.0 - Corrigida com acoplamentos e penalidades
"""

import logging
from typing import Dict, Tuple
from q1_calculator import calculate_q1_exploitability, ExternalDataFetcher
from q2_calculator import calculate_q2_exposure, VulnerabilityClassifier
from q3_calculator import calculate_q3_impact
from q4_calculator import calculate_q4_fixability
from q5_calculator import calculate_q5_urgency
from models import VulnerabilityMetrics, ProcessingConfig

logger = logging.getLogger(__name__)


class RiskPriorityCalculator:
    """Calcula o RPI (Risk-Priority Index) usando a metodologia 5Q com acoplamentos"""

    def __init__(self, external_fetcher: ExternalDataFetcher, config: ProcessingConfig = None):
        self.external_fetcher = external_fetcher
        self.classifier = VulnerabilityClassifier()
        self.config = config or ProcessingConfig()

    def calculate_rpi_worker(self, vuln_data: Dict, kev_data: Dict, epss_data: Dict) -> Tuple[Dict, VulnerabilityMetrics]:
        """Função worker para calcular RPI de uma vulnerabilidade (usada em multiprocessing)"""
        try:
            # Valida campos críticos
            if not vuln_data.get('title') and not vuln_data.get('vulnerability_ids') and not vuln_data.get('component_name'):
                return vuln_data, None

            # Calcula métricas
            metrics = self.calculate_rpi(vuln_data)

            # Adiciona métricas ao objeto
            vuln_data['rpi_metrics'] = metrics
            vuln_data['rpi_score'] = metrics.rpi_score
            vuln_data['domain'] = metrics.domain

            return vuln_data, metrics
        except Exception as e:
            logger.debug(f"Erro processando vulnerabilidade: {e}")
            return vuln_data, None

    def calculate_rpi(self, vuln_data: Dict) -> VulnerabilityMetrics:
        """
        Calcula RPI com acoplamentos sofisticados entre as 5 perguntas

        Acoplamentos implementados:
        - Gate de exploitabilidade (g_exploit): Q1 → [Q3, Q5]
        - Gate de superfície (g_surface): Q2 → [Q1, Q5]
        - Fator ambiental (f_env): ambiente → [Q2, Q5]
        - Validações (verified, dynamic) → boost geral
        - Penalidades (accepted, mitigated, false_p) → redução drástica
        """
        metrics = VulnerabilityMetrics()

        # 1) Calcula scores base das 5 perguntas
        metrics.q1_exploitability = calculate_q1_exploitability(vuln_data, self.external_fetcher)
        metrics.q2_exposure       = calculate_q2_exposure(vuln_data, self.classifier)
        metrics.q3_impact         = calculate_q3_impact(vuln_data, self.classifier)
        metrics.q4_fixability     = calculate_q4_fixability(vuln_data, self.classifier)

        # -- NOVO: disponibiliza Q1..Q4 no vuln_data para o Q5 usar diretamente
        vuln_data['q1_exploitability'] = metrics.q1_exploitability
        vuln_data['q2_exposure']       = metrics.q2_exposure
        vuln_data['q3_impact']         = metrics.q3_impact
        vuln_data['q4_fixability']     = metrics.q4_fixability

        # Também expõe is_runtime (ajuda a heurística do Q5 quando Q2 não vier setado)
        metrics.is_runtime = self.classifier.is_runtime_dependency(vuln_data)
        vuln_data['is_runtime'] = metrics.is_runtime

        # 2) Agora sim chama o Q5 com os sinais já no vuln_data
        metrics.q5_urgency = calculate_q5_urgency(vuln_data, self.external_fetcher)

        # Metadados importantes
        metrics.domain = self.classifier.classify_domain(vuln_data)
        metrics.is_runtime = self.classifier.is_runtime_dependency(vuln_data)
        cve_id = vuln_data.get('vulnerability_ids', '')
        metrics.has_kev = cve_id in self.external_fetcher.kev_data
        poc_info = self.external_fetcher.check_poc_availability(cve_id)
        metrics.has_poc = poc_info.get('has_poc', False)
        if cve_id in self.external_fetcher.epss_data:
            metrics.epss_score = self.external_fetcher.epss_data[cve_id].get('epss', 0.0)
            metrics.epss_percentile = self.external_fetcher.epss_data[cve_id].get('percentile', 0.0)

        # 2) Gates de acoplamento baseados em Q1 (exploitability)
        epss = float(metrics.epss_score or 0.0)
        if metrics.has_kev:
            g_exploit = 1.20  # KEV = máximo gate (20% boost)
        elif metrics.has_poc:
            g_exploit = 1.15  # PoC = alto gate (15% boost)
        elif epss >= 0.50:
            g_exploit = 1.10  # EPSS alto = gate médio (10% boost)
        elif epss >= 0.20:
            g_exploit = 1.05  # EPSS médio = gate pequeno (5% boost)
        else:
            g_exploit = 1.00  # Sem evidência de exploração

        # 3) Gates de acoplamento baseados em Q2 (exposure)
        q2_base = float(metrics.q2_exposure or 0.0)
        if q2_base >= 80:
            g_surface = 1.15  # Alta exposição amplifica tudo (15% boost)
        elif q2_base >= 60:
            g_surface = 1.08  # Exposição média (8% boost)
        else:
            g_surface = 0.95  # Baixa exposição reduz (5% penalty)

        # 4) Fator ambiental (produção vs dev/test)
        def _env_factor():
            txt = " ".join(str(vuln_data.get(k, "")) for k in ("product", "service", "url", "title")).lower()
            prod_like = any(s in txt for s in ("prod", "production", "prd"))
            dev_like = any(s in txt for s in ("dev", "test", "stage", "stg", "homolog", "hml", "qa"))
            if prod_like and not dev_like:
                return 1.10  # Produção = 10% boost
            if dev_like and not prod_like:
                return 0.85  # Dev/Test = 15% penalty
            return 1.00
        f_env = _env_factor()

        # 5) Aplica acoplamentos aos scores
        # Q2 amplifica Q1 (exposição aumenta exploitabilidade percebida)
        q1_coupled = min(100.0, metrics.q1_exploitability * g_surface)

        # Ambiente afeta Q2 (produção vs dev)
        q2_coupled = min(100.0, metrics.q2_exposure * f_env)

        # Q1 amplifica Q3 (fácil de explorar = maior impacto potencial)
        q3_coupled = min(100.0, metrics.q3_impact * g_exploit)

        # Q4 não é acoplado (fixability é independente)
        q4_coupled = metrics.q4_fixability

        # Q5 é fortemente influenciado por Q1, Q2 e ambiente
        q5_coupled = min(100.0, metrics.q5_urgency * (0.7 + 0.3 * g_exploit) * (0.8 + 0.2 * g_surface) * f_env)

        # 6) Validações e confiança
        validation_boost = 1.0

        # Finding verificado = mais confiável
        if vuln_data.get('verified') is True or str(vuln_data.get('verified', '')).lower() == 'true':
            validation_boost *= 1.15  # 15% boost

        # Finding dinâmico = sistema em execução real
        if vuln_data.get('dynamic_finding') is True or str(vuln_data.get('dynamic_finding', '')).lower() == 'true':
            validation_boost *= 1.10  # 10% boost

        # Scanner confidence baixa = reduz score
        scanner_conf = vuln_data.get('scanner_confidence')
        if scanner_conf not in (None, "NaN", ""):
            try:
                conf_value = float(scanner_conf)
                if conf_value < 0.5:
                    validation_boost *= 0.7  # 30% penalty para baixa confiança
            except:
                pass

        # 7) Número de ocorrências (crítico!)
        nb_occurences = vuln_data.get('nb_occurences')
        if nb_occurences not in (None, "NaN", ""):
            try:
                occ = float(nb_occurences)
                if occ > 100:
                    q3_coupled = min(100.0, q3_coupled * 1.5)  # 50% boost para muitas ocorrências
                elif occ > 50:
                    q3_coupled = min(100.0, q3_coupled * 1.3)  # 30% boost
                elif occ > 10:
                    q3_coupled = min(100.0, q3_coupled * 1.15)  # 15% boost
            except:
                pass

        # 8) Cálculo do RPI ponderado com validações
        rpi = (
            self.config.weights['q1'] * q1_coupled +
            self.config.weights['q2'] * q2_coupled +
            self.config.weights['q3'] * q3_coupled +
            self.config.weights['q4'] * q4_coupled +
            self.config.weights['q5'] * q5_coupled
        ) * validation_boost

        # 9) PENALIDADES CRÍTICAS (aplicadas no final)

        # Risco aceito = praticamente ignorar
        if vuln_data.get('risk_accepted') is True or str(vuln_data.get('risk_accepted', '')).lower() == 'true':
            rpi *= 0.05  # 95% penalty - quase zero prioridade

        # Mitigado = muito baixa prioridade
        if vuln_data.get('is_mitigated') is True or str(vuln_data.get('is_mitigated', '')).lower() == 'true':
            rpi *= 0.10  # 90% penalty

        # False positive = redução significativa
        if vuln_data.get('false_p') is True or str(vuln_data.get('false_p', '')).lower() == 'true':
            rpi *= 0.20  # 80% penalty

        # 10) SLA violation override - máxima prioridade
        if vuln_data.get('violates_sla') is True or str(vuln_data.get('violates_sla', '')).lower() == 'true':
            rpi = max(rpi, 85.0)  # Garante score mínimo alto para SLA violations

        # Armazena scores finais acoplados
        metrics.q1_exploitability = q1_coupled
        metrics.q2_exposure = q2_coupled
        metrics.q3_impact = q3_coupled
        metrics.q4_fixability = q4_coupled
        metrics.q5_urgency = q5_coupled
        metrics.rpi_score = max(0.0, min(100.0, rpi))

        return metrics


class TieBreaker:
    """Implementa lógica de desempate determinística e sofisticada"""

    @staticmethod
    def get_tie_breaker_key(vuln_data: Dict, metrics: VulnerabilityMetrics) -> tuple:
        """
        Gera tupla de ordenação para desempate

        Ordem de prioridade:
        1. Violação de SLA
        2. Verificado
        3. Finding dinâmico
        4. Não é false positive
        5. Não está mitigado
        6. Não foi aceito
        7. Alta confiança do scanner
        8. Tem KEV
        9. EPSS percentile alto
        10. Muitas ocorrências
        11. Tem endpoints/URL
        12. CVSS alto
        13. Runtime dependency
        14. Menor esforço para corrigir
        15. Já tem Jira issue
        16. ID único para estabilidade
        """

        # Helper para valores None/NaN
        def safe_value(val, default=0, negate=False):
            if val is None or str(val).lower() in ['nan', 'none', '']:
                return default
            try:
                num_val = float(val)
                return -num_val if negate else num_val
            except:
                return default

        # Helper para booleanos
        def safe_bool(val):
            if val is True or str(val).lower() == 'true':
                return 1
            return 0

        # 1. SLA/Tempo
        violates_sla = safe_bool(vuln_data.get('violates_sla'))
        sla_days = safe_value(vuln_data.get('sla_days_remaining'), 999999)
        sla_deadline = vuln_data.get('sla_deadline', '9999-12-31')

        # 2. Validações
        verified = safe_bool(vuln_data.get('verified'))
        dynamic = safe_bool(vuln_data.get('dynamic_finding'))
        false_p = safe_bool(vuln_data.get('false_p'))
        is_mitigated = safe_bool(vuln_data.get('is_mitigated'))
        risk_accepted = safe_bool(vuln_data.get('risk_accepted'))

        # 3. Confiança
        confidence = safe_value(vuln_data.get('scanner_confidence'), 0.5, negate=True)

        # 4. Exploração real
        has_kev = 1 if metrics.has_kev else 0
        epss_percentile = safe_value(metrics.epss_percentile, 0, negate=True)

        # 5. Exposição
        endpoints = vuln_data.get('endpoints', '')
        endpoints_count = len(str(endpoints).split(',')) if endpoints and str(endpoints) != 'NaN' else 0
        has_url = 1 if vuln_data.get('url') and str(vuln_data.get('url')) != 'NaN' else 0

        # 6. Impacto técnico
        cvss = safe_value(vuln_data.get('cvssv3_score'), 0, negate=True)

        # 7. Abrangência
        occurences = safe_value(vuln_data.get('nb_occurences'), 1, negate=True)

        # 8. Contexto
        is_runtime = 1 if metrics.is_runtime else 0

        # 9. Velocidade de correção
        effort = safe_value(vuln_data.get('effort_for_fixing'), 999999)
        has_jira = safe_bool(vuln_data.get('has_jira_issue'))

        # 10. Estabilidade (ID único)
        unique_id = vuln_data.get('unique_id_from_tool', vuln_data.get('id', ''))

        return (
            -violates_sla,      # Violações de SLA primeiro
            sla_days,           # Menor prazo SLA primeiro
            sla_deadline,       # Data SLA mais próxima
            -verified,          # Verificados primeiro
            -dynamic,           # Dinâmicos primeiro
            false_p,            # Não false positives primeiro (invertido)
            is_mitigated,       # Não mitigados primeiro (invertido)
            risk_accepted,      # Não aceitos primeiro (invertido)
            confidence,         # Maior confiança primeiro (já negado)
            -has_kev,          # KEV primeiro
            epss_percentile,    # Maior EPSS primeiro (já negado)
            occurences,         # Mais ocorrências primeiro (já negado)
            -endpoints_count,   # Mais endpoints primeiro
            -has_url,          # Com URL primeiro
            cvss,              # Maior CVSS primeiro (já negado)
            -is_runtime,       # Runtime primeiro
            effort,            # Menor esforço primeiro
            -has_jira,         # Com Jira primeiro
            unique_id          # ID único para estabilidade
        )
