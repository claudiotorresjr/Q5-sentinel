#!/usr/bin/env python3
"""
Módulo de modelos de dados para o sistema de priorização de vulnerabilidades

Contém dataclasses e estruturas de dados utilizadas no sistema RPI (Risk-Priority Index)

Autor: Security Analytics Team
Data: 2025
Versão: 6.0 - Estruturas completas com todos os campos
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional

# models.py
# ... mantém imports e classes anteriores ...

@dataclass
class ProcessingConfig:
    """Configuration for vulnerability processing and ranking."""
    # Existing fields...
    num_processes: int = 4
    enable_progress_bars: bool = True
    export_csv: bool = True
    top_n_report: int = 20

    # 5Q weights must add up to 1.0
    weights: Dict[str, float] = field(default_factory=lambda: {
        'q1': 0.25, 'q2': 0.20, 'q3': 0.30, 'q4': 0.10, 'q5': 0.15
    })

    # --- NEW: Funnel (tie-heavy) configuration ---
    funnel_enabled: bool = True
    top_k_for_funnel: int = 1000          # how many from the top to inspect
    funnel_threshold: int = 50            # minimum equal-score items to trigger funnel
    funnel_equal_epsilon: float = 1e-4    # score tolerance to consider “equal”

    # MCDM settings for local re-ranking (within equal-score groups)
    mcdm_use_topsis: bool = True
    mcdm_weights: Dict[str, float] = field(default_factory=lambda: {
        # Benefit criteria (higher is better):
        'q1': 0.22,      # exploitability
        'q2': 0.18,      # exposure
        'q3': 0.26,      # impact
        'q5': 0.14,      # urgency
        'epss': 0.08,    # EPSS percentile
        'occ': 0.06,     # occurrences
        'conf': 0.04,    # scanner confidence
        # Cost criterion (lower is better):
        'effort': 0.02   # effort to fix (cost)
    })

    thresholds: Dict[str, float] = field(default_factory=lambda: {
        'critical_rpi': 80.0, 'high_rpi': 60.0, 'medium_rpi': 40.0, 'low_rpi': 20.0
    })

    def validate(self) -> bool:
        """Validate config sanity."""
        if abs(sum(self.weights.values()) - 1.0) > 0.01:
            raise ValueError("5Q weights must sum to 1.0")
        # MCDM weights can sum to <= 1.0 (they’re local and optional).
        return True


@dataclass
class VulnerabilityMetrics:
    """Classe para armazenar métricas calculadas de vulnerabilidade"""

    # Scores das 5 perguntas (0-100)
    q1_exploitability: float = 0.0
    q2_exposure: float = 0.0
    q3_impact: float = 0.0
    q4_fixability: float = 0.0
    q5_urgency: float = 0.0

    # Score final RPI
    rpi_score: float = 0.0

    # Classificação
    domain: str = ""
    is_runtime: bool = False

    # Indicadores de exploração
    has_kev: bool = False
    has_poc: bool = False
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    threat_heat: float = 0.0

    # Validação e confiança
    is_verified: bool = False
    is_dynamic: bool = False
    is_static: bool = False
    scanner_confidence: float = 1.0

    # Exposição
    has_url: bool = False
    has_endpoints: bool = False
    endpoint_count: int = 0
    environment: str = "unknown"  # production, development, unknown

    # Impacto
    nb_occurrences: int = 1
    asset_criticality: int = 5  # 1-10
    cvss_score: float = 0.0
    severity: str = "medium"

    # SLA e urgência
    violates_sla: bool = False
    sla_days_remaining: float = 999.0
    sla_age: float = 0.0

    # Estados de gestão (penalidades)
    is_accepted: bool = False      # risk_accepted
    is_mitigated: bool = False     # is_mitigated
    is_false_positive: bool = False  # false_p

    # Gestão
    has_jira: bool = False
    has_owner: bool = False
    effort_for_fixing: str = ""

    # Metadados adicionais
    component_name: str = ""
    component_version: str = ""
    cve_id: str = ""
    cwe: str = ""

    def to_dict(self) -> Dict:
        """Converte métricas para dicionário"""
        return {
            'q1_exploitability': self.q1_exploitability,
            'q2_exposure': self.q2_exposure,
            'q3_impact': self.q3_impact,
            'q4_fixability': self.q4_fixability,
            'q5_urgency': self.q5_urgency,
            'rpi_score': self.rpi_score,
            'domain': self.domain,
            'is_runtime': self.is_runtime,
            'has_kev': self.has_kev,
            'has_poc': self.has_poc,
            'epss_score': self.epss_score,
            'epss_percentile': self.epss_percentile,
            'is_verified': self.is_verified,
            'is_dynamic': self.is_dynamic,
            'scanner_confidence': self.scanner_confidence,
            'has_url': self.has_url,
            'has_endpoints': self.has_endpoints,
            'environment': self.environment,
            'nb_occurrences': self.nb_occurrences,
            'asset_criticality': self.asset_criticality,
            'violates_sla': self.violates_sla,
            'sla_days_remaining': self.sla_days_remaining,
            'is_accepted': self.is_accepted,
            'is_mitigated': self.is_mitigated,
            'is_false_positive': self.is_false_positive,
            'has_jira': self.has_jira,
            'effort_for_fixing': self.effort_for_fixing
        }


@dataclass
class ProcessingConfig:
    """Configuração para processamento de vulnerabilidades"""

    # Configurações de processamento
    num_processes: int = 4
    enable_progress_bars: bool = True
    export_csv: bool = True
    top_n_report: int = 20

    # Pesos base das 5 perguntas (devem somar 1.0)
    weights: Dict[str, float] = field(default_factory=lambda: {
        'q1': 0.30,  # Exploitability - peso alto
        'q2': 0.20,  # Exposure - peso médio
        'q3': 0.25,  # Impact - peso alto
        'q4': 0.10,  # Fixability - peso baixo
        'q5': 0.15   # Urgency - peso médio
    })

    # Fatores de acoplamento
    coupling_strength: float = 0.3  # Força dos acoplamentos entre perguntas

    # Multiplicadores de validação
    validation_multipliers: Dict[str, float] = field(default_factory=lambda: {
        'verified': 1.15,        # Verificado manualmente
        'dynamic': 1.10,         # Finding dinâmico
        'low_confidence': 0.70   # Baixa confiança do scanner
    })

    # Penalidades (multiplicadores aplicados ao RPI final)
    penalties: Dict[str, float] = field(default_factory=lambda: {
        'risk_accepted': 0.05,      # 95% penalty - quase ignorar
        'is_mitigated': 0.10,       # 90% penalty - já foi mitigado
        'false_positive': 0.20,     # 80% penalty - falso positivo
    })

    # Bonificações por múltiplas ocorrências
    occurrence_multipliers: Dict[str, float] = field(default_factory=lambda: {
        'low': 1.0,      # 1-5 ocorrências
        'medium': 1.2,   # 5-20 ocorrências
        'high': 1.4,     # 20-100 ocorrências
        'critical': 2.0  # 100+ ocorrências
    })

    # Limites para categorização
    thresholds: Dict[str, float] = field(default_factory=lambda: {
        'critical_rpi': 80.0,
        'high_rpi': 60.0,
        'medium_rpi': 40.0,
        'low_rpi': 20.0
    })

    def validate(self) -> bool:
        """Valida configuração"""
        # Verifica se pesos somam 1.0
        total_weight = sum(self.weights.values())
        if abs(total_weight - 1.0) > 0.01:
            raise ValueError(f"Pesos devem somar 1.0, mas somam {total_weight}")
        return True


@dataclass
class VulnerabilityData:
    """Estrutura unificada para dados de vulnerabilidade"""
    raw_data: Dict
    metrics: Optional[VulnerabilityMetrics] = None
    tie_breaker_key: Optional[Tuple] = None
    processed: bool = False
    priority_rank: int = 0
    rpi_category: str = "unknown"  # critical, high, medium, low

    @property
    def rpi_score(self) -> float:
        return self.metrics.rpi_score if self.metrics else 0.0

    @property
    def domain(self) -> str:
        return self.metrics.domain if self.metrics else ""

    @property
    def cve_id(self) -> str:
        return self.raw_data.get('vulnerability_ids', '')

    @property
    def title(self) -> str:
        return self.raw_data.get('title', 'No title')

    def categorize_rpi(self, config: ProcessingConfig) -> str:
        """Categoriza vulnerabilidade baseado no RPI score"""
        if self.rpi_score >= config.thresholds['critical_rpi']:
            return 'critical'
        elif self.rpi_score >= config.thresholds['high_rpi']:
            return 'high'
        elif self.rpi_score >= config.thresholds['medium_rpi']:
            return 'medium'
        elif self.rpi_score >= config.thresholds['low_rpi']:
            return 'low'
        else:
            return 'minimal'

    def to_dict(self) -> Dict:
        """Converte para dicionário mantendo compatibilidade"""
        result = self.raw_data.copy()
        if self.metrics:
            result['rpi_metrics'] = self.metrics
            result['rpi_score'] = self.metrics.rpi_score
            result['domain'] = self.metrics.domain
            result['rpi_category'] = self.categorize_rpi(ProcessingConfig())
        if self.tie_breaker_key:
            result['tie_breaker_key'] = self.tie_breaker_key
        result['priority_rank'] = self.priority_rank
        return result

    def get_summary(self) -> str:
        """Retorna resumo da vulnerabilidade"""
        return (
            f"#{self.priority_rank} - RPI: {self.rpi_score:.1f} - {self.title[:50]}\n"
            f"  CVE: {self.cve_id} | Domain: {self.domain}\n"
            f"  5Q: Q1={self.metrics.q1_exploitability:.0f} Q2={self.metrics.q2_exposure:.0f} "
            f"Q3={self.metrics.q3_impact:.0f} Q4={self.metrics.q4_fixability:.0f} "
            f"Q5={self.metrics.q5_urgency:.0f}"
        )


@dataclass
class RPIStatistics:
    """Estatísticas agregadas do processamento RPI"""
    total_processed: int = 0
    total_unique: int = 0
    total_errors: int = 0

    # Distribuição por categoria
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    minimal_count: int = 0

    # Estatísticas de scores
    max_rpi: float = 0.0
    min_rpi: float = 100.0
    avg_rpi: float = 0.0
    median_rpi: float = 0.0

    # Estatísticas especiais
    kev_count: int = 0
    poc_count: int = 0
    sla_violations: int = 0
    verified_count: int = 0
    dynamic_count: int = 0

    # Distribuição por domínio
    domain_distribution: Dict[str, int] = field(default_factory=dict)

    # Top vulnerabilidades
    top_vulnerabilities: List[str] = field(default_factory=list)

    def calculate_from_results(self, results: List[Dict], config: ProcessingConfig):
        """Calcula estatísticas a partir dos resultados"""
        if not results:
            return

        self.total_processed = len(results)

        rpi_scores = []
        for vuln in results:
            metrics = vuln.get('rpi_metrics')
            if not metrics:
                continue

            rpi = metrics.rpi_score
            rpi_scores.append(rpi)

            # Categorização
            if rpi >= config.thresholds['critical_rpi']:
                self.critical_count += 1
            elif rpi >= config.thresholds['high_rpi']:
                self.high_count += 1
            elif rpi >= config.thresholds['medium_rpi']:
                self.medium_count += 1
            elif rpi >= config.thresholds['low_rpi']:
                self.low_count += 1
            else:
                self.minimal_count += 1

            # Contadores especiais
            if metrics.has_kev:
                self.kev_count += 1
            if metrics.has_poc:
                self.poc_count += 1
            if metrics.violates_sla:
                self.sla_violations += 1
            if metrics.is_verified:
                self.verified_count += 1
            if metrics.is_dynamic:
                self.dynamic_count += 1

            # Domínio
            domain = metrics.domain
            self.domain_distribution[domain] = self.domain_distribution.get(domain, 0) + 1

        # Estatísticas de score
        if rpi_scores:
            self.max_rpi = max(rpi_scores)
            self.min_rpi = min(rpi_scores)
            self.avg_rpi = sum(rpi_scores) / len(rpi_scores)
            sorted_scores = sorted(rpi_scores)
            mid = len(sorted_scores) // 2
            if len(sorted_scores) % 2 == 0:
                self.median_rpi = (sorted_scores[mid-1] + sorted_scores[mid]) / 2
            else:
                self.median_rpi = sorted_scores[mid]

        # Top vulnerabilidades
        self.top_vulnerabilities = [
            f"{vuln.get('vulnerability_ids', 'N/A')} - {vuln.get('title', 'N/A')[:50]}"
            for vuln in results[:5]
        ]

    def get_summary(self) -> str:
        """Retorna resumo das estatísticas"""
        return f"""
=== ESTATÍSTICAS RPI ===
Total processado: {self.total_processed}
RPI médio: {self.avg_rpi:.1f} | Mediana: {self.median_rpi:.1f}
RPI máximo: {self.max_rpi:.1f} | Mínimo: {self.min_rpi:.1f}

Distribuição:
- Crítico: {self.critical_count}
- Alto: {self.high_count}
- Médio: {self.medium_count}
- Baixo: {self.low_count}
- Mínimo: {self.minimal_count}

Indicadores:
- Com KEV: {self.kev_count}
- Com PoC: {self.poc_count}
- SLA violado: {self.sla_violations}
- Verificados: {self.verified_count}
- Dinâmicos: {self.dynamic_count}
"""
