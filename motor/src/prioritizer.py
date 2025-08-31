#!/usr/bin/env python3
"""
Módulo do priorizador principal para o sistema de priorização de vulnerabilidades

Contém a classe VulnerabilityPrioritizer que orquestra todo o processo

Autor: Security Analytics Team
Data: 2025
Versão: 5.0 - Modular
"""

import json
import logging
from typing import List, Dict, Optional
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing as mp
import pandas as pd
from q1_calculator import extract_cve_id, ExternalDataFetcher
from calculators import RiskPriorityCalculator, TieBreaker
from models import VulnerabilityMetrics, ProcessingConfig

logger = logging.getLogger(__name__)

# Tenta importar tqdm, se não tiver, usa alternativa simples
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    # Fallback simples se não conseguir instalar
    class tqdm:
        def __init__(self, iterable=None, total=None, desc=None, **kwargs):
            self.iterable = iterable
            self.total = total or (len(iterable) if iterable else 0)
            self.desc = desc or ""
            self.n = 0
            if self.desc:
                print(f"{self.desc}: processando {self.total} items...")
        def __iter__(self):
            for item in self.iterable:
                self.n += 1
                if self.n % max(1, self.total // 10) == 0:
                    print(f"  ...{self.n}/{self.total} ({100*self.n//self.total}%)")
                yield item
            def update(self, n=1):
                self.n += n
            def close(self):
                if self.desc and self.total:
                    print(f"  ✓ {self.desc} completo!")

# Defaults used if ProcessingConfig doesn't define these fields
DEFAULT_MCDM_WEIGHTS = {
    # Benefit criteria
    'q1': 0.22,   # exploitability
    'q2': 0.18,   # exposure
    'q3': 0.26,   # impact
    'q5': 0.14,   # urgency
    'epss': 0.08, # EPSS percentile
    'occ': 0.06,  # occurrences
    'conf': 0.04, # scanner confidence
    # Cost (inverted to benefit internally)
    'effort': 0.02
}

class VulnerabilityPrioritizer:
    """Classe principal que orquestra todo o processo de priorização"""

    def __init__(self, config: ProcessingConfig = None):
        self.config = config or ProcessingConfig()
        self._ensure_config_defaults()
        self.external_fetcher = ExternalDataFetcher()
        self.calculator = RiskPriorityCalculator(self.external_fetcher, self.config)
        self.tie_breaker = TieBreaker()

    def _ensure_config_defaults(self) -> None:
        """Ensure config has funnel/MCDM fields even if models.py is older."""
        cfg = self.config
        if not hasattr(cfg, "funnel_enabled"):
            cfg.funnel_enabled = True
        if not hasattr(cfg, "top_k_for_funnel"):
            cfg.top_k_for_funnel = 1000
        if not hasattr(cfg, "funnel_threshold"):
            cfg.funnel_threshold = 50
        if not hasattr(cfg, "funnel_equal_epsilon"):
            cfg.funnel_equal_epsilon = 1e-4
        if not hasattr(cfg, "mcdm_use_topsis"):
            cfg.mcdm_use_topsis = True
        if not hasattr(cfg, "mcdm_weights"):
            cfg.mcdm_weights = DEFAULT_MCDM_WEIGHTS.copy()


            # ---------------------- FUNNEL HELPERS ----------------------

    def _apply_funneling_if_needed(self, prioritized: List[Dict]) -> List[Dict]:
        """
        If there is a large equal-score group within the top-k region, apply a local
        cohort + MCDM (TOPSIS) re-ranking only to that group, keeping determinism.
        """
        cfg = self.config
        if not getattr(cfg, "funnel_enabled", True):
            return prioritized
        if not prioritized:
            return prioritized

        top_k = min(len(prioritized), getattr(cfg, "top_k_for_funnel", 1000))
        eps = float(getattr(cfg, "funnel_equal_epsilon", 1e-4))
        thr = int(getattr(cfg, "funnel_threshold", 50))

        # Group by (rounded) RPI in the top-k slice
        head = prioritized[:top_k]
        # Use rounding (2 decimals) first; fall back to epsilon check when needed
        # Collect groups as { score_key: [indices_in_head] }
        groups = {}
        for idx, v in enumerate(head):
            s = float(v.get("rpi_score", 0.0))
            key = round(s, 2)
            groups.setdefault(key, []).append(idx)

        # Find largest qualifying tie group (≥ threshold) within top-k
        candidate_key, candidate_idx_list = None, None
        for key, idxs in groups.items():
            if len(idxs) >= thr:
                # extra check: ensure scores are equal within epsilon
                vals = [head[i].get("rpi_score", 0.0) for i in idxs]
                if (max(vals) - min(vals)) <= eps:
                    if (candidate_idx_list is None) or (len(idxs) > len(candidate_idx_list)):
                        candidate_key, candidate_idx_list = key, idxs

        if not candidate_idx_list:
            return prioritized  # nothing to funnel

        # Apply cohort + local MCDM within the selected group
        block = [head[i] for i in candidate_idx_list]
        # Produce new order for this block
        re_sorted = self._reorder_equal_group(block)

        # Splice the re-ranked block back into the head
        for new_pos, old_idx in enumerate(candidate_idx_list):
            head[old_idx] = re_sorted[new_pos]

        # Recompose whole list
        return head + prioritized[top_k:]

    def _reorder_equal_group(self, block: List[Dict]) -> List[Dict]:
        """
        Re-rank an equal-score block using cohort buckets and local TOPSIS.
        Sort key: (bucket_rank, -topsis_score, original_tie_breaker_key)
        """
        # 1) Build tuples: (bucket_rank, topsis_score, tie_key, item)
        tuples = []
        for v in block:
            m = v.get("rpi_metrics")
            b = self._cohort_bucket(v, m)
            t = self._local_topsis_score(v, m)
            tie = v.get("tie_breaker_key", ())
            tuples.append((b, t, tie, v))

        # 2) Sort (bucket asc, topsis desc, existing tie-breaker)
        tuples.sort(key=lambda x: (x[0], -x[1], x[2]))
        return [t[-1] for t in tuples]

    def _cohort_bucket(self, vuln: Dict, metrics) -> int:
        """
        Map item to a deterministic cohort bucket:
          0: SLA violated
          1: KEV (known exploited)
          2: PoC/weaponized signal
          3: EPSS percentile ≥ 90
          4: High surface & impact (Q2 ≥ 80 and Q3 ≥ 80)
          5: Others
        """
        # Safety if metrics missing
        if not metrics:
            return 5
        if self._safe_bool(vuln.get("violates_sla")):
            return 0
        if getattr(metrics, "has_kev", False):
            return 1
        if getattr(metrics, "has_poc", False):
            return 2
        if float(getattr(metrics, "epss_percentile", 0.0) or 0.0) >= 90.0:
            return 3
        if float(getattr(metrics, "q2_exposure", 0.0) or 0.0) >= 80.0 and \
           float(getattr(metrics, "q3_impact", 0.0) or 0.0) >= 80.0:
            return 4
        return 5

    def _local_topsis_score(self, vuln: Dict, metrics) -> float:
        """
        Compute a local TOPSIS closeness coefficient in [0,1] for a single item.
        Only used inside equal-score groups to provide “fine texture”.
        """
        cfg = self.config
        if not getattr(cfg, "mcdm_use_topsis", True) or not metrics:
            return 0.0

        # Collect raw criteria (robust to missing values)
        q1 = self._safe_float(getattr(metrics, "q1_exploitability", None), 0.0)
        q2 = self._safe_float(getattr(metrics, "q2_exposure", None), 0.0)
        q3 = self._safe_float(getattr(metrics, "q3_impact", None), 0.0)
        q5 = self._safe_float(getattr(metrics, "q5_urgency", None), 0.0)
        epss_p = self._safe_float(getattr(metrics, "epss_percentile", None), 0.0)  # 0..100
        occ = self._safe_float(vuln.get("nb_occurences"), 0.0)                      # count
        conf = self._safe_float(vuln.get("scanner_confidence"), 0.0)                # 0..1 or 0..100
        if conf > 1.0:  # normalize if dataset has 0..100
            conf = conf / 100.0
        effort_raw = vuln.get("effort_for_fixing")
        eff = self._parse_effort(effort_raw)  # convert “Low/Medium/High/NNN” to numeric cost

        # Assemble vectors and weights
        w = getattr(cfg, "mcdm_weights", DEFAULT_MCDM_WEIGHTS)
        benefit = {
            'q1': q1, 'q2': q2, 'q3': q3, 'q5': q5,
            'epss': epss_p, 'occ': occ, 'conf': conf
        }
        cost = {'effort': eff}

        # Normalize (min-max). If flat, give neutral 0.5.
        def norm(val, lo, hi):
            if hi <= lo: return 0.5
            return (val - lo) / (hi - lo)

        # To compute min/max we need the block context; rebuild them once and cache.
        # For simplicity, use conservative bounds:
        #   Qs/EPSSp in [0,100], conf in [0,1], occ >=0 (cap at 99th percentile), effort >=0 (cap at 99th).
        # These bounds keep determinism without having to pass the whole block here.
        # If you prefer block-aware bounds, refactor _local_topsis_score to batch mode.
        cap_occ = 1.0 + (occ if occ < 1e6 else 1e6)  # avoid div/0 with min=0
        v_b = {
            'q1': norm(benefit['q1'], 0.0, 100.0),
            'q2': norm(benefit['q2'], 0.0, 100.0),
            'q3': norm(benefit['q3'], 0.0, 100.0),
            'q5': norm(benefit['q5'], 0.0, 100.0),
            'epss': norm(benefit['epss'], 0.0, 100.0),
            'occ': norm(min(benefit['occ'], cap_occ), 0.0, cap_occ),
            'conf': norm(benefit['conf'], 0.0, 1.0),
        }
        # Cost: lower is better → turn into benefit by 1 - normalized
        eff_cap = max(1.0, eff)
        v_c = {'effort': 1.0 - norm(min(eff, eff_cap), 0.0, eff_cap)}

        # Weighted ideal (TOPSIS)
        def wv(key, vec): return (w.get(key, 0.0) or 0.0) * vec[key]

        weighted = {k: wv(k, v_b) for k in v_b}
        weighted.update({k: wv(k, v_c) for k in v_c})

        # Ideal best/worst for each criterion (since we normalized to [0,1] already)
        # For benefit criteria, best=1, worst=0; for our “cost→benefit” already inverted, same rule applies.
        # Distance to ideals:
        import math
        d_plus = math.sqrt(sum((1.0 - weighted[k])**2 for k in weighted))
        d_minus = math.sqrt(sum((0.0 - weighted[k])**2 for k in weighted))

        if (d_plus + d_minus) == 0:
            return 0.0
        return d_minus / (d_plus + d_minus)

    # ---------------------- SMALL HELPERS ----------------------

    @staticmethod
    def _safe_bool(val) -> bool:
        """Return True for booleans or 'true' strings."""
        if val is True: return True
        s = str(val).strip().lower()
        return s == "true" or s == "1" or s == "yes"

    @staticmethod
    def _safe_float(val, default=0.0) -> float:
        """Best-effort float conversion."""
        try:
            if val is None: return default
            return float(val)
        except Exception:
            return default

    @staticmethod
    def _parse_effort(val) -> float:
        """
        Convert effort text/number to a non-negative cost scalar.
        Rules:
          - numeric string/int: use as-is (>=0)
          - 'low'/'medium'/'high': 1/5/10
          - unknown/empty: neutral 5
        """
        if val is None: return 5.0
        s = str(val).strip().lower()
        if s.isdigit():
            return max(0.0, float(s))
        if s in ("low", "baixo"):
            return 1.0
        if s in ("medium", "médio", "medio"):
            return 5.0
        if s in ("high", "alto"):
            return 10.0
        # try plain float
        try:
            return max(0.0, float(s))
        except Exception:
            return 5.0


    def process_vulnerability_worker(self, vuln_data: Dict) -> tuple[Dict, Optional[VulnerabilityMetrics]]:
        """Função worker global para multiprocessing - calcula RPI de uma vulnerabilidade"""
        try:
            # Valida campos críticos
            if not vuln_data.get('title') and not vuln_data.get('vulnerability_ids') and not vuln_data.get('component_name'):
                return vuln_data, None

            # Calcula métricas
            metrics = self.calculator.calculate_rpi(vuln_data)

            # Adiciona métricas ao objeto
            vuln_data['rpi_metrics'] = metrics
            vuln_data['rpi_score'] = metrics.rpi_score
            vuln_data['domain'] = metrics.domain

            return vuln_data, metrics
        except Exception as e:
            logger.debug(f"Erro processando vulnerabilidade: {e}")
            return vuln_data, None

    def process_vulnerabilities(self, vuln_list: List[Dict]) -> List[Dict]:
        """Processa lista de vulnerabilidades e retorna ordenada por prioridade"""

        print("\n" + "="*80)
        print("🚀 INICIANDO ANÁLISE DE VULNERABILIDADES")
        print("="*80)

        # 1. Deduplica vulnerabilidades
        print("\n📋 Etapa 1/5: Deduplicação")
        unique_vulns = self._deduplicate_vulnerabilities(vuln_list)
        logger.info(f"✅ Vulnerabilidades únicas: {len(unique_vulns)} de {len(vuln_list)} total")

        # 2. Busca dados externos
        print("\n🌐 Etapa 2/5: Coleta de dados externos")
        cve_list = []
        for v in tqdm(unique_vulns, desc="Extraindo CVEs", unit="vuln", disable=not self.config.enable_progress_bars):
            raw = v.get('vulnerability_ids', '')
            cve = extract_cve_id(raw)
            if cve:
                cve_list.append(cve)
        cve_list = list(set(cve_list))  # remove duplicates
        logger.info(f"📊 CVEs únicos encontrados: {len(cve_list)}")

        self.external_fetcher.fetch_kev_catalog()
        if cve_list:
            self.external_fetcher.fetch_epss_scores(cve_list)

        # 3. Calcula RPI para cada vulnerabilidade usando multiprocessing
        print("\n🧮 Etapa 3/5: Calculando RPI scores (5Q) - Multiprocessing")

        # Determina número de processos baseado no CPU disponível
        num_processes = min(mp.cpu_count(), len(unique_vulns))
        print(f"   Usando {num_processes} processos para cálculo paralelo")

        results = []
        errors = 0

        with ProcessPoolExecutor(max_workers=num_processes) as executor:
            # Submete todos os jobs usando o método da classe
            future_to_vuln = {executor.submit(self.process_vulnerability_worker, vuln): vuln for vuln in unique_vulns}

            # Processa resultados com barra de progresso
            with tqdm(total=len(unique_vulns), desc="Calculando RPI", unit="vuln", disable=not self.config.enable_progress_bars) as pbar:
                for future in as_completed(future_to_vuln):
                    vuln, metrics = future.result()
                    if metrics is not None:
                        # Gera chave de desempate
                        vuln['tie_breaker_key'] = self.tie_breaker.get_tie_breaker_key(vuln, metrics)
                        results.append(vuln)
                    else:
                        errors += 1
                    pbar.update(1)

        if errors > 0:
            logger.info(f"⚠️  Processadas {len(results)} vulnerabilidades com sucesso ({errors} erros ignorados)")

        if not results:
            logger.warning("❌ Nenhuma vulnerabilidade processada com sucesso!")
            return []

        # 4. Ordena por RPI e desempate
        print("\n🏆 Etapa 4/5: Ordenando por prioridade")
        sorted_results = sorted(
            results,
            key=lambda x: (-x['rpi_score'], x['tie_breaker_key'])
        )
        # 4.5 Funilamento (apenas se houver muitos empatados no topo)
        sorted_results = self._apply_funneling_if_needed(sorted_results)

        # 5. Finalização
        print("\n✨ Etapa 5/5: Finalizando análise")
        top_vuln = sorted_results[0]
        print(f"\n🎯 Top vulnerabilidade identificada:")
        print(f"   {top_vuln.get('title', 'N/A')[:70]}")
        print(f"   RPI Score: {top_vuln['rpi_score']:.2f}")
        print(f"   Domínio: {top_vuln.get('domain', 'N/A')}")

        return sorted_results

    def _deduplicate_vulnerabilities(self, vuln_list: List[Dict]) -> List[Dict]:
        """Remove duplicatas e contabiliza ocorrências

        Identifica vulnerabilidades únicas pelo CVE, hash_code ou unique_id. Para
        cada conjunto de duplicatas, mantém a primeira entrada e anota quantas
        vezes apareceu no campo nb_occurences. Isso permite que cálculos de
        impacto considerem a superfície total dessa vulnerabilidade.
        """
        unique_map: Dict[str, Dict] = {}
        counts: Dict[str, int] = {}

        for vuln in vuln_list:
            # Cria identificador único baseado em CVE, hash ou unique_id
            cve_id = vuln.get('vulnerability_ids', '') or ''
            hash_code = vuln.get('hash_code', '') or ''
            unique_id = vuln.get('unique_id_from_tool', '') or ''
            # Normaliza identificador
            identifier = cve_id or hash_code or unique_id or str(vuln.get('id', ''))
            if not identifier:
                # Se nada disponível, usa representação do objeto como fallback
                identifier = str(id(vuln))
            # Incrementa contagem
            counts[identifier] = counts.get(identifier, 0) + 1
            # Armazena apenas a primeira ocorrência
            if identifier not in unique_map:
                unique_map[identifier] = vuln

        # Atribui número de ocorrências às vulnerabilidades deduplicadas
        unique_list = []
        for identifier, vuln in unique_map.items():
            nb_occ = counts.get(identifier, 1)
            vuln['nb_occurences'] = nb_occ
            unique_list.append(vuln)
        return unique_list

    def generate_report(self, prioritized_vulns: List[Dict], top_n: int = 10) -> str:
        """Gera relatório formatado das top N vulnerabilidades"""
        report = []
        report.append("=" * 80)
        report.append("RELATÓRIO DE PRIORIZAÇÃO DE VULNERABILIDADES - METODOLOGIA 5Q (RPI)")
        report.append("=" * 80)
        report.append("")

        # Agrupa por domínio
        by_domain = {}
        for vuln in prioritized_vulns[:top_n]:
            domain = vuln.get('domain', 'general')
            if domain not in by_domain:
                by_domain[domain] = []
            by_domain[domain].append(vuln)

        # Top 10 geral
        report.append(f"TOP {top_n} VULNERABILIDADES PRIORITÁRIAS")
        report.append("-" * 40)

        for i, vuln in enumerate(prioritized_vulns[:top_n], 1):
            metrics = vuln.get('rpi_metrics')
            cve_id = vuln.get('vulnerability_ids', 'N/A')
            title = vuln.get('title', 'Sem título')

            report.append(f"\n#{i}. {title[:70]}")
            report.append(f"    CVE: {cve_id} | RPI Score: {vuln['rpi_score']:.2f}")
            report.append(f"    Domínio: {vuln['domain']} | Produto: {vuln.get('product', 'N/A')}")
            report.append(f"    Componente: {vuln.get('component_name', 'N/A')} v{vuln.get('component_version', 'N/A')}")

            # Scores das 5 perguntas
            report.append(f"    Q1 (Exploitabilidade): {metrics.q1_exploitability:.1f}")
            report.append(f"    Q2 (Exposição): {metrics.q2_exposure:.1f}")
            report.append(f"    Q3 (Impacto): {metrics.q3_impact:.1f}")
            report.append(f"    Q4 (Facilidade Fix): {metrics.q4_fixability:.1f}")
            report.append(f"    Q5 (Urgência): {metrics.q5_urgency:.1f}")

            # Sinais especiais
            signals = []
            if metrics.has_kev:
                signals.append("⚠️ KEV (Exploração Conhecida)")
            if metrics.has_poc:
                signals.append("🔓 PoC Disponível")
            if metrics.epss_score > 0.5:
                signals.append(f"📊 EPSS Alto ({metrics.epss_score:.2%})")
            if vuln.get('violates_sla'):
                signals.append("⏰ SLA Violado")

            if signals:
                report.append(f"    Alertas: {' | '.join(signals)}")

            # Por que priorizar
            report.append(f"    📌 Por que agora: {self._generate_priority_reason(vuln, metrics)}")

            # Como corrigir
            mitigation = vuln.get('mitigation', 'Verificar documentação')
            if mitigation and str(mitigation) != 'NaN':
                report.append(f"    ✅ Como corrigir: {mitigation[:100]}")

            # Risco se adiar
            report.append(f"    ⚡ Risco se adiar 30 dias: {self._estimate_risk_increase(vuln, metrics)}")

        # Resumo por domínio
        report.append("\n" + "=" * 80)
        report.append("DISTRIBUIÇÃO POR DOMÍNIO")
        report.append("-" * 40)

        for domain, vulns in by_domain.items():
            avg_rpi = sum(v['rpi_score'] for v in vulns) / len(vulns)
            report.append(f"{domain.upper()}: {len(vulns)} vulnerabilidades (RPI médio: {avg_rpi:.1f})")

        return "\n".join(report)

    def _generate_priority_reason(self, vuln: Dict, metrics: VulnerabilityMetrics) -> str:
        """Gera justificativa concisa para priorização"""
        reasons = []

        if metrics.has_kev:
            reasons.append("exploração ativa confirmada")
        elif metrics.has_poc:
            reasons.append("PoC público disponível")

        if metrics.q2_exposure > 70:
            reasons.append("alta exposição")

        if metrics.q3_impact > 80:
            reasons.append("impacto crítico")

        if vuln.get('violates_sla'):
            reasons.append("SLA violado")
        elif vuln.get('sla_days_remaining', 999) < 7:
            reasons.append("próximo do SLA")

        if not reasons:
            reasons.append("risco elevado identificado")

        return ", ".join(reasons)

    def _estimate_risk_increase(self, vuln: Dict, metrics: VulnerabilityMetrics) -> str:
        """Estima aumento de risco se não corrigir em 30 dias"""
        risk_factors = []

        if metrics.has_kev or metrics.epss_score > 0.3:
            risk_factors.append("Probabilidade de exploração aumenta 40%")

        sla_days = vuln.get('sla_days_remaining', 999)
        if sla_days < 30:
            risk_factors.append(f"Violação de SLA em {max(0, sla_days)} dias")

        if metrics.q3_impact > 70:
            risk_factors.append("Janela de ataque crítica permanece aberta")

        if not risk_factors:
            risk_factors.append("Risco moderado de exploração oportunista")

        return "; ".join(risk_factors)

    def export_to_csv(self, prioritized_vulns: List[Dict], filename: str = "vulnerability_priorities.csv"):
        """Exporta resultados para CSV com barra de progresso"""
        print(f"\n📝 Exportando resultados para {filename}...")
        df_data = []

        with tqdm(total=len(prioritized_vulns), desc="Preparando dados", unit="vuln", disable=not self.config.enable_progress_bars) as pbar:
            for vuln in prioritized_vulns:
                metrics = vuln.get('rpi_metrics', VulnerabilityMetrics())

                row = {
                    'rank': len(df_data) + 1,
                    'cve_id': vuln.get('vulnerability_ids', ''),
                    'title': vuln.get('title', ''),
                    'component': vuln.get('component_name', ''),
                    'version': vuln.get('component_version', ''),
                    'rpi_score': vuln.get('rpi_score', 0),
                    'q1_exploitability': metrics.q1_exploitability,
                    'q2_exposure': metrics.q2_exposure,
                    'q3_impact': metrics.q3_impact,
                    'q4_fixability': metrics.q4_fixability,
                    'q5_urgency': metrics.q5_urgency,
                    'domain': vuln.get('domain', ''),
                    'has_kev': metrics.has_kev,
                    'has_poc': metrics.has_poc,
                    'epss_score': metrics.epss_score,
                    'sla_days_remaining': vuln.get('sla_days_remaining', ''),
                    'severity': vuln.get('severity', ''),
                    'product': vuln.get('product', ''),
                    'mitigation': vuln.get('mitigation', '')
                }
                df_data.append(row)
                pbar.update(1)

        df = pd.DataFrame(df_data)
        df.to_csv(filename, index=False)
        logger.info(f"✅ Resultados exportados para {filename}")

        # Estatísticas rápidas
        print(f"\n📊 Estatísticas do arquivo exportado:")
        print(f"   Total de vulnerabilidades: {len(df)}")
        print(f"   RPI médio: {df['rpi_score'].mean():.2f}")
        print(f"   RPI máximo: {df['rpi_score'].max():.2f}")
        print(f"   Com KEV: {df['has_kev'].sum()}")
        print(f"   Com PoC: {df['has_poc'].sum()}")

        return df

    def pareto_cut(prioritized, target_share=0.80):
        """
        Return the smallest prefix size k such that the cumulative share of total
        RPI reaches target_share (e.g., 0.80). Also returns the share and k/N.
        """
        scores = [float(v.get('rpi_score', 0.0)) for v in prioritized if v.get('rpi_metrics')]
        if not scores:
            return 0, 0.0, 0.0
        total = sum(scores)
        cum, k = 0.0, 0
        for s in scores:
            cum += s
            k += 1
            if cum / total >= target_share:
                break
        return k, cum / total, k / len(scores)
