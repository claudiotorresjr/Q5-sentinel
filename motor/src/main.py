#!/usr/bin/env python3
"""
Sistema de Priorização de Vulnerabilidades usando RPI (Risk-Priority Index)
Metodologia das 5 Perguntas (5Q) para reduzir 15000+ vulnerabilidades até a primeira a atacar

Script principal que coordena os cálculos Q1-Q5

Autor: Security Analytics Team
Data: 2025
Versão: 5.0 - Modular
"""

import json
import sys
import os
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
import argparse
from torch import frac

# Importações dos módulos criados
from models import VulnerabilityMetrics, ProcessingConfig
from calculators import RiskPriorityCalculator, TieBreaker
from prioritizer import VulnerabilityPrioritizer
from utils import load_vulnerability_data, find_vulnerability_file, print_banner, print_statistics
#from pareto import print_concentration_report
from models import ProcessingConfig
from prioritizer import VulnerabilityPrioritizer
from utils import load_vulnerability_data, print_statistics

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def _get_arg_val(argv, flag, default=None, cast=str):
    if flag in argv:
        i = argv.index(flag)
        if i+1 < len(argv) and not argv[i+1].startswith('-'):
            try:
                return cast(argv[i+1])
            except Exception:
                return default
    return default

# Configuração de logging

def main():
    """Função principal para executar o sistema de priorização"""
    # Banner inicial
    print_banner("🛡️  SISTEMA DE PRIORIZAÇÃO DE VULNERABILIDADES - RPI v5.0")
    print("   📊 Metodologia das 5 Perguntas (5Q)")

    parser = argparse.ArgumentParser(description="Sistema de Priorização de Vulnerabilidades")
    parser.add_argument('--inputs', nargs='+', help='Arquivos JSON de vulnerabilidades')
    parser.add_argument('--no-progress', action='store_true', help='Desabilitar barras de progresso')
    parser.add_argument('--top-k', type=int, default=1000, help='Top K for funnel')
    parser.add_argument('--funnel-threshold', type=int, default=50)
    parser.add_argument('--funnel-eps', type=float, default=1e-4)
    parser.add_argument('--no-funnel', action='store_true')
    parser.add_argument('filename', nargs='?', help='Arquivo JSON de vulnerabilidades (opcional)')
    args = parser.parse_args()

    enable_progress = not args.no_progress
    if not enable_progress:
        print("ℹ️  Barras de progresso desabilitadas")

    config = ProcessingConfig(enable_progress_bars=enable_progress)
    config.top_k_for_funnel = args.top_k
    config.funnel_threshold = args.funnel_threshold
    config.funnel_equal_epsilon = args.funnel_eps
    config.funnel_enabled = not args.no_funnel

    # Carrega dados de vulnerabilidades
    if args.inputs:
        vulnerabilities = []
        for filename in args.inputs:
            vulns = load_vulnerability_data(filename, enable_progress)
            if vulns:
                vulnerabilities.extend(vulns)
    elif args.filename:
        vulnerabilities = load_vulnerability_data(args.filename, enable_progress)
    else:
        filename = find_vulnerability_file()
        if filename:
            vulnerabilities = load_vulnerability_data(filename, enable_progress)
        else:
            logger.error("❌ Nenhum arquivo de vulnerabilidades encontrado!")
            print("Uso: python main.py [--inputs file1.json file2.json] [arquivo.json] [--no-progress]")
            return []

    if not vulnerabilities:
        logger.error("❌ Nenhuma vulnerabilidade para processar!")
        return []

    # Estatísticas iniciais
    print_statistics(vulnerabilities, "DADOS CARREGADOS")

    # Inicializa o priorizador
    prioritizer = VulnerabilityPrioritizer(config)

    # Processa vulnerabilidades
    prioritized = prioritizer.process_vulnerabilities(vulnerabilities)
    k, share, frac = VulnerabilityPrioritizer.pareto_cut(prioritized, 0.80)
    #print_concentration_report(prioritized)


    if not prioritized:
        logger.error("❌ Nenhuma vulnerabilidade foi priorizada com sucesso!")
        return []

    # Gera relatório detalhado para top 20
    print_banner("📋 GERANDO RELATÓRIO")
    report = prioritizer.generate_report(prioritized, top_n=config.top_n_report)
    print(report)

    # Exporta TODOS os resultados para CSV
    if config.export_csv:
        prioritizer.export_to_csv(prioritized, "src/vulnerability_priorities.csv")

    # Mostra resumo das top 5 mais críticas com visual melhorado
    print_banner("🎯 TOP 5 VULNERABILIDADES CRÍTICAS PARA AÇÃO IMEDIATA")

    for i, vuln in enumerate(prioritized[:5], 1):
        metrics = vuln.get('rpi_metrics', VulnerabilityMetrics())

        # Box visual para cada vulnerabilidade
        print(f"\n┌{'─'*76}┐")
        print(f"│ #{i}. RPI: {vuln.get('rpi_score', 0):>5.1f} │ {vuln.get('title', 'Sem título')[:63]:<63} │")
        print(f"├{'─'*76}┤")

        # Informações principais
        cve = vuln.get('vulnerability_ids', 'N/A')
        component = vuln.get('component_name', 'N/A')
        version = vuln.get('component_version', 'N/A')
        print(f"│ CVE: {cve:<25} Componente: {component} v{version}")

        # Scores das 5 perguntas em formato visual
        print(f"│ 5Q Scores: Q1={metrics.q1_exploitability:>4.0f} Q2={metrics.q2_exposure:>4.0f} Q3={metrics.q3_impact:>4.0f} Q4={metrics.q4_fixability:>4.0f} Q5={metrics.q5_urgency:>4.0f}")

        # Indicadores críticos com ícones
        critical_indicators = []
        if metrics.has_kev:
            critical_indicators.append("🔴 KEV")
        if metrics.has_poc:
            critical_indicators.append("⚠️  PoC")
        if vuln.get('violates_sla'):
            critical_indicators.append("⏰ SLA!")
        if metrics.epss_score > 0.5:
            critical_indicators.append(f"📊 EPSS:{metrics.epss_score:.0%}")

        if critical_indicators:
            indicators_str = ' '.join(critical_indicators)
            print(f"│ Alertas: {indicators_str}")

        # Ação recomendada
        mitigation = vuln.get('mitigation', '')
        if mitigation and str(mitigation) != 'NaN':
            mit_clean = str(mitigation).replace('NEWLINE', ' ').strip()[:65]
            print(f"│ ✅ Ação: {mit_clean}")

        print(f"└{'─'*76}┘")

    # Resumo final
    print_banner("📊 RESUMO DA ANÁLISE")
    print(f"📁 Relatório completo: vulnerability_priorities.csv")
    print(f"📊 Total analisado: {len(prioritized)} vulnerabilidades únicas")

    # Estatísticas por domínio
    domain_stats = {}
    for vuln in prioritized:
        domain = vuln.get('domain', 'general')
        if domain not in domain_stats:
            domain_stats[domain] = {'count': 0, 'total_rpi': 0}
        domain_stats[domain]['count'] += 1
        domain_stats[domain]['total_rpi'] += vuln.get('rpi_score', 0)

    print(f"\n🏢 Distribuição por domínio:")
    for domain, stats in sorted(domain_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:5]:
        avg_rpi = stats['total_rpi'] / stats['count'] if stats['count'] > 0 else 0
        print(f"   {domain}: {stats['count']} vulns (RPI médio: {avg_rpi:.1f})")

    # Indicadores de risco
    kev_count = sum(1 for v in prioritized if v.get('rpi_metrics', VulnerabilityMetrics()).has_kev)
    poc_count = sum(1 for v in prioritized if v.get('rpi_metrics', VulnerabilityMetrics()).has_poc)
    sla_violations = sum(1 for v in prioritized if v.get('violates_sla'))

    print(f"\n⚠️  Indicadores de risco:")
    print(f"   Com KEV (exploração ativa): {kev_count}")
    print(f"   Com PoC disponível: {poc_count}")
    print(f"   SLA violado: {sla_violations}")

    print("\n✨ Análise completa! Use os resultados para priorizar remediação.")
    print("="*80 + "\n")

    return prioritized


if __name__ == "__main__":
    # Uso: python main.py [arquivo.json] [--no-progress]
    # Se não especificar arquivo, procura por vulnerabilities.json, data.json, ou vulns.json
    # Use --no-progress para desabilitar barras de progresso

    main()
