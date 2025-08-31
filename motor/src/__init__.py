#!/usr/bin/env python3
"""
Sistema de Priorização de Vulnerabilidades usando RPI (Risk-Priority Index)
Metodologia das 5 Perguntas (5Q)

Este pacote contém módulos modulares para melhor organização e desenvolvimento.

Módulos:
- models: Estruturas de dados e dataclasses
- calculators: Classes de cálculo de RPI e desempate
- prioritizer: Classe principal de priorização
- utils: Funções utilitárias
- main: Ponto de entrada principal

Autor: Security Analytics Team
Data: 2025
Versão: 5.0 - Modular
"""

__version__ = "5.0"
__author__ = "Security Analytics Team"
__description__ = "Sistema de Priorização de Vulnerabilidades usando RPI (Risk-Priority Index)"

# Importações convenientes para uso direto
from .models import VulnerabilityMetrics, ProcessingConfig
from .calculators import RiskPriorityCalculator, TieBreaker
from .prioritizer import VulnerabilityPrioritizer
from .utils import load_vulnerability_data, print_banner, print_statistics

__all__ = [
    'VulnerabilityMetrics',
    'ProcessingConfig',
    'RiskPriorityCalculator',
    'TieBreaker',
    'VulnerabilityPrioritizer',
    'load_vulnerability_data',
    'print_banner',
    'print_statistics'
]
