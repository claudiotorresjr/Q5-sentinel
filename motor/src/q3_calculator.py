#!/usr/bin/env python3
"""
Módulo Q3: Cálculo de Impacto
Q3: Qual o estrago se der ruim? (0-100)

Este módulo contém todas as funções relacionadas ao cálculo do impacto,
incluindo avaliação de severidade e domínios afetados.

Versão 6.0 - Correções:
- Tratamento mais agressivo de múltiplas ocorrências
- Consideração do campo criticality do ativo
- Melhor integração com CVSS v3
"""

import re
import math
from typing import Dict
import logging

logger = logging.getLogger(__name__)


class VulnerabilityClassifier:
    """Classifica vulnerabilidades por domínio e contexto"""

    # Mapeamento de componentes para domínios
    DOMAIN_PATTERNS = {
        'web_api': [
            r'spring', r'struts', r'tomcat', r'jetty', r'express', r'fastapi',
            r'django', r'flask', r'rails', r'asp\.net', r'nginx', r'apache'
        ],
        'backend': [
            r'java', r'python', r'node', r'dotnet', r'golang', r'rust',
            r'spring-security', r'auth', r'jwt', r'oauth'
        ],
        'database': [
            r'mysql', r'postgres', r'oracle', r'mongodb', r'redis', r'elastic',
            r'jdbc', r'odbc', r'hibernate', r'sqlalchemy'
        ],
        'search_index': [
            r'solr', r'elastic', r'lucene', r'sphinx', r'algolia'
        ],
        'messaging': [
            r'kafka', r'rabbitmq', r'activemq', r'redis', r'zeromq', r'nats'
        ],
        'infrastructure': [
            r'docker', r'kubernetes', r'terraform', r'ansible', r'aws', r'azure'
        ],
        'frontend': [
            r'react', r'vue', r'angular', r'jquery', r'bootstrap', r'webpack',
            r'babel', r'postcss', r'sass', r'less'
        ],
        'build_tools': [
            r'maven', r'gradle', r'npm', r'yarn', r'webpack', r'rollup', r'vite'
        ],
        'big_data': [
            r'hadoop', r'spark', r'hive', r'presto', r'flink', r'storm'
        ]
    }

    @classmethod
    def classify_domain(cls, vuln_data: Dict) -> str:
        """Classifica vulnerabilidade por domínio baseado em componente e contexto"""
        component = str(vuln_data.get('component_name', '')).lower()
        file_path = str(vuln_data.get('file_path', '')).lower()
        service = str(vuln_data.get('service', '')).lower()
        test = str(vuln_data.get('test', '')).lower()

        # Verifica padrões em ordem de prioridade
        for domain, patterns in cls.DOMAIN_PATTERNS.items():
            for pattern in patterns:
                if (re.search(pattern, component) or
                    re.search(pattern, file_path) or
                    re.search(pattern, service)):
                    return domain

        # Fallback baseado no tipo de teste
        if 'dependency' in test:
            if 'frontend' in test.lower():
                return 'frontend'
            return 'backend'
        elif 'sast' in test:
            return 'backend'
        elif 'infrastructure' in test or 'prowler' in test:
            return 'infrastructure'

        return 'general'


def calculate_q3_impact(vuln_data: Dict, classifier: VulnerabilityClassifier) -> float:
    """
    Q3: Qual o estrago se der ruim? (0-100)

    Fatores considerados:
    1. CVSS v3 score (base impact)
    2. Número de ocorrências (CRÍTICO - superfície de ataque)
    3. Criticidade do ativo
    4. Domínio do componente
    5. Sensibilidade dos dados
    """

    # Helper para conversão segura
    def safe_float(val, default=0):
        if val is None or str(val).lower() in ['nan', 'none', '']:
            return default
        try:
            return float(val)
        except:
            return default

    base_impact = 50  # Default médio

    # 1. Score base do CVSS ou severity
    cvss_score = safe_float(vuln_data.get('cvssv3_score'))

    if cvss_score > 0:
        # CVSS v3 é o mais confiável para impacto
        base_impact = cvss_score * 10  # CVSS 0-10 para 0-100
        logger.debug(f"CVSS v3 score: {cvss_score} → base impact: {base_impact}")
    else:
        # Fallback para severity textual
        severity_map = {
            'critical': 90,
            's4': 90,        # Severidade numérica
            'high': 70,
            's3': 70,
            'medium': 50,
            's2': 50,
            'low': 30,
            's1': 30,
            'informational': 10,
            'info': 10,
            's0': 10
        }

        severity = str(vuln_data.get('severity', '')).lower()
        if not severity:
            # Tenta numerical_severity como fallback
            severity = str(vuln_data.get('numerical_severity', '')).lower()

        base_impact = severity_map.get(severity, 50)
        logger.debug(f"Severity: {severity} → base impact: {base_impact}")

    # 2. NÚMERO DE OCORRÊNCIAS - TRATAMENTO AGRESSIVO
    # Múltiplas instâncias = superfície de ataque exponencialmente maior
    nb_occurences = safe_float(vuln_data.get('nb_occurences'), 1)

    if nb_occurences > 1:
        # Escala agressiva não-linear
        # 2 ocorrências = 1.1x
        # 10 ocorrências = 1.3x
        # 50 ocorrências = 1.6x
        # 100 ocorrências = 2.0x
        # 500+ ocorrências = 2.5x

        if nb_occurences >= 500:
            occurrence_multiplier = 2.5
        elif nb_occurences >= 100:
            occurrence_multiplier = 2.0
        elif nb_occurences >= 50:
            occurrence_multiplier = 1.6
        elif nb_occurences >= 20:
            occurrence_multiplier = 1.4
        elif nb_occurences >= 10:
            occurrence_multiplier = 1.3
        elif nb_occurences >= 5:
            occurrence_multiplier = 1.2
        else:
            # Para valores pequenos, usa log
            occurrence_multiplier = 1.0 + (math.log10(nb_occurences) * 0.2)

        base_impact *= occurrence_multiplier
        logger.debug(f"Occurrences: {nb_occurences} → multiplier: {occurrence_multiplier:.2f}")

    # 3. CRITICIDADE DO ATIVO (campo criticality)
    criticality = vuln_data.get('criticality')
    if criticality and str(criticality) != 'NaN':
        try:
            # Criticality varia de 01 a 10
            crit_str = str(criticality).strip()
            if crit_str.startswith('0'):
                crit_str = crit_str[1:]  # Remove leading zero

            crit_value = int(crit_str)

            # Mapeia criticidade para multiplicador
            if crit_value >= 9:
                base_impact *= 1.4  # Ativo ultra-crítico
            elif crit_value >= 8:
                base_impact *= 1.3  # Ativo muito crítico
            elif crit_value >= 7:
                base_impact *= 1.2  # Ativo crítico
            elif crit_value >= 6:
                base_impact *= 1.1  # Ativo importante
            elif crit_value <= 3:
                base_impact *= 0.8  # Ativo não crítico

            logger.debug(f"Asset criticality: {crit_value}")
        except Exception as e:
            logger.debug(f"Error parsing criticality '{criticality}': {e}")

    # 4. Ajuste baseado no domínio do componente
    domain = classifier.classify_domain(vuln_data)

    domain_multipliers = {
        'database': 1.4,        # Dados críticos
        'infrastructure': 1.3,  # Afeta toda infra
        'search_index': 1.2,    # Dados sensíveis indexados
        'backend': 1.15,        # Lógica de negócio
        'web_api': 1.1,         # Exposição externa
        'messaging': 1.05,      # Comunicação entre sistemas
        'frontend': 0.9,        # Menor impacto direto
        'build_tools': 0.7      # Impacto em build, não produção
    }

    domain_mult = domain_multipliers.get(domain, 1.0)
    base_impact *= domain_mult
    logger.debug(f"Domain: {domain} → multiplier: {domain_mult}")

    # 5. Componentes com dados sensíveis
    component = str(vuln_data.get('component_name', '')).lower()
    title = str(vuln_data.get('title', '')).lower()
    description = str(vuln_data.get('description', '')).lower()

    # Palavras-chave de alta sensibilidade
    high_sensitivity_keywords = [
        'auth', 'authentication', 'authorization',
        'crypto', 'cryptograph', 'encrypt',
        'password', 'passwd', 'credential',
        'token', 'jwt', 'oauth', 'saml',
        'session', 'cookie',
        'payment', 'credit', 'card', 'billing',
        'personal', 'pii', 'gdpr', 'sensitive'
    ]

    # Verifica presença de palavras sensíveis
    search_text = f"{component} {title} {description}"
    sensitivity_count = sum(1 for keyword in high_sensitivity_keywords if keyword in search_text)

    if sensitivity_count >= 3:
        base_impact *= 1.3  # Múltiplos indicadores de sensibilidade
        logger.debug(f"High sensitivity detected: {sensitivity_count} keywords")
    elif sensitivity_count >= 1:
        base_impact *= 1.15  # Alguma sensibilidade
        logger.debug(f"Sensitivity detected: {sensitivity_count} keywords")

    # 7. Verifica se é vulnerabilidade verificada (mais certeza do impacto)
    if vuln_data.get('verified') is True or str(vuln_data.get('verified', '')).lower() == 'true':
        base_impact *= 1.05  # Pequeno boost por ser confirmado

    # Limita o score final a 100
    final_impact = min(100, max(0, base_impact))

    logger.debug(f"Final Q3 impact score: {final_impact:.1f}")

    return final_impact
