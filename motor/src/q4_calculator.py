#!/usr/bin/env python3
"""
Módulo Q4: Cálculo de Facilidade de Correção
Q4: Dá para consertar rápido? (0-100, onde 100 = muito fácil)

Este módulo contém todas as funções relacionadas ao cálculo da facilidade de correção,
incluindo avaliação de esforços e disponibilidade de patches.
"""

import re
from typing import Dict

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

def calculate_q4_fixability(vuln_data: Dict, classifier: VulnerabilityClassifier) -> float:
    """Q4: Dá para consertar rápido? (0-100, onde 100 = muito fácil)"""
    fix_friction = 0

    # Verifica disponibilidade de patch
    mitigation = str(vuln_data.get('mitigation', ''))
    if 'upgrade to version' in mitigation.lower() or 'update' in mitigation.lower():
        fix_friction = 0  # Patch claro disponível
    else:
        fix_friction = 30  # Sem patch claro

    # Verifica complexidade da correção
    effort = vuln_data.get('effort_for_fixing', '')
    if effort and str(effort) != 'NaN':
        try:
            # Tenta converter para número
            effort_val = float(effort)
            fix_friction += effort_val * 10
        except (ValueError, TypeError):
            # Se não for número, trata como string
            effort_str = str(effort).upper()
            if 'HIGH' in effort_str or 'COMPLEX' in effort_str:
                fix_friction += 40
            elif 'MEDIUM' in effort_str or 'MODERATE' in effort_str:
                fix_friction += 20
            elif 'LOW' in effort_str or 'SIMPLE' in effort_str:
                fix_friction += 10
            # Ignora outros valores como 'PATCH'

    # Verifica se já tem issue/owner
    has_jira = vuln_data.get('has_jira_issue', False)
    if has_jira and str(has_jira) != 'NaN':
        if has_jira == True or str(has_jira).lower() == 'true':
            fix_friction -= 20  # Já tem dono = mais fácil

    # Verifica se é componente crítico (mais difícil de mudar)
    # Note: classifier precisa ser passado como parâmetro
    domain = classifier.classify_domain(vuln_data)
    if domain in ['database', 'infrastructure']:
        fix_friction += 20  # Mudanças em infra são mais complexas

    # Score final (inverso da fricção)
    q4_score = max(0, min(100, 100 - fix_friction))
    return q4_score
