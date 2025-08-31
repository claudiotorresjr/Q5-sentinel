#!/usr/bin/env python3
"""
Módulo Q2: Cálculo de Exposição
Q2: Está exposta e alcançável? (0-100)

Este módulo contém todas as funções relacionadas ao cálculo da exposição,
incluindo classificação de domínio e verificação de dependências runtime.

Versão 6.0 - Correções:
- Valorização de finding dinâmico vs estático
- Consideração de verificação manual
- Melhor análise de endpoints e URLs
- Detecção de ambiente (prod/dev/test)
"""

import re
from typing import Dict, List
from dataclasses import dataclass
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

    # Mapeamento de CWEs para categorias de impacto
    CWE_IMPACT_SCORES = {
        # RCE/Command Injection - Crítico
        '78': 100, '77': 100, '94': 100, '502': 100, '74': 100,
        # Deserialization - Crítico
        '502': 95, '915': 95,
        # SQL Injection - Crítico
        '89': 90, '564': 90,
        # SSRF - Alto
        '918': 85,
        # Auth Bypass - Alto
        '287': 80, '306': 80, '862': 80, '863': 80,
        # Path Traversal - Alto
        '22': 75, '23': 75, '35': 75,
        # XXE - Alto
        '611': 75, '827': 75,
        # XSS - Médio-Alto
        '79': 70, '80': 70,
        # CSRF - Médio
        '352': 60,
        # Info Disclosure - Médio
        '200': 50, '209': 50, '532': 50,
        # DoS - Baixo-Médio
        '400': 40, '770': 40
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

    @classmethod
    def is_runtime_dependency(cls, vuln_data: Dict) -> bool:
        """Determina se é dependência de runtime vs dev/transitiva"""
        file_path = str(vuln_data.get('file_path', '')).lower()

        # Indicadores de runtime
        runtime_indicators = [
            'boot-inf/lib', 'web-inf/lib', '/lib/', '.jar', '.war',
            'node_modules', 'vendor/', 'site-packages', 'requirements.txt'
        ]

        # Indicadores de dev/test
        dev_indicators = [
            'test/', 'tests/', 'spec/', 'mock/', 'dev-dependencies',
            'devdependencies', 'test-', '-test', 'example/', 'sample/'
        ]

        # Verifica dev primeiro (mais específico)
        for indicator in dev_indicators:
            if indicator in file_path:
                return False

        # Depois verifica runtime
        for indicator in runtime_indicators:
            if indicator in file_path:
                return True

        # Default: considera runtime se não for claramente dev
        return True


def calculate_q2_exposure(vuln_data: Dict, classifier: VulnerabilityClassifier) -> float:
    """
    Q2: Está exposta e alcançável? (0-100)

    Fatores considerados:
    1. Finding dinâmico vs estático (CRÍTICO)
    2. Presença de URL/endpoints
    3. Verificação manual
    4. Ambiente (prod vs dev/test)
    5. Domínio do componente
    6. Runtime vs dev dependency
    """

    # Helper para conversão segura
    def safe_bool(val):
        if val is True or str(val).lower() == 'true':
            return True
        return False

    exposure_score = 20  # Base mínima
    reachability_score = 30  # Base mínima

    # 1. CRÍTICO: Finding dinâmico = sistema em execução real
    is_dynamic = safe_bool(vuln_data.get('dynamic_finding'))
    is_static = safe_bool(vuln_data.get('static_finding'))

    if is_dynamic:
        # Finding dinâmico confirma exposição real
        exposure_score = 75
        logger.debug("Dynamic finding detected - high exposure")
    elif is_static:
        # Finding estático tem menor certeza de exposição
        exposure_score = 35
        logger.debug("Static finding only - moderate exposure")

    # 2. Verificação manual aumenta confiança
    is_verified = safe_bool(vuln_data.get('verified'))
    if is_verified:
        if is_dynamic:
            exposure_score = min(100, exposure_score * 1.2)  # Dinâmico + verificado = muito confiável
        else:
            exposure_score = min(100, exposure_score * 1.15)  # Estático + verificado = mais confiável
        logger.debug("Verified finding - increased confidence")

    # 3. URL/Endpoints indicam exposição externa
    url = vuln_data.get('url')
    if url and str(url).lower() not in ['nan', 'none', '']:
        # Tem URL = provavelmente exposto à internet
        exposure_score = max(exposure_score, 85)

        # Analisa o tipo de URL
        url_lower = str(url).lower()
        if any(x in url_lower for x in ['https://', 'http://', 'ws://', 'wss://']):
            exposure_score = max(exposure_score, 90)  # URL completa

        # URLs públicas conhecidas
        if any(x in url_lower for x in ['.com', '.org', '.net', '.io', 'public', 'external']):
            exposure_score = 95  # Claramente público
        elif any(x in url_lower for x in ['localhost', '127.0.0.1', 'internal', 'private']):
            exposure_score = min(exposure_score, 60)  # Interno

        logger.debug(f"URL detected: {url[:50]}... - exposure: {exposure_score}")

    # 4. Endpoints expostos
    endpoints = vuln_data.get('endpoints')
    if endpoints and str(endpoints).lower() not in ['nan', 'none', '']:
        endpoints_str = str(endpoints)

        # Conta número de endpoints
        if ',' in endpoints_str:
            endpoint_count = len(endpoints_str.split(','))
        elif ';' in endpoints_str:
            endpoint_count = len(endpoints_str.split(';'))
        elif '\n' in endpoints_str:
            endpoint_count = len(endpoints_str.split('\n'))
        else:
            endpoint_count = 1 if len(endpoints_str) > 0 else 0

        if endpoint_count > 0:
            # Mais endpoints = maior superfície de ataque
            exposure_score = max(exposure_score, 50 + min(40, endpoint_count * 5))
            logger.debug(f"Endpoints detected: {endpoint_count} - exposure: {exposure_score}")

            # Analisa tipos de endpoints
            if any(x in endpoints_str.lower() for x in ['/api/', '/rest/', '/graphql', '/ws']):
                exposure_score = max(exposure_score, 70)  # APIs são mais expostas
            if any(x in endpoints_str.lower() for x in ['/admin', '/manage', '/config']):
                exposure_score = max(exposure_score, 60)  # Endpoints administrativos

    # 5. Análise do ambiente por heurística
    context_fields = [
        str(vuln_data.get('product', '')),
        str(vuln_data.get('service', '')),
        str(vuln_data.get('url', '')),
        str(vuln_data.get('title', '')),
        str(vuln_data.get('engagement', ''))  # Campo adicional do JSON
    ]
    context = ' '.join(context_fields).lower()

    # Detecta ambiente de produção
    prod_indicators = ['prod', 'production', 'prd', 'live', 'release']
    dev_indicators = ['dev', 'development', 'test', 'testing', 'stage', 'staging',
                     'stg', 'homolog', 'hml', 'qa', 'uat', 'sandbox', 'demo']

    is_prod = any(x in context for x in prod_indicators)
    is_dev = any(x in context for x in dev_indicators)

    if is_prod and not is_dev:
        exposure_score = min(100, exposure_score * 1.3)  # Produção = 30% mais crítico
        reachability_score = min(100, reachability_score * 1.3)
        logger.debug("Production environment detected")
    elif is_dev and not is_prod:
        exposure_score = max(10, exposure_score * 0.7)  # Dev/Test = 30% menos crítico
        reachability_score = max(10, reachability_score * 0.7)
        logger.debug("Development/Test environment detected")

    # 6. Runtime vs Dev dependency
    if classifier.is_runtime_dependency(vuln_data):
        reachability_score = max(reachability_score, 70)
        logger.debug("Runtime dependency - high reachability")
    else:
        reachability_score = min(reachability_score, 40)
        logger.debug("Dev/Test dependency - low reachability")

    # 7. Componentes críticos de infraestrutura
    domain = classifier.classify_domain(vuln_data)

    # Domínios mais expostos/críticos
    critical_domains = {
        'web_api': 1.3,      # APIs são mais expostas
        'database': 1.2,     # DBs contêm dados críticos
        'infrastructure': 1.2, # Infra afeta tudo
        'search_index': 1.15, # Índices podem expor dados
        'messaging': 1.1,     # Mensageria conecta sistemas
        'backend': 1.05,      # Backend tem lógica crítica
        'frontend': 0.9,      # Frontend menos crítico
        'build_tools': 0.7    # Build tools não em produção
    }

    domain_multiplier = critical_domains.get(domain, 1.0)
    reachability_score = min(100, reachability_score * domain_multiplier)
    logger.debug(f"Domain: {domain} - multiplier: {domain_multiplier}")

    # 8. Service field analysis
    service = str(vuln_data.get('service', '')).lower()
    if service and service != 'nan':
        # Serviços públicos conhecidos
        public_services = ['auth', 'login', 'gateway', 'api', 'edge', 'public',
                          'portal', 'www', 'web', 'frontend', 'customer']

        if any(svc in service for svc in public_services):
            exposure_score = max(exposure_score, 60)
            logger.debug(f"Public service detected: {service}")

    # 9. Score final ponderado
    # 60% exposição + 40% alcançabilidade
    q2_score = 0.6 * exposure_score + 0.4 * reachability_score

    final_score = min(100, max(0, q2_score))
    logger.debug(f"Final Q2 exposure score: {final_score:.1f}")

    return final_score
