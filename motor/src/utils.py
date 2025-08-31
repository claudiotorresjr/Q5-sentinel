#!/usr/bin/env python3
"""
Módulo de utilitários para o sistema de priorização de vulnerabilidades

Contém funções auxiliares para carregamento de dados, validação e formatação

Autor: Security Analytics Team
Data: 2025
Versão: 5.0 - Modular
"""

import json
import os
import logging
from typing import List, Dict
import pandas as pd

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

logger = logging.getLogger(__name__)


def load_vulnerability_data(filename: str = None, enable_progress: bool = True) -> List[Dict]:
    """Carrega dados de vulnerabilidades de arquivo JSON com barra de progresso"""
    import sys

    print(f"\n📂 Carregando dados de: {filename}")
    try:
        # Obtém tamanho do arquivo para barra de progresso
        file_size = os.path.getsize(filename)
        print(f"   Tamanho do arquivo: {file_size / (1024*1024):.2f} MB")

        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Suporta diferentes formatos de JSON
        if isinstance(data, dict):
            # Se for dict, procura por chaves comuns de vulnerabilidades
            if 'vulnerabilities' in data:
                data = data['vulnerabilities']
            elif 'findings' in data:
                data = data['findings']
            elif 'results' in data:
                data = data['results']
            elif 'data' in data:
                data = data['data']
            else:
                # Assume que o dict tem vulnerabilidades como valores
                data = list(data.values())

        if not isinstance(data, list):
            logger.error(f"Formato inesperado de dados: {type(data)}")
            return []

        # Limpa dados inválidos com barra de progresso
        print(f"\n🧹 Limpando {len(data)} registros...")
        clean_data = []

        with tqdm(total=len(data), desc="Limpando dados", unit="registro", disable=not enable_progress) as pbar:
            for item in data:
                if isinstance(item, dict):
                    # Converte NaN strings para None
                    cleaned_item = {}
                    for k, v in item.items():
                        if v == 'NaN' or (isinstance(v, float) and pd.isna(v)):
                            cleaned_item[k] = None
                        else:
                            cleaned_item[k] = v
                    clean_data.append(cleaned_item)
                pbar.update(1)

        logger.info(f"✅ Carregados {len(clean_data)} registros de vulnerabilidades")
        return clean_data

    except Exception as e:
        logger.error(f"❌ Erro ao carregar arquivo JSON: {e}")
        return []


def find_vulnerability_file(directory: str = ".") -> str:
    """Procura por arquivos de vulnerabilidades comuns no diretório"""
    common_names = [
        'vulnerabilidades.json',
        'vulnerabilities.json',
        'data.json',
        'vulns.json',
        'findings.json',
        'results.json'
    ]

    for filename in common_names:
        filepath = os.path.join(directory, filename)
        if os.path.exists(filepath):
            return filepath

    # Se não encontrou, retorna o primeiro arquivo .json encontrado
    for file in os.listdir(directory):
        if file.endswith('.json'):
            return os.path.join(directory, file)

    return None


def validate_vulnerability_data(vuln_data: Dict) -> bool:
    """Valida se os dados de vulnerabilidade têm campos mínimos necessários"""
    required_fields = ['title', 'vulnerability_ids', 'component_name']

    # Pelo menos um dos campos obrigatórios deve estar presente
    has_required = any(vuln_data.get(field) for field in required_fields)

    # Deve ser um dicionário
    is_dict = isinstance(vuln_data, dict)

    return is_dict and has_required


def clean_text_field(text: str, max_length: int = 100) -> str:
    """Limpa e limita comprimento de campos de texto"""
    if not text or str(text) == 'NaN':
        return ""

    # Remove quebras de linha e múltiplos espaços
    cleaned = str(text).replace('\n', ' ').replace('\r', ' ')
    cleaned = ' '.join(cleaned.split())

    # Limita comprimento
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length-3] + "..."

    return cleaned


def format_cve_list(cve_string: str) -> List[str]:
    """Extrai e formata lista de CVEs de uma string"""
    if not cve_string:
        return []

    # Divide por vírgulas, ponto e vírgula, ou espaços
    cves = []
    for separator in [',', ';', ' ', '\n']:
        if separator in cve_string:
            cves = cve_string.split(separator)
            break
    else:
        cves = [cve_string]

    # Limpa e filtra CVEs válidas
    valid_cves = []
    for cve in cves:
        cve = cve.strip().upper()
        if cve.startswith('CVE-') and len(cve) >= 10:
            valid_cves.append(cve)

    return list(set(valid_cves))  # Remove duplicatas


def print_banner(title: str, width: int = 80):
    """Imprime um banner formatado"""
    print("\n" + "="*width)
    print(f"   {title}")
    print("="*width)


from collections import Counter

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}

def normalize_severity(raw) -> str:
    """Return a normalized severity label. None/empty -> 'Unknown'."""
    if raw is None:
        return 'Unknown'
    s = str(raw).strip()
    if not s:
        return 'Unknown'
    s_low = s.lower()
    # Map common variants
    mapping = {
        'crit': 'Critical', 'critical': 'Critical',
        'high': 'High', 'h': 'High',
        'medium': 'Medium', 'med': 'Medium', 'm': 'Medium',
        'low': 'Low', 'l': 'Low',
        'info': 'Info', 'informational': 'Info', 'information': 'Info',
        's4': 'Critical', 's3': 'High', 's2': 'Medium', 's1': 'Low', 's0': 'Info'
    }
    return mapping.get(s_low, s.capitalize())

def _sev_sort_key(label: str):
    """Sort by fixed severity order, then alphabetically."""
    key = (SEVERITY_ORDER.get(label.lower(), SEVERITY_ORDER['unknown']), label.lower())
    return key

def print_statistics(vulnerabilities: list, title: str = "DADOS"):
    """Pretty-print basic stats with safe severity ordering."""
    print(f"\n📊 {title}\n" + "-"*40)
    total = len(vulnerabilities)
    print(f"Total de vulnerabilidades: {total}")

    # Build severity counter safely (handles None/missing fields)
    sev_counter = Counter()
    for v in vulnerabilities:
        raw = (
            v.get('severity') or
            v.get('severity_text') or
            v.get('severity_level') or
            v.get('cvss_severity') or
            None
        )
        sev_counter[normalize_severity(raw)] += 1

    print("Distribuição por severidade:")
    for severity, count in sorted(sev_counter.items(), key=lambda kv: _sev_sort_key(kv[0])):
        print(f" - {severity}: {count}")

    # Você pode manter suas outras métricas aqui abaixo (por produto, domínio, etc.)
