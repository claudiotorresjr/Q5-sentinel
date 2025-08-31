#!/usr/bin/env python3
"""
API Server para servir dados de vulnerabilidades do CSV
Converte CSV para formato JSON compatível com o front-end
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
import os
from typing import Dict, List, Any

app = Flask(__name__)
CORS(app)

# Caminho para o CSV
CSV_PATH = os.path.join(os.path.dirname(__file__), 'vulnerability_priorities.csv')

def convert_csv_to_json_format(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Converte DataFrame do CSV para formato JSON esperado pelo front-end
    """
    json_data = []
    
    for index, row in df.iterrows():
        # Mapeamento de campos do CSV para JSON
        vulnerability = {
            "id": str(index + 1),
            "vulnerability_ids": row.get('cve_id', 'N/A'),
            "product": row.get('product', 'N/A'),
            "component_name": row.get('component', 'N/A'),
            "version": row.get('version', 'N/A'),
            "domain": row.get('domain', 'general'),
            "environment": "prod",  # Assumindo prod como padrão
            "is_runtime": True,     # Assumindo runtime como padrão
            "is_dynamic": True,     # Assumindo dynamic como padrão
            "is_verified": True,    # Assumindo verified como padrão
            "has_kev": str(row.get('has_kev', 'false')).lower() == 'true',
            "has_poc": str(row.get('has_poc', 'false')).lower() == 'true',
            "epss_score": float(row.get('epss_score', 0)) if str(row.get('epss_score', '')) != '' else 0,
            "epss_percentile": float(row.get('epss_score', 0)) * 100 if str(row.get('epss_score', '')) != '' else 0,  # Aproximação
            "threat_heat": int(float(row.get('rpi_score', 0)) * 0.8) if str(row.get('rpi_score', '')) != '' else 0,  # Aproximação
            "cvss_base_score": 10.0 if row.get('severity', '').lower() == 'critical' else 8.0,  # Aproximação
            "severity": row.get('severity', 'medium').lower(),
            "criticality": row.get('severity', 'medium').lower(),
            "nb_occurences": 1,     # Valor padrão
            "nb_endpoints": 1,      # Valor padrão
            "rpi_score": float(row.get('rpi_score', 0)) if str(row.get('rpi_score', '')) != '' else 0,
            "q1_exploitability": float(row.get('q1_exploitability', 0)) if str(row.get('q1_exploitability', '')) != '' else 0,
            "q2_exposure": float(row.get('q2_exposure', 0)) if str(row.get('q2_exposure', '')) != '' else 0,
            "q3_impact": float(row.get('q3_impact', 0)) if str(row.get('q3_impact', '')) != '' else 0,
            "q4_fixability": float(row.get('q4_fixability', 0)) if str(row.get('q4_fixability', '')) != '' else 0,
            "q5_urgency": float(row.get('q5_urgency', 0)) if str(row.get('q5_urgency', '')) != '' else 0,
            "violates_sla": float(row.get('sla_days_remaining', 0)) < 0 if str(row.get('sla_days_remaining', '')) != '' else False,
            "sla_days_remaining": int(float(row.get('sla_days_remaining', 30))) if str(row.get('sla_days_remaining', '')) != '' else 30,
            "effort_for_fixing": 50,  # Valor padrão
            "has_jira_issue": False,  # Valor padrão
            "mitigation": str(row.get('mitigation', 'N/A')) if str(row.get('mitigation', '')) != '' else 'N/A',
            "status": "open",         # Valor padrão
            "scanner_confidence": 0.85,  # Valor padrão
            "tie_breaker_key": "SLA>KEV>EPSSp>occ",  # Valor padrão
            "reason_text": f"RPI Score: {row.get('rpi_score', 0)}. Domain: {row.get('domain', 'N/A')}."
        }
        
        json_data.append(vulnerability)
    
    return json_data

@app.route('/api/priorities', methods=['GET'])
def get_priorities():
    """
    Endpoint para retornar dados de vulnerabilidades formatados
    """
    try:
        # Lê o CSV
        if not os.path.exists(CSV_PATH):
            return jsonify({"error": "CSV file not found"}), 404
        
        df = pd.read_csv(CSV_PATH)
        
        # Aplica filtros se fornecidos
        search = request.args.get('search', '').lower()
        if search:
            mask = (
                df['cve_id'].str.lower().str.contains(search, na=False) |
                df['product'].str.lower().str.contains(search, na=False) |
                df['component'].str.lower().str.contains(search, na=False) |
                df['domain'].str.lower().str.contains(search, na=False)
            )
            df = df[mask]
        
        # Filtro KEV
        has_kev = request.args.get('has_kev')
        if has_kev is not None:
            kev_filter = has_kev.lower() == 'true'
            df = df[df['has_kev'].astype(str).str.lower() == str(kev_filter).lower()]
        
        # Filtro PoC
        has_poc = request.args.get('has_poc')
        if has_poc is not None:
            poc_filter = has_poc.lower() == 'true'
            df = df[df['has_poc'].astype(str).str.lower() == str(poc_filter).lower()]
        
        # Filtro domínio
        domain = request.args.get('domain')
        if domain:
            df = df[df['domain'] == domain]
        
        # Filtro severidade
        severity = request.args.get('severity')
        if severity:
            df = df[df['severity'].str.lower() == severity.lower()]
        
        # Filtro RPI mínimo
        rpi_min = request.args.get('rpi_min')
        if rpi_min:
            df = df[pd.to_numeric(df['rpi_score'], errors='coerce') >= float(rpi_min)]
        
        # Filtro RPI máximo
        rpi_max = request.args.get('rpi_max')
        if rpi_max:
            df = df[pd.to_numeric(df['rpi_score'], errors='coerce') <= float(rpi_max)]
        
        # Paginação
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 100))  # Padrão 100 por página
        offset = (page - 1) * limit
        
        total_count = len(df)
        df = df.iloc[offset:offset + limit]
        
        # Substitui NaN por None antes da conversão
        df = df.fillna('')
        
        # Converte para formato JSON 
        json_data = convert_csv_to_json_format(df)
        
        # Retorna dados com informações de paginação
        response_data = {
            "data": json_data,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total_count,
                "total_pages": (total_count + limit - 1) // limit,
                "has_next": offset + limit < total_count,
                "has_prev": page > 1
            }
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/hero-counters', methods=['GET'])
def get_hero_counters():
    """
    Endpoint para retornar contadores para o painel hero
    """
    try:
        if not os.path.exists(CSV_PATH):
            return jsonify({"error": "CSV file not found"}), 404
        
        df = pd.read_csv(CSV_PATH)
        
        counters = {
            "sla_violated": len(df[pd.to_numeric(df['sla_days_remaining'], errors='coerce') < 0]),
            "sla_warning": len(df[(pd.to_numeric(df['sla_days_remaining'], errors='coerce') >= 0) & 
                                 (pd.to_numeric(df['sla_days_remaining'], errors='coerce') <= 7)]),
            "kev_count": len(df[df['has_kev'].astype(str).str.lower() == 'true']),
            "poc_count": len(df[df['has_poc'].astype(str).str.lower() == 'true']),
            "epss_high": len(df[pd.to_numeric(df['epss_score'], errors='coerce') >= 0.9]),
            "total_count": len(df)
        }
        
        return jsonify(counters)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Endpoint para estatísticas gerais
    """
    try:
        if not os.path.exists(CSV_PATH):
            return jsonify({"error": "CSV file not found"}), 404
        
        df = pd.read_csv(CSV_PATH)
        
        stats = {
            "total_vulnerabilities": len(df),
            "domains": df['domain'].value_counts().to_dict(),
            "severities": df['severity'].value_counts().to_dict(),
            "avg_rpi_score": float(df['rpi_score'].mean()) if pd.notna(df['rpi_score'].mean()) else 0,
            "top_rpi_score": float(df['rpi_score'].max()) if pd.notna(df['rpi_score'].max()) else 0
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/test', methods=['GET'])
def test():
    """
    Simple test endpoint
    """
    return jsonify({"status": "ok", "message": "API is working!"})

if __name__ == '__main__':
    print(f"🚀 Starting API server...")
    print(f"📁 CSV path: {CSV_PATH}")
    print(f"✅ Server ready at http://localhost:5000")
    print(f"🔗 Endpoints:")
    print(f"   GET /api/priorities - Vulnerability data")
    print(f"   GET /api/hero-counters - Hero counter data")
    print(f"   GET /api/stats - General statistics")
    print(f"   GET /test - Test endpoint")
    
    app.run(debug=True, host='0.0.0.0', port=5000)