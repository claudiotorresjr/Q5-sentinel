# Sistema de Priorização de Vulnerabilidades - RPI v5.0

## Metodologia das 5 Perguntas (5Q)

Sistema modular para reduzir vulnerabilidades até a primeira a atacar usando o **Risk-Priority Index (RPI)**.

## 📁 Estrutura Modular

O sistema foi reestruturado em módulos para melhor visibilidade e desenvolvimento:

```
certo/
├── __init__.py          # Pacote Python e importações convenientes
├── main.py              # Ponto de entrada principal (simplificado)
├── models.py            # Estruturas de dados e dataclasses
├── calculators.py       # Classes de cálculo (RPI, TieBreaker)
├── prioritizer.py       # Classe principal de priorização
├── utils.py             # Funções utilitárias
├── q1_calculator.py     # Cálculo Q1 (Exploitabilidade)
├── q2_calculator.py     # Cálculo Q2 (Exposição)
├── q3_calculator.py     # Cálculo Q3 (Impacto)
├── q4_calculator.py     # Cálculo Q4 (Facilidade de correção)
└── q5_calculator.py     # Cálculo Q5 (Urgência)
```

## 🚀 Como Usar

### Execução Simples
```bash
python main.py vulnerabilidades.json
```

### Execução sem Barras de Progresso
```bash
python main.py vulnerabilidades.json --no-progress
```

### Uso Programático
```python
from certo import VulnerabilityPrioritizer, load_vulnerability_data

# Carrega dados
vulnerabilidades = load_vulnerability_data('dados.json')

# Processa
prioritizer = VulnerabilityPrioritizer()
resultados = prioritizer.process_vulnerabilities(vulnerabilidades)

# Gera relatório
relatorio = prioritizer.generate_report(resultados, top_n=10)
print(relatorio)
```

## 📦 Módulos

### models.py
- `VulnerabilityMetrics`: Dataclass com métricas calculadas
- `ProcessingConfig`: Configurações de processamento
- `VulnerabilityData`: Estrutura unificada de dados

### calculators.py
- `RiskPriorityCalculator`: Calcula RPI usando metodologia 5Q
- `TieBreaker`: Lógica de desempate determinística

### prioritizer.py
- `VulnerabilityPrioritizer`: Classe principal que orquestra todo o processo

### utils.py
- `load_vulnerability_data()`: Carrega dados de vulnerabilidades
- `print_banner()`: Imprime banners formatados
- `print_statistics()`: Estatísticas dos dados
- `find_vulnerability_file()`: Localiza arquivos de vulnerabilidades

## 🧮 Metodologia 5Q

O sistema calcula o **Risk-Priority Index (RPI)** baseado em 5 perguntas:

1. **Q1 - Exploitabilidade** (30%): Quão fácil é explorar?
2. **Q2 - Exposição** (25%): Quão exposta está a vulnerabilidade?
3. **Q3 - Impacto** (20%): Qual o impacto se explorada?
4. **Q4 - Facilidade de Correção** (10%): Quão fácil é corrigir?
5. **Q5 - Urgência** (15%): Qual a urgência para correção?

## 📊 Saídas

- **Relatório textual**: Top vulnerabilidades com justificativas
- **Arquivo CSV**: Todos os resultados com métricas detalhadas
- **Estatísticas**: Distribuição por domínio e indicadores de risco

## 🔧 Desenvolvimento

### Adicionando Novos Cálculos
1. Crie novo módulo `qn_calculator.py`
2. Implemente função `calculate_qn_*()`
3. Importe no `calculators.py`
4. Atualize pesos em `ProcessingConfig`

### Modificando Pesos
```python
config = ProcessingConfig(weights={
    'q1': 0.25,  # Novo peso para Q1
    'q2': 0.30,  # Novo peso para Q2
    # ...
})
```

## 📈 Benefícios da Modularização

- ✅ **Manutenibilidade**: Código organizado por responsabilidade
- ✅ **Reutilização**: Módulos podem ser importados separadamente
- ✅ **Testabilidade**: Cada módulo pode ser testado isoladamente
- ✅ **Legibilidade**: Arquivos menores e mais focados
- ✅ **Colaboração**: Desenvolvimento paralelo em diferentes módulos

## 🏷️ Versão

**v5.0 - Modular** - Reestruturação completa para melhor desenvolvimento
# sbseg-hacka
