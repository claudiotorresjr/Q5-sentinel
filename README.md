# Q5-sentinel
## Desenvolvido para o Hachathon RNP 2025

### Frontend

```bash
cd frontend && npm install
npm run dev
```

Acessar: `http://localhost:8080`

# Motor

Usar python3

```bash
cd motor
python src/main.py --inputs src/data/CPBR_produto2.json
# ou
python src/main.py --inputs src/data/CPBR_produto1.json src/data/CPBR_produto2.json src/data/CPBR_produto3.json
```

Iniciar o servidor


```bash
cd motor
python src/api_server.py
```
