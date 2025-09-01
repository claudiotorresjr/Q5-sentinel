# Q5-sentinel
## Desenvolvido para o Hachathon RNP 2025

### Frontend

```bash
cd frontend && npm install
npm run dev
```

Acessar: `http://localhost:8080`

### Motor

Usar python3

```bash
cd motor
conda create -n q5-sentinel python=3.11 -y
conda activate q5-sentinel

conda install -c conda-forge flask=2.3.3 flask-cors=4.0.0 \
    pandas=2.1.3 numpy=1.25.2 requests=2.31.0 tqdm=4.66.1 -y

# PyTorch with CPU only
conda install -c pytorch pytorch=2.1.0 cpuonly -y

```

Iniciar o servidor


```bash
cd motor
python src/api_server.py
```
