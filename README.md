# NetAnalytics_Pro
Sistema profissional de análise de rede com detecção inteligente de ameaças e geolocalização em tempo real

 PRÉ-REQUISITOS:
Python 3.8+
MySQL
Wireshark

INSTALAÇÃO:
PASSO 1: Clonar e acessar a pasta

git clone <url-do-repositorio>
cd NetAnalytics_Pro

PASSO 2: Instalar dependências Python

pip install -r requirements.txt
Se não tiver requirements.txt:


pip install flask pandas mysql-connector-python reportlab scipy aiohttp
PASSO 3: Configurar MySQL
sql
-- Conectar como root e executar:
ALTER USER 'root'@'localhost' IDENTIFIED BY 'sua_senha';
Editar app.py - linha ~15:

python
MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'sua_senha',  # ← COLOCAR SUA SENHA AQUI!
    'database': 'netanalytics_db'
}


❌ "ModuleNotFoundError"
bash
pip install nome_do_modulo
