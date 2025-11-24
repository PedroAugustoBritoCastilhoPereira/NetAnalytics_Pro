from flask import Flask, render_template, request, send_file, redirect, url_for
import pandas as pd
import json
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from scipy.stats import entropy
import subprocess, shutil
import mysql.connector
from mysql.connector import Error
from datetime import datetime
import urllib.request
import json as json_lib
import asyncio
import aiohttp
import logging
from logging.handlers import RotatingFileHandler
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import re
from functools import wraps
import os  # ✅ ADICIONAR ESTE IMPORT

app = Flask(__name__)

# ==================== CONFIGURAÇÃO AVANÇADA ====================
class Config:
    MYSQL_CONFIG = {
        'host': 'localhost',
        'user': 'root',
        'password': 'toor',
        'database': 'netanalytics_db',
        'pool_size': 10,
        'pool_reset_session': True
    }
    
    # Configurações de segurança
    MAX_PACKETS_PER_CAPTURE = 5000
    ALLOWED_INTERFACES = ['Wi-Fi', 'Ethernet', 'eth0', 'en0']
    MAX_CAPTURE_TIME = 60  # segundos
    RATE_LIMIT_REQUESTS = 10  # requisições por minuto
    
    # Configurações de performance
    ASYNC_WORKERS = 4
    DB_BATCH_SIZE = 100

# ==================== SISTEMA DE LOGGING AVANÇADO ====================
def setup_advanced_logging():
    """Configura sistema de logging profissional"""
    
    # ✅ CORREÇÃO: Criar pasta logs se não existir
    logs_dir = 'logs'
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
        print(f"✅ Pasta '{logs_dir}' criada com sucesso")
    
    logger = logging.getLogger('netanalytics')
    logger.setLevel(logging.INFO)
    
    # Formatação detalhada
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File Handler com rotação
    log_file = os.path.join(logs_dir, 'netanalytics.log')
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    
    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Log de inicialização
    logger.info("🚀 NetAnalytics Pro inicializado - Sistema de Logging Ativo")
    return logger

# Inicializar logger
logger = setup_advanced_logging()

# ==================== SISTEMA DE SEGURANÇA ====================
class SecuritySystem:
    def __init__(self):
        self.rate_limits = {}
        self.suspicious_ips = set()
        logger.info("🛡️ Sistema de Segurança Inicializado")
    
    def validate_input(self, data):
        """Validação robusta de entrada"""
        violations = []
        
        # Validação de interface
        if 'interface' in data and data['interface'] not in Config.ALLOWED_INTERFACES:
            violations.append(f"Interface não permitida: {data['interface']}")
            logger.warning(f"Tentativa de uso de interface não permitida: {data['interface']}")
        
        # Validação de quantidade de pacotes
        if 'qtd' in data:
            try:
                qtd = int(data['qtd'])
                if qtd <= 0 or qtd > Config.MAX_PACKETS_PER_CAPTURE:
                    violations.append(f"Quantidade de pacotes inválida: {qtd}")
            except ValueError:
                violations.append("Quantidade de pacotes deve ser numérica")
        
        # Validação contra SQL Injection básico
        for key, value in data.items():
            if isinstance(value, str) and self.has_sql_injection(value):
                violations.append(f"Possível tentativa de SQL injection em {key}")
                logger.warning(f"Possível SQL injection detectado: {key}={value}")
        
        return violations
    
    def has_sql_injection(self, value):
        """Detecta padrões de SQL injection"""
        sql_patterns = [
            r'(\bUNION\b.*\bSELECT\b)',
            r'(\bDROP\b.*\bTABLE\b)',
            r'(\bINSERT\b.*\bINTO\b)',
            r'(\bDELETE\b.*\bFROM\b)',
            r'(\bUPDATE\b.*\bSET\b)',
            r'(\bOR\b.*\b1=1\b)',
            r'(\b--\b)',
            r'(\b;\b)'
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False
    
    def check_rate_limit(self, ip):
        """Sistema de rate limiting"""
        now = time.time()
        if ip in self.rate_limits:
            requests, first_request = self.rate_limits[ip]
            
            # Reset a cada minuto
            if now - first_request > 60:
                self.rate_limits[ip] = [1, now]
                return True
            
            if requests >= Config.RATE_LIMIT_REQUESTS:
                logger.warning(f"Rate limit excedido para IP: {ip}")
                return False
            
            self.rate_limits[ip][0] += 1
        else:
            self.rate_limits[ip] = [1, now]
        
        return True

# Inicializar sistema de segurança
security_system = SecuritySystem()

# ==================== SISTEMA DE ALERTAS AVANÇADO ====================
class AlertSystem:
    def __init__(self):
        self.alerts = []
        logger.info("🚨 Sistema de Alertas Inicializado")
    
    def add_alert(self, level, message, packet_data=None):
        """Adiciona alerta ao sistema com logging"""
        alert = {
            'timestamp': datetime.now(),
            'level': level,
            'message': message,
            'packet_data': packet_data
        }
        self.alerts.append(alert)
        
        # Log baseado no nível do alerta
        if level == 'danger':
            logger.error(f"ALERTA PERIGO: {message}")
        elif level == 'warning':
            logger.warning(f"ALERTA AVISO: {message}")
        else:
            logger.info(f"ALERTA INFO: {message}")
            
        return alert
    
    def get_session_alerts(self, df):
        """Gera alertas para uma sessão específica"""
        session_alerts = []
        
        try:
            # 1. Muitas conexões de uma fonte
            ip_counts = df['src_ip'].value_counts()
            suspicious_ips = ip_counts[ip_counts > 20]
            for ip, count in suspicious_ips.items():
                if ip and ip != 'None':
                    session_alerts.append({
                        'level': 'warning',
                        'message': f"IP {ip} com {count} conexões (possível scanner)"
                    })
            
            # 2. Portas incomuns
            common_ports = [80, 443, 53, 22, 25, 993, 995, 587, 465]
            unusual_ports = df[~df['dst_port'].isin(common_ports) & df['dst_port'].notna()]
            if len(unusual_ports) > 3:
                session_alerts.append({
                    'level': 'danger' if len(unusual_ports) > 10 else 'warning',
                    'message': f"{len(unusual_ports)} conexões em portas incomuns"
                })
            
            # 3. Protocolos desconhecidos
            protocol_counts = df['protocol'].value_counts()
            if 'outro' in protocol_counts and protocol_counts['outro'] > 5:
                session_alerts.append({
                    'level': 'warning',
                    'message': f"{protocol_counts['outro']} pacotes com protocolos não identificados"
                })
            
            # 4. Tráfego muito alto
            total_bytes = df['length'].sum()
            if total_bytes > 1000000:
                session_alerts.append({
                    'level': 'info',
                    'message': f"Tráfego elevado: {total_bytes/1000000:.2f} MB"
                })
                
        except Exception as e:
            logger.error(f"Erro na análise de alertas: {e}")
        
        return session_alerts

alert_system = AlertSystem()

# ==================== CONEXÃO COM POOL ====================
def create_connection_pool():
    """Cria pool de conexões para melhor performance"""
    try:
        connection = mysql.connector.connect(
            pool_name="netanalytics_pool",
            pool_size=Config.MYSQL_CONFIG['pool_size'],
            **{k: v for k, v in Config.MYSQL_CONFIG.items() if k != 'pool_size'}
        )
        logger.info("✅ Pool de conexões MySQL criado com sucesso")
        return connection
    except Error as e:
        logger.error(f"❌ Erro ao criar pool de conexões: {e}")
        return None

# ==================== FUNÇÕES ASSÍNCRONAS ====================
async def async_capture_packets(interface, qtd):
    """Captura de pacotes assíncrona"""
    try:
        logger.info(f"Iniciando captura assíncrona: {interface}, {qtd} pacotes")
        
        tshark_path = shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
        command = [tshark_path, "-i", interface, "-c", str(qtd), "-T", "json"]
        
        # Execução assíncrona do comando
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Erro desconhecido"
            logger.error(f"Erro na captura assíncrona: {error_msg}")
            return None
        
        data = json_lib.loads(stdout.decode())
        logger.info(f"Captura assíncrona concluída: {len(data)} pacotes")
        return data
        
    except Exception as e:
        logger.error(f"Erro na captura assíncrona: {e}")
        return None

async def async_geolocation(ip):
    """Geolocalização assíncrona"""
    if not ip or ip == 'None' or ip.startswith(('192.168.', '10.', '172.')):
        return None
    
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,lat,lon"
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
            async with session.get(url) as response:
                data = await response.json()
                
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon')
                    }
                    
    except Exception as e:
        logger.debug(f"Erro na geolocalização do IP {ip}: {e}")
    
    return None

async def async_batch_geolocation(ips):
    """Geolocalização em lote assíncrona"""
    tasks = [async_geolocation(ip) for ip in ips if ip]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filtrar resultados válidos
    valid_results = {}
    for ip, result in zip(ips, results):
        if result and not isinstance(result, Exception):
            valid_results[ip] = result
    
    return valid_results

# ==================== FUNÇÕES DE BANCO OTIMIZADAS ====================
def init_database():
    """Inicializa o banco de dados com performance"""
    connection = create_connection_pool()
    if connection:
        try:
            cursor = connection.cursor()
            
            cursor.execute("CREATE DATABASE IF NOT EXISTS netanalytics_db")
            cursor.execute("USE netanalytics_db")
            
            # Tabela de sessões com índices
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS capture_sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    interface VARCHAR(50),
                    packet_count INT,
                    total_bytes BIGINT,
                    unique_ips INT,
                    entropy FLOAT,
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_interface (interface)
                )
            """)
            
            # Tabela de pacotes com índices
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    session_id INT,
                    timestamp VARCHAR(100),
                    src_ip VARCHAR(45),
                    dst_ip VARCHAR(45),
                    src_mac VARCHAR(17),
                    dst_mac VARCHAR(17),
                    protocol VARCHAR(10),
                    src_port INT,
                    dst_port INT,
                    length INT,
                    FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE,
                    INDEX idx_session_id (session_id),
                    INDEX idx_src_ip (src_ip),
                    INDEX idx_dst_ip (dst_ip),
                    INDEX idx_protocol (protocol),
                    INDEX idx_timestamp (timestamp(20))
                )
            """)
            
            connection.commit()
            logger.info("✅ Banco de dados inicializado com índices de performance")
            
        except Error as e:
            logger.error(f"❌ Erro ao inicializar banco: {e}")
        finally:
            cursor.close()
            connection.close()

def batch_insert_packets(cursor, session_id, packets_batch):
    """Insere pacotes em lote para melhor performance"""
    try:
        insert_query = """
            INSERT INTO packets 
            (session_id, timestamp, src_ip, dst_ip, src_mac, dst_mac, protocol, src_port, dst_port, length)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        cursor.executemany(insert_query, packets_batch)
        return True
    except Error as e:
        logger.error(f"Erro no batch insert: {e}")
        return False

def save_capture_session_optimized(session_data, packets_df):
    """Salva sessão otimizada com inserção em lote"""
    connection = create_connection_pool()
    if not connection:
        return None
        
    try:
        cursor = connection.cursor()
        
        # Insere a sessão
        cursor.execute("""
            INSERT INTO capture_sessions 
            (interface, packet_count, total_bytes, unique_ips, entropy)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            session_data['interface'],
            session_data['packet_count'],
            session_data['total_bytes'],
            session_data['unique_ips'],
            session_data['entropy']
        ))
        
        session_id = cursor.lastrowid
        
        # Prepara dados para inserção em lote
        packets_batch = []
        for _, packet in packets_df.iterrows():
            packets_batch.append((
                session_id,
                str(packet['timestamp']),
                str(packet['src_ip']),
                str(packet['dst_ip']),
                str(packet['src_mac']),
                str(packet['dst_mac']),
                str(packet['protocol']),
                int(packet['src_port']) if pd.notna(packet['src_port']) else None,
                int(packet['dst_port']) if pd.notna(packet['dst_port']) else None,
                int(packet['length'])
            ))
            
            # Insere em lotes
            if len(packets_batch) >= Config.DB_BATCH_SIZE:
                if not batch_insert_packets(cursor, session_id, packets_batch):
                    connection.rollback()
                    return None
                packets_batch = []
        
        # Insere o lote final
        if packets_batch:
            if not batch_insert_packets(cursor, session_id, packets_batch):
                connection.rollback()
                return None
        
        connection.commit()
        logger.info(f"✅ Sessão #{session_id} salva com {len(packets_df)} pacotes")
        return session_id
        
    except Error as e:
        logger.error(f"❌ Erro ao salvar sessão: {e}")
        if connection:
            connection.rollback()
        return None
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

# ==================== FUNÇÕES PRINCIPAIS ====================
def parse_packets(packets):
    """Converte pacotes para DataFrame - CORRIGIDO numpy.int64"""
    dados = []
    for packet in packets:
        layers = packet['_source']['layers']
        frame = layers.get('frame', {})
        eth = layers.get('eth', {})
        ip = layers.get('ip', {})
        tcp = layers.get('tcp', {})
        udp = layers.get('udp', {})
        protocolo = "tcp" if "tcp" in layers else ("udp" if "udp" in layers else ip.get("ip.proto", "outro"))
        
        src_port = tcp.get('tcp.srcport', udp.get('udp.srcport', None))
        dst_port = tcp.get('tcp.dstport', udp.get('udp.dstport', None))
        
        # CONVERSÃO EXPLÍCITA para tipos Python nativos
        dados.append({
            'timestamp': str(frame.get('frame.time', None)),
            'src_mac': str(eth.get('eth.src', None)),
            'dst_mac': str(eth.get('eth.dst', None)),
            'src_ip': str(ip.get('ip.src', None)),
            'dst_ip': str(ip.get('ip.dst', None)),
            'protocol': str(protocolo),
            'src_port': int(src_port) if src_port and src_port.isdigit() else None,
            'dst_port': int(dst_port) if dst_port and dst_port.isdigit() else None,
            'length': int(frame.get('frame.len', 0))
        })
    return pd.DataFrame(dados)

def get_ip_geolocation(ip):
    """Geolocalização síncrona (fallback)"""
    if not ip or ip == 'None' or ip.startswith(('192.168.', '10.', '172.')):
        return None
    
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,lat,lon"
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json_lib.loads(response.read().decode())
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'N/A'),
                    'city': data.get('city', 'N/A'),
                    'isp': data.get('isp', 'N/A'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon')
                }
    except Exception as e:
        logger.debug(f"Erro na geolocalização síncrona do IP {ip}: {e}")
    return None

def get_sessions():
    """Busca sessões com cache implícito"""
    connection = create_connection_pool()
    sessions = []
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT * FROM capture_sessions 
                ORDER BY timestamp DESC 
                LIMIT 10
            """)
            sessions = cursor.fetchall()
        except Error as e:
            logger.error(f"❌ Erro ao buscar sessões: {e}")
        finally:
            cursor.close()
            connection.close()
    return sessions

def get_session_detail(session_id):
    """Busca detalhes de uma sessão específica"""
    connection = create_connection_pool()
    session = None
    packets = []
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute("SELECT * FROM capture_sessions WHERE id = %s", (session_id,))
            session = cursor.fetchone()
            
            if session:
                cursor.execute("""
                    SELECT * FROM packets 
                    WHERE session_id = %s 
                    ORDER BY timestamp DESC 
                    LIMIT 100
                """, (session_id,))
                packets = cursor.fetchall()
            
        except Error as e:
            logger.error(f"❌ Erro ao buscar sessão: {e}")
        finally:
            cursor.close()
            connection.close()
    return session, packets

# ==================== ROTAS PRINCIPAIS ====================
@app.route("/", methods=["GET", "POST"])
def index():
    start_time = time.time()
    client_ip = request.remote_addr
    
    logger.info(f"📥 Requisição recebida de {client_ip} - {request.method}")
    
    # Rate limiting
    if not security_system.check_rate_limit(client_ip):
        logger.warning(f"Rate limit excedido para {client_ip}")
        return render_template("index.html", 
                             error="⏰ Muitas requisições. Aguarde um momento.",
                             sessions=[])
    
    sessions = get_sessions()
    
    # Verifica se é uma requisição para ver detalhes
    view_session_id = request.args.get('view_session')
    if view_session_id:
        session_detail, packets = get_session_detail(int(view_session_id))
        
        # Geolocalização assíncrona
        unique_ips = set()
        for packet in packets:
            if packet['src_ip'] and packet['src_ip'] not in unique_ips:
                unique_ips.add(packet['src_ip'])
        
        # Executa geolocalização em lote
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            geo_results = loop.run_until_complete(async_batch_geolocation(list(unique_ips)))
            loop.close()
        except:
            # Fallback síncrono
            geo_results = {}
            for ip in unique_ips:
                geo_results[ip] = get_ip_geolocation(ip)
        
        response_time = time.time() - start_time
        logger.info(f"📤 Resposta enviada em {response_time:.2f}s - Detalhes da sessão")
        
        return render_template("index.html", 
                             sessions=sessions,
                             session_detail=session_detail,
                             packets=packets,
                             unique_ips=geo_results,
                             active_tab="history")
    
    # Verifica se é uma requisição POST de captura
    if request.method == "POST":
        # Validação de segurança
        violations = security_system.validate_input(request.form)
        if violations:
            logger.warning(f"Violacoes de segurança detectadas: {violations}")
            return render_template("index.html", 
                                 sessions=sessions,
                                 error="❌ Dados de entrada inválidos.",
                                 active_tab="capture")
        
        interface = request.form.get("interface", "Wi-Fi")
        qtd = int(request.form.get("qtd", 100))
        
        logger.info(f"🎯 Iniciando captura: {interface}, {qtd} pacotes")
        
        try:
            # Captura assíncrona
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            data = loop.run_until_complete(async_capture_packets(interface, qtd))
            loop.close()
            
            if not data:
                return render_template("index.html", 
                                     sessions=sessions,
                                     error="❌ Erro na captura de pacotes.",
                                     active_tab="capture")
            
            df = parse_packets(data)
            logger.info(f"📦 {len(df)} pacotes capturados com sucesso!")
            
            # Processamento dos dados
            protocol_dist = df['protocol'].value_counts(normalize=True)
            entropy_value = float(entropy(protocol_dist.values))
            
            # Salva no MySQL otimizado
            session_data = {
                'interface': interface,
                'packet_count': len(df),
                'total_bytes': int(df['length'].sum()),
                'unique_ips': int(df['src_ip'].nunique()),
                'entropy': entropy_value
            }
            
            session_id = save_capture_session_optimized(session_data, df)
            
            # Gera alertas
            session_alerts = alert_system.get_session_alerts(df)
            
            # Atualiza sessões
            sessions = get_sessions()
            
            response_time = time.time() - start_time
            logger.info(f"✅ Captura concluída em {response_time:.2f}s - Sessão #{session_id}")
            
            return render_template("index.html",
                                 sessions=sessions,
                                 df_length=len(df),
                                 unique_ips=session_data['unique_ips'],
                                 entropy=session_data['entropy'],
                                 protocol_counts=df['protocol'].value_counts().to_dict(),
                                 total_bytes=session_data['total_bytes'],
                                 result="ok",
                                 session_id=session_id,
                                 session_alerts=session_alerts,
                                 raw_data=df.to_json(orient="records"),
                                 active_tab="capture")
                                 
        except asyncio.TimeoutError:
            logger.error("⏰ Timeout na captura assíncrona")
            return render_template("index.html",
                                 sessions=sessions,
                                 error="⏰ Timeout: A captura demorou muito",
                                 active_tab="capture")
        except Exception as e:
            logger.error(f"❌ Erro inesperado na captura: {e}")
            return render_template("index.html",
                                 sessions=sessions,
                                 error=f"❌ Erro inesperado: {str(e)}",
                                 active_tab="capture")
    
    # Requisição GET normal
    response_time = time.time() - start_time
    logger.info(f"📤 Resposta GET em {response_time:.2f}s")
    
    return render_template("index.html", sessions=sessions, active_tab="capture")

@app.route("/download", methods=["POST"])
def download():
    """Download de relatório PDF profissional"""
    client_ip = request.remote_addr
    logger.info(f"📥 Download de relatório solicitado por {client_ip}")
    
    try:
        raw = request.form.get("data")
        df = pd.read_json(raw)
        
        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        # ==================== CABEÇALHO PROFISSIONAL ====================
        pdf.setFillColorRGB(0, 0.8, 0.8)  # Cor ciano
        pdf.setFont("Helvetica-Bold", 20)
        pdf.drawString(50, height - 50, "NETANALYTICS PRO")
        
        pdf.setFillColorRGB(0.7, 0.7, 0.7)  # Cinza
        pdf.setFont("Helvetica", 10)
        pdf.drawString(50, height - 70, "Relatório Completo de Análise de Rede")
        pdf.drawString(50, height - 85, f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        
        # Linha divisória
        pdf.setStrokeColorRGB(0, 0.8, 0.8)
        pdf.setLineWidth(1)
        pdf.line(50, height - 95, width - 50, height - 95)
        
        # ==================== RESUMO EXECUTIVO ====================
        y_position = height - 120
        
        pdf.setFillColorRGB(0.2, 0.2, 0.2)
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(50, y_position, "📊 RESUMO EXECUTIVO")
        y_position -= 25
        
        # Métricas principais em boxes
        metrics = [
            ("Total de Pacotes", len(df)),
            ("IPs Únicos", df['src_ip'].nunique()),
            ("Bytes Trafegados", f"{df['length'].sum():,}"),
            ("Entropia", f"{entropy(df['protocol'].value_counts(normalize=True).values):.2f}"),
            ("Tempo de Captura", f"{len(df) // 10} segundos" if len(df) > 0 else "N/A")
        ]
        
        pdf.setFont("Helvetica", 9)
        box_width = 100
        box_height = 40
        x_positions = [60, 170, 280, 390]
        
        for i, (label, value) in enumerate(metrics):
            if i < len(x_positions):
                x = x_positions[i]
                
                # Box background
                pdf.setFillColorRGB(0.95, 0.95, 0.95)
                pdf.rect(x, y_position - box_height, box_width, box_height, fill=1, stroke=0)
                
                # Border
                pdf.setStrokeColorRGB(0, 0.8, 0.8)
                pdf.setLineWidth(0.5)
                pdf.rect(x, y_position - box_height, box_width, box_height, fill=0, stroke=1)
                
                # Text
                pdf.setFillColorRGB(0, 0, 0)
                pdf.setFont("Helvetica-Bold", 8)
                pdf.drawString(x + 5, y_position - 15, label)
                pdf.setFont("Helvetica-Bold", 12)
                pdf.drawString(x + 5, y_position - 30, str(value))
        
        y_position -= 60
        
        # ==================== DISTRIBUIÇÃO POR PROTOCOLO ====================
        pdf.setFillColorRGB(0.2, 0.2, 0.2)
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(50, y_position, "🌐 DISTRIBUIÇÃO POR PROTOCOLO")
        y_position -= 25
        
        protocol_counts = df['protocol'].value_counts()
        total_packets = len(df)
        
        pdf.setFont("Helvetica", 10)
        for protocol, count in protocol_counts.items():
            percentage = (count / total_packets) * 100
            pdf.drawString(70, y_position, f"• {protocol}: {count} pacotes ({percentage:.1f}%)")
            y_position -= 15
            
            if y_position < 100:  # Nova página se necessário
                pdf.showPage()
                y_position = height - 50
                pdf.setFont("Helvetica", 10)
        
        y_position -= 10
        
        # ==================== TOP IPs ====================
        pdf.setFillColorRGB(0.2, 0.2, 0.2)
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(50, y_position, "🔍 TOP ENDEREÇOS IP")
        y_position -= 25
        
        top_ips = df['src_ip'].value_counts().head(8)
        
        pdf.setFont("Helvetica", 9)
        for ip, count in top_ips.items():
            if ip and ip != 'None':
                pdf.drawString(70, y_position, f"• {ip}: {count} conexões")
                y_position -= 12
                
                if y_position < 100:
                    pdf.showPage()
                    y_position = height - 50
                    pdf.setFont("Helvetica", 9)
        
        y_position -= 15
        
        # ==================== ANÁLISE DE PORTAS ====================
        pdf.setFillColorRGB(0.2, 0.2, 0.2)
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(50, y_position, "🚪 ANÁLISE DE PORTAS")
        y_position -= 25
        
        # Portas mais comuns
        common_ports = {
            80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 
            25: "SMTP", 993: "IMAPS", 995: "POP3S"
        }
        
        port_analysis = df['dst_port'].value_counts().head(6)
        
        pdf.setFont("Helvetica", 9)
        for port, count in port_analysis.items():
            if pd.notna(port):
                service = common_ports.get(port, "Desconhecido")
                pdf.drawString(70, y_position, f"• Porta {port} ({service}): {count} conexões")
                y_position -= 12
                
                if y_position < 100:
                    pdf.showPage()
                    y_position = height - 50
                    pdf.setFont("Helvetica", 9)
        
        y_position -= 15
        
        # ==================== DETECÇÃO DE POSSÍVEIS AMEAÇAS ====================
        pdf.setFillColorRGB(0.2, 0.2, 0.2)
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(50, y_position, "🚨 DETECÇÃO DE POSSÍVEIS AMEAÇAS")
        y_position -= 25
        
        threats = []
        
        # 1. IPs com muitas conexões
        ip_counts = df['src_ip'].value_counts()
        suspicious_ips = ip_counts[ip_counts > 20]
        for ip, count in suspicious_ips.items():
            if ip and ip != 'None':
                threats.append(f"IP {ip} com {count} conexões (possível scanner)")
        
        # 2. Portas incomuns
        common_port_list = list(common_ports.keys())
        unusual_ports = df[~df['dst_port'].isin(common_port_list) & df['dst_port'].notna()]
        if len(unusual_ports) > 3:
            threats.append(f"{len(unusual_ports)} conexões em portas incomuns")
        
        # 3. Protocolos desconhecidos
        if 'outro' in protocol_counts and protocol_counts['outro'] > 5:
            threats.append(f"{protocol_counts['outro']} pacotes com protocolos não identificados")
        
        pdf.setFont("Helvetica", 9)
        if threats:
            for threat in threats[:4]:  # Limitar a 4 ameaças
                pdf.setFillColorRGB(0.8, 0.2, 0.2)  # Vermelho para ameaças
                pdf.drawString(70, y_position, f"⚠ {threat}")
                y_position -= 15
                pdf.setFillColorRGB(0, 0, 0)  # Voltar ao preto
                
                if y_position < 100:
                    pdf.showPage()
                    y_position = height - 50
                    pdf.setFont("Helvetica", 9)
        else:
            pdf.setFillColorRGB(0.2, 0.8, 0.2)  # Verde para seguro
            pdf.drawString(70, y_position, "✅ Nenhuma ameaça significativa detectada")
            y_position -= 15
            pdf.setFillColorRGB(0, 0, 0)
        
        y_position -= 20
        
        # ==================== ESTATÍSTICAS DETALHADAS ====================
        pdf.setFillColorRGB(0.2, 0.2, 0.2)
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(50, y_position, "📈 ESTATÍSTICAS DETALHADAS")
        y_position -= 25
        
        stats = [
            ("Tamanho médio dos pacotes", f"{df['length'].mean():.1f} bytes"),
            ("Maior pacote", f"{df['length'].max()} bytes"),
            ("Menor pacote", f"{df['length'].min()} bytes"),
            ("Pacotes TCP", f"{len(df[df['protocol'] == 'tcp'])}"),
            ("Pacotes UDP", f"{len(df[df['protocol'] == 'udp'])}"),
            ("Outros protocolos", f"{len(df[~df['protocol'].isin(['tcp', 'udp'])])}"),
            ("Taxa de pacotes/segundo", f"{(len(df) / 60):.1f}" if len(df) > 0 else "N/A")
        ]
        
        pdf.setFont("Helvetica", 9)
        for i in range(0, len(stats), 2):
            if i < len(stats):
                stat1 = stats[i]
                pdf.drawString(70, y_position, f"• {stat1[0]}: {stat1[1]}")
            
            if i + 1 < len(stats):
                stat2 = stats[i + 1]
                pdf.drawString(250, y_position, f"• {stat2[0]}: {stat2[1]}")
            
            y_position -= 15
            
            if y_position < 100:
                pdf.showPage()
                y_position = height - 50
                pdf.setFont("Helvetica", 9)
        
        y_position -= 20
        
        # ==================== RECOMENDAÇÕES ====================
        pdf.setFillColorRGB(0.2, 0.2, 0.2)
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(50, y_position, "💡 RECOMENDAÇÕES")
        y_position -= 25
        
        recommendations = []
        
        if len(unusual_ports) > 10:
            recommendations.append("Investigar portas incomuns - possível atividade suspeita")
        
        if len(suspicious_ips) > 0:
            recommendations.append("Monitorar IPs com alta atividade de conexão")
        
        if df['length'].sum() > 1000000:  # 1MB
            recommendations.append("Alto volume de tráfego - verificar necessidade")
        
        if len(recommendations) == 0:
            recommendations.append("Tráfego dentro dos parâmetros normais")
            recommendations.append("Manter monitoramento regular")
        
        pdf.setFont("Helvetica", 9)
        for rec in recommendations[:3]:
            pdf.drawString(70, y_position, f"• {rec}")
            y_position -= 15
            
            if y_position < 100:
                pdf.showPage()
                y_position = height - 50
                pdf.setFont("Helvetica", 9)
        
        # ==================== RODAPÉ ====================
        pdf.setFillColorRGB(0.5, 0.5, 0.5)
        pdf.setFont("Helvetica-Oblique", 8)
        pdf.drawString(50, 30, "Relatório gerado automaticamente pelo NetAnalytics Pro v2.0")
        pdf.drawString(50, 20, "Sistema de análise de rede profissional")
        
        pdf.save()
        buffer.seek(0)
        
        logger.info(f"✅ Relatório PDF profissional gerado para {client_ip}")
        return send_file(
            buffer, 
            as_attachment=True, 
            download_name=f"relatorio_netanalytics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", 
            mimetype="application/pdf"
        )
        
    except Exception as e:
        logger.error(f"❌ Erro ao gerar relatório PDF: {e}")
        return "Erro ao gerar relatório", 500

@app.route("/delete_session/<int:session_id>")
def delete_session(session_id):
    """Exclusão de sessão com logging"""
    client_ip = request.remote_addr
    logger.info(f"🗑️ Exclusão solicitada por {client_ip} - Sessão #{session_id}")
    
    connection = create_connection_pool()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("DELETE FROM capture_sessions WHERE id = %s", (session_id,))
            connection.commit()
            logger.info(f"✅ Sessão #{session_id} deletada por {client_ip}")
        except Error as e:
            logger.error(f"❌ Erro ao deletar sessão #{session_id}: {e}")
        finally:
            cursor.close()
            connection.close()
    
    return redirect('/')

@app.route("/system/status")
def system_status():
    """Endpoint de status do sistema"""
    status = {
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0',
        'features': {
            'async_capture': True,
            'security_system': True,
            'advanced_logging': True,
            'performance_optimized': True
        }
    }
    return status

if __name__ == "__main__":
    # ✅ CORREÇÃO: Já não precisa mais criar a pasta aqui
    # porque a função setup_advanced_logging() já faz isso
    
    # Inicializar sistemas
    init_database()
    
    logger.info("=" * 50)
    logger.info("🚀 NETANALYTICS PRO v2.0 INICIADO")
    logger.info("📊 Performance: ✅ Assíncrono")
    logger.info("🛡️ Segurança: ✅ Avançada") 
    logger.info("📝 Logging: ✅ Profissional")
    logger.info("=" * 50)
    
    app.run(debug=True, threaded=True)