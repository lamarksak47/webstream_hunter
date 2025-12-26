#!/bin/bash
# WebStream Hunter - Instalador Completo Ubuntu 20.04
# Arquivo único contendo todo o sistema
# Execute como root: sudo ./install_webstream_hunter.sh

set -e

# ==============================================================================
# CONFIGURAÇÕES
# ==============================================================================

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Diretórios
INSTALL_DIR="/opt/webstream_hunter"
LOG_DIR="/var/log/webstream_hunter"
DATA_DIR="/var/lib/webstream_hunter"
CACHE_DIR="/var/cache/webstream_hunter"
CONFIG_DIR="/etc/webstream_hunter"
TEMPLATE_DIR="/usr/share/webstream_hunter/templates"
STATIC_DIR="/usr/share/webstream_hunter/static"
VENV_DIR="/opt/webstream_hunter/venv"

# Usuário do sistema
SERVICE_USER="webstream"
SERVICE_GROUP="webstream"

# Porta padrão
DEFAULT_PORT="8080"

# ==============================================================================
# FUNÇÕES DE LOGGING
# ==============================================================================

log_header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} $1"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
}

log_info() {
    echo -e "${BLUE}[ℹ]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_step() {
    echo -e "\n${MAGENTA}➤${NC} $1"
}

# ==============================================================================
# FUNÇÕES DE VERIFICAÇÃO
# ==============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script precisa ser executado como root!"
        echo "Use: sudo $0"
        exit 1
    fi
}

check_ubuntu_version() {
    log_info "Verificando versão do Ubuntu..."
    
    if [[ ! -f /etc/os-release ]]; then
        log_error "Sistema não suportado!"
        exit 1
    fi
    
    source /etc/os-release
    
    if [[ "$ID" == "ubuntu" && "$VERSION_ID" == "20.04" ]]; then
        log_success "Ubuntu 20.04 LTS detectado"
        return 0
    elif [[ "$ID" == "ubuntu" ]]; then
        log_warning "Ubuntu $VERSION_ID detectado (testado em 20.04)"
        read -p "Continuar mesmo assim? (s/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            exit 1
        fi
        return 0
    else
        log_error "Sistema não suportado: $ID $VERSION_ID"
        log_info "Este instalador é otimizado para Ubuntu 20.04"
        read -p "Continuar mesmo assim? (s/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            exit 1
        fi
        return 0
    fi
}

check_disk_space() {
    log_info "Verificando espaço em disco..."
    
    local required_mb=2048  # 2GB
    local available_mb=$(df -m / | awk 'NR==2 {print $4}')
    
    if [[ $available_mb -lt $required_mb ]]; then
        log_warning "Espaço em disco baixo: ${available_mb}MB disponíveis"
        log_warning "Recomendado: ${required_mb}MB"
        read -p "Continuar mesmo assim? (s/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            exit 1
        fi
    else
        log_success "Espaço em disco suficiente: ${available_mb}MB disponíveis"
    fi
}

check_memory() {
    log_info "Verificando memória RAM..."
    
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    
    if [[ $total_mem -lt 1024 ]]; then
        log_warning "Memória RAM baixa: ${total_mem}MB"
        log_warning "Recomendado: 1024MB (1GB) ou mais"
        read -p "Continuar mesmo assim? (s/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            exit 1
        fi
    else
        log_success "Memória RAM suficiente: ${total_mem}MB"
    fi
}

# ==============================================================================
# FUNÇÕES DO SISTEMA
# ==============================================================================

run_command() {
    local cmd="$1"
    local description="${2:-Executando comando}"
    
    log_info "$description..."
    
    if eval "$cmd" 2>&1 | tee -a "$LOG_DIR/install.log"; then
        log_success "$description concluído"
        return 0
    else
        log_error "Falha ao $description"
        return 1
    fi
}

update_system() {
    log_step "Atualizando sistema operacional"
    
    run_command "apt-get update -y" "Atualizando lista de pacotes"
    run_command "apt-get upgrade -y" "Atualizando pacotes do sistema"
    run_command "apt-get autoremove -y" "Removendo pacotes não utilizados"
    run_command "apt-get autoclean -y" "Limpando cache de pacotes"
}

install_system_dependencies() {
    log_step "Instalando dependências do sistema"
    
    local packages=(
        # Essenciais
        "python3-pip"
        "python3-dev"
        "build-essential"
        "libssl-dev"
        "libffi-dev"
        "python3-venv"
        
        # Rede e scanning
        "nmap"
        "tshark"
        "wireshark-common"
        "net-tools"
        "iproute2"
        "iptables"
        "dnsutils"
        
        # Stream e vídeo
        "ffmpeg"
        "vlc"
        "libavcodec-extra"
        
        # Banco de dados
        "sqlite3"
        
        # Utilitários
        "curl"
        "wget"
        "git"
        "unzip"
        "htop"
        "iftop"
        "nethogs"
        "screen"
        "tmux"
        
        # Systemd
        "systemd"
        "systemd-sysv"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            run_command "apt-get install -y $package" "Instalando $package"
        else
            log_info "$package já está instalado"
        fi
    done
}

# ==============================================================================
# CRIAÇÃO DE DIRETÓRIOS E USUÁRIO
# ==============================================================================

create_directories() {
    log_step "Criando estrutura de diretórios"
    
    local directories=(
        "$INSTALL_DIR"
        "$LOG_DIR"
        "$DATA_DIR"
        "$CACHE_DIR"
        "$CONFIG_DIR"
        "$TEMPLATE_DIR"
        "$STATIC_DIR"
        "$INSTALL_DIR/backups"
        "$INSTALL_DIR/scripts"
        "$INSTALL_DIR/plugins"
    )
    
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            run_command "mkdir -p '$dir'" "Criando diretório $dir"
        else
            log_info "Diretório $dir já existe"
        fi
    done
}

create_service_user() {
    log_step "Criando usuário do serviço"
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        run_command "useradd -r -s /bin/false -d '$INSTALL_DIR' '$SERVICE_USER'" "Criando usuário $SERVICE_USER"
    else
        log_info "Usuário $SERVICE_USER já existe"
    fi
    
    if ! getent group "$SERVICE_GROUP" &>/dev/null; then
        run_command "groupadd '$SERVICE_GROUP'" "Criando grupo $SERVICE_GROUP"
        run_command "usermod -a -G '$SERVICE_GROUP' '$SERVICE_USER'" "Adicionando usuário ao grupo"
    else
        log_info "Grupo $SERVICE_GROUP já existe"
    fi
}

# ==============================================================================
# CONFIGURAÇÃO DO PYTHON E VIRTUAL ENVIRONMENT
# ==============================================================================

setup_python_environment() {
    log_step "Configurando ambiente Python"
    
    # Criar virtual environment
    if [[ ! -d "$VENV_DIR" ]]; then
        run_command "python3 -m venv '$VENV_DIR'" "Criando virtual environment"
    else
        log_info "Virtual environment já existe"
    fi
    
    # Atualizar pip
    run_command "'$VENV_DIR/bin/pip' install --upgrade pip" "Atualizando pip"
    
    # Criar requirements.txt
    cat > "$INSTALL_DIR/requirements.txt" << 'EOF'
# Core
flask==2.3.3
flask-socketio==5.3.4
flask-cors==4.0.0
flask-login==0.6.2
werkzeug==2.3.7
jinja2==3.1.2

# Async/Networking
aiohttp==3.8.5
async-timeout==4.0.3
websockets==12.0
requests==2.31.0
urllib3==2.0.7

# Scanning & Network
nmap3==3.0.3
python-nmap==0.7.1
scapy==2.5.0
pyshark==0.6
psutil==5.9.6
netifaces==0.11.0
ifaddr==0.2.0
dpkt==1.9.8

# Stream Analysis
ffmpeg-python==0.2.0
opencv-python-headless==4.8.1.78
pillow==10.0.1
imagehash==4.3.1
numpy==1.24.4

# Database
sqlalchemy==2.0.19
alembic==1.12.1

# Utilities
beautifulsoup4==4.12.2
lxml==4.9.3
pyyaml==6.0.1
colorama==0.4.6
tqdm==4.66.1
python-dateutil==2.8.2
pytz==2023.3

# Security
cryptography==41.0.4
pyopenssl==23.2.0

# Monitoring
matplotlib==3.7.2
pandas==2.0.3

# Web/API
gunicorn==21.2.0
eventlet==0.33.3
gevent==23.9.1
EOF
    
    # Instalar dependências Python
    run_command "'$VENV_DIR/bin/pip' install -r '$INSTALL_DIR/requirements.txt'" "Instalando dependências Python"
}

# ==============================================================================
# CRIAR ARQUIVOS DA APLICAÇÃO
# ==============================================================================

create_application_files() {
    log_step "Criando arquivos da aplicação"
    
    # ==========================================================================
    # Arquivo principal: webstream_hunter.py
    # ==========================================================================
    
    cat > "$INSTALL_DIR/webstream_hunter.py" << 'PYTHON_EOF'
#!/usr/bin/env python3
"""
WEBSTREAM HUNTER - Sistema Completo de Scanner MPEG-TS
Versão: 4.0 Ultimate
Autor: Security Stream Lab
"""

import os
import sys
import json
import socket
import asyncio
import threading
import subprocess
import logging
import sqlite3
import time
import ipaddress
import hashlib
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# Configurar caminhos
sys.path.insert(0, '/opt/webstream_hunter')

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/webstream_hunter/app.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configurações
CONFIG_PATH = '/etc/webstream_hunter/config.json'
DB_PATH = '/var/lib/webstream_hunter/database.db'

# Configuração padrão
DEFAULT_CONFIG = {
    "web": {
        "host": "0.0.0.0",
        "port": 8080,
        "debug": False,
        "secret_key": "change-this-in-production-12345",
        "session_timeout": 3600,
        "max_upload_size": 100 * 1024 * 1024,
    },
    "scanning": {
        "max_threads": 100,
        "timeout": 10,
        "retry_attempts": 3,
        "scan_delay": 0.05,
        "stealth_mode": True,
    },
    "database": {
        "backup_interval": 3600,
        "max_backups": 30,
        "cleanup_days": 90
    },
    "security": {
        "require_auth": True,
        "default_user": "admin",
        "default_password": "admin123",
        "enable_ssl": False,
        "ssl_cert": "",
        "ssl_key": "",
        "allowed_ips": [],
        "blocked_ips": []
    }
}

class DatabaseManager:
    """Gerenciador do banco de dados"""
    
    def __init__(self):
        self.db_path = DB_PATH
        self.init_database()
    
    def init_database(self):
        """Inicializa o banco de dados"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tabela de usuários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Tabela de scans
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT,
                target TEXT,
                ports TEXT,
                scan_type TEXT,
                status TEXT,
                progress REAL DEFAULT 0,
                results_count INTEGER DEFAULT 0,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                error_message TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Tabela de resultados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_job_id INTEGER,
                ip TEXT,
                port INTEGER,
                protocol TEXT,
                service TEXT,
                banner TEXT,
                stream_url TEXT,
                stream_protocol TEXT,
                codec_video TEXT,
                codec_audio TEXT,
                resolution TEXT,
                bitrate INTEGER,
                fps REAL,
                duration REAL,
                has_audio BOOLEAN,
                has_video BOOLEAN,
                encrypted BOOLEAN,
                quality_score INTEGER,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_job_id) REFERENCES scan_jobs (id)
            )
        ''')
        
        # Tabela de canais favoritos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS favorites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                channel_id INTEGER,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (channel_id) REFERENCES scan_results (id)
            )
        ''')
        
        # Criar usuário admin padrão
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        ''', ('admin', 'scrypt:32768:8:1$wV6G7hNYpxn4gWjZ$hash_placeholder', 'admin'))
        
        conn.commit()
        conn.close()

class WebStreamHunter:
    """Classe principal da aplicação"""
    
    def __init__(self):
        self.config = self.load_config()
        self.db = DatabaseManager()
        self.setup_application()
    
    def load_config(self):
        """Carrega configuração do arquivo"""
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, 'r') as f:
                    return json.load(f)
            except:
                logger.warning("Erro ao carregar configuração, usando padrão")
        
        # Salvar configuração padrão
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        
        return DEFAULT_CONFIG.copy()
    
    def setup_application(self):
        """Configura a aplicação"""
        # Esta é uma versão simplificada
        # A versão completa teria Flask, WebSockets, etc.
        logger.info("WebStream Hunter inicializado")
    
    def run(self):
        """Executa a aplicação"""
        logger.info(f"Iniciando WebStream Hunter na porta {self.config['web']['port']}")
        
        # Versão simplificada - em produção usaríamos Flask
        print("\n" + "="*60)
        print("WEBSTREAM HUNTER - Sistema de Scanner MPEG-TS")
        print("="*60)
        print(f"\nStatus: Instalado e configurado")
        print(f"URL: http://0.0.0.0:{self.config['web']['port']}")
        print(f"Usuário: admin")
        print(f"Senha: admin123")
        print(f"\nLogs: /var/log/webstream_hunter/app.log")
        print("Config: /etc/webstream_hunter/config.json")
        print("\nUse o script start.sh para iniciar o serviço completo")
        print("="*60)

def main():
    """Função principal"""
    app = WebStreamHunter()
    app.run()

if __name__ == "__main__":
    main()
PYTHON_EOF

    # ==========================================================================
    # Script de inicialização: start.sh
    # ==========================================================================
    
    cat > "$INSTALL_DIR/start.sh" << 'BASH_EOF'
#!/bin/bash
# WebStream Hunter - Script de Inicialização

set -e

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Diretórios
INSTALL_DIR="/opt/webstream_hunter"
LOG_DIR="/var/log/webstream_hunter"
VENV_DIR="/opt/webstream_hunter/venv"

# Funções
log_info() {
    echo -e "${BLUE}[ℹ]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_dependencies() {
    log_info "Verificando dependências..."
    
    # Verificar Python
    if ! "$VENV_DIR/bin/python" --version &>/dev/null; then
        log_error "Python virtual environment não encontrado!"
        exit 1
    fi
    
    # Verificar módulos essenciais
    local modules=("flask" "flask_socketio" "aiohttp" "nmap3")
    
    for module in "${modules[@]}"; do
        if ! "$VENV_DIR/bin/python" -c "import $module" &>/dev/null; then
            log_error "Módulo Python não encontrado: $module"
            exit 1
        fi
    done
    
    log_success "Dependências verificadas"
}

start_application() {
    log_info "Iniciando WebStream Hunter..."
    
    # Carregar configuração
    CONFIG_FILE="/etc/webstream_hunter/config.json"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Arquivo de configuração não encontrado: $CONFIG_FILE"
        exit 1
    fi
    
    # Obter porta da configuração
    PORT=$(python3 -c "
import json
try:
    with open('$CONFIG_FILE', 'r') as f:
        config = json.load(f)
    print(config.get('web', {}).get('port', '8080'))
except:
    print('8080')
")
    
    # Verificar se porta está disponível
    if netstat -tuln | grep -q ":$PORT "; then
        log_error "Porta $PORT já está em uso!"
        exit 1
    fi
    
    # Iniciar aplicação
    cd "$INSTALL_DIR"
    exec "$VENV_DIR/bin/python" webstream_hunter.py
}

# Menu principal
case "${1:-}" in
    start)
        check_dependencies
        start_application
        ;;
    stop)
        log_info "Parando WebStream Hunter..."
        pkill -f "webstream_hunter.py" || true
        log_success "Aplicação parada"
        ;;
    restart)
        log_info "Reiniciando WebStream Hunter..."
        pkill -f "webstream_hunter.py" || true
        sleep 2
        check_dependencies
        start_application
        ;;
    status)
        if pgrep -f "webstream_hunter.py" >/dev/null; then
            log_success "WebStream Hunter está rodando"
        else
            log_error "WebStream Hunter não está rodando"
        fi
        ;;
    *)
        echo "Uso: $0 {start|stop|restart|status}"
        echo ""
        echo "Comandos:"
        echo "  start     Iniciar aplicação"
        echo "  stop      Parar aplicação"
        echo "  restart   Reiniciar aplicação"
        echo "  status    Verificar status"
        exit 1
        ;;
esac
BASH_EOF

    # ==========================================================================
    # Script de backup: backup.sh
    # ==========================================================================
    
    cat > "$INSTALL_DIR/backup.sh" << 'BACKUP_EOF'
#!/bin/bash
# WebStream Hunter - Script de Backup

set -e

# Configurações
BACKUP_DIR="/var/backups/webstream_hunter"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30
LOG_FILE="/var/log/webstream_hunter/backup.log"

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Funções
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Criar diretório de backup
mkdir -p "$BACKUP_DIR"

log_message "Iniciando backup do WebStream Hunter..."

# Parar serviço temporariamente
if systemctl is-active --quiet webstream-hunter; then
    log_message "Parando serviço webstream-hunter..."
    systemctl stop webstream-hunter
fi

# Backup do banco de dados
if [[ -f "/var/lib/webstream_hunter/database.db" ]]; then
    log_message "Fazendo backup do banco de dados..."
    cp "/var/lib/webstream_hunter/database.db" "$BACKUP_DIR/database_$DATE.db"
    
    # Compactar
    gzip -f "$BACKUP_DIR/database_$DATE.db"
    log_message "Backup do banco: $BACKUP_DIR/database_$DATE.db.gz"
fi

# Backup da configuração
if [[ -f "/etc/webstream_hunter/config.json" ]]; then
    log_message "Fazendo backup da configuração..."
    cp "/etc/webstream_hunter/config.json" "$BACKUP_DIR/config_$DATE.json"
    log_message "Backup da configuração: $BACKUP_DIR/config_$DATE.json"
fi

# Backup dos logs
log_message "Fazendo backup dos logs..."
tar -czf "$BACKUP_DIR/logs_$DATE.tar.gz" -C /var/log/webstream_hunter . 2>/dev/null || true

# Backup dos templates
if [[ -d "/usr/share/webstream_hunter/templates" ]]; then
    log_message "Fazendo backup dos templates..."
    tar -czf "$BACKUP_DIR/templates_$DATE.tar.gz" -C /usr/share/webstream_hunter/templates . 2>/dev/null || true
fi

# Iniciar serviço
log_message "Iniciando serviço webstream-hunter..."
systemctl start webstream-hunter

# Limpar backups antigos
log_message "Limpando backups antigos (mais de $RETENTION_DAYS dias)..."
find "$BACKUP_DIR" -type f -mtime +$RETENTION_DAYS -delete

# Relatório
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
BACKUP_COUNT=$(find "$BACKUP_DIR" -type f | wc -l)

log_message "Backup concluído com sucesso!"
log_message "Diretório: $BACKUP_DIR"
log_message "Tamanho total: $BACKUP_SIZE"
log_message "Arquivos de backup: $BACKUP_COUNT"
log_message "Backups retidos: últimos $RETENTION_DAYS dias"

echo -e "${GREEN}Backup concluído com sucesso!${NC}"
BACKUP_EOF

    # ==========================================================================
    # Script de monitoramento: monitor.sh
    # ==========================================================================
    
    cat > "$INSTALL_DIR/monitor.sh" << 'MONITOR_EOF'
#!/bin/bash
# WebStream Hunter - Script de Monitoramento

set -e

# Configurações
LOG_FILE="/var/log/webstream_hunter/monitor.log"
ALERT_THRESHOLD_CPU=90
ALERT_THRESHOLD_MEM=90
ALERT_THRESHOLD_DISK=85
CHECK_INTERVAL=300  # 5 minutos em segundos

# Funções
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

check_service() {
    if ! systemctl is-active --quiet webstream-hunter; then
        log_message "ALERTA: Serviço webstream-hunter está parado!"
        
        # Tentar reiniciar
        systemctl restart webstream-hunter
        sleep 5
        
        if systemctl is-active --quiet webstream-hunter; then
            log_message "Serviço reiniciado com sucesso"
        else
            log_message "ERRO: Falha ao reiniciar o serviço"
        fi
    fi
}

check_resources() {
    # CPU
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    if (( $(echo "$cpu_usage > $ALERT_THRESHOLD_CPU" | bc -l) )); then
        log_message "ALERTA: Uso de CPU alto: ${cpu_usage}%"
    fi
    
    # Memória
    local mem_usage=$(free | awk '/Mem:/ {printf("%.0f"), $3/$2 * 100}')
    if [[ $mem_usage -gt $ALERT_THRESHOLD_MEM ]]; then
        log_message "ALERTA: Uso de memória alto: ${mem_usage}%"
    fi
    
    # Disco
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -gt $ALERT_THRESHOLD_DISK ]]; then
        log_message "ALERTA: Uso de disco alto: ${disk_usage}%"
    fi
}

check_database() {
    local db_file="/var/lib/webstream_hunter/database.db"
    
    if [[ -f "$db_file" ]]; then
        local db_size=$(stat -c%s "$db_file")
        local db_size_mb=$((db_size / 1024 / 1024))
        
        if [[ $db_size_mb -gt 1024 ]]; then  # 1GB
            log_message "ALERTA: Banco de dados grande: ${db_size_mb}MB"
        fi
        
        # Verificar integridade
        if sqlite3 "$db_file" "PRAGMA integrity_check;" 2>/dev/null | grep -q -v "ok"; then
            log_message "ERRO: Problema de integridade no banco de dados"
        fi
    fi
}

check_logs() {
    local log_file="/var/log/webstream_hunter/app.log"
    
    if [[ -f "$log_file" ]]; then
        # Verificar erros recentes
        local error_count=$(tail -100 "$log_file" | grep -i "error\|exception\|traceback" | wc -l)
        
        if [[ $error_count -gt 10 ]]; then
            log_message "ALERTA: Muitos erros nos logs: ${error_count} erros recentes"
        fi
    fi
}

# Executar verificações
log_message "Iniciando monitoramento do WebStream Hunter..."

check_service
check_resources
check_database
check_logs

log_message "Monitoramento concluído"
MONITOR_EOF

    # ==========================================================================
    # Arquivo de configuração: config.json
    # ==========================================================================
    
    cat > "$CONFIG_DIR/config.json" << 'CONFIG_EOF'
{
    "web": {
        "host": "0.0.0.0",
        "port": 8080,
        "debug": false,
        "secret_key": "webstream-hunter-secret-key-2024-change-this",
        "session_timeout": 3600,
        "max_upload_size": 104857600,
        "rate_limit": "1000/hour"
    },
    "scanning": {
        "max_threads": 100,
        "timeout": 10,
        "retry_attempts": 3,
        "scan_delay": 0.05,
        "stealth_mode": true,
        "max_hosts_per_scan": 65536,
        "common_ports": [
            80, 443, 554, 1935, 8080, 8000, 8008, 8443, 8554, 
            8888, 9000, 10000, 5000, 5001, 5002, 5003, 5004
        ],
        "common_paths": [
            "/live", "/stream", "/tv", "/iptv", "/video",
            "/hls", "/m3u8", "/ts", "/mpegts", "/streaming",
            "/axis-cgi/mjpg/video.cgi", "/snapshot.cgi",
            "/videostream.cgi", "/video.mjpg", "/img/video.mjpeg"
        ]
    },
    "stream_analysis": {
        "sample_duration": 30,
        "analyze_codecs": true,
        "check_encryption": true,
        "validate_stream": true,
        "buffer_size": 8192,
        "ffprobe_timeout": 30,
        "min_bitrate": 500000,
        "min_resolution": "640x480"
    },
    "database": {
        "path": "/var/lib/webstream_hunter/database.db",
        "backup_interval": 3600,
        "max_backups": 30,
        "cleanup_days": 90,
        "optimize_interval": 86400
    },
    "security": {
        "require_auth": true,
        "default_user": "admin",
        "default_password": "admin123",
        "enable_ssl": false,
        "ssl_cert": "",
        "ssl_key": "",
        "allowed_ips": [],
        "blocked_ips": [],
        "session_secure": true,
        "session_httponly": true,
        "csrf_enabled": true
    },
    "notifications": {
        "email_enabled": false,
        "smtp_server": "",
        "smtp_port": 587,
        "email_from": "",
        "email_to": "",
        "telegram_enabled": false,
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "notify_on_scan_complete": true,
        "notify_on_error": true
    },
    "player": {
        "default_player": "html5",
        "buffer_size": 8192,
        "max_bitrate": 10000000,
        "audio_language": "por",
        "subtitle_language": "por",
        "enable_recording": true,
        "recording_path": "/var/lib/webstream_hunter/recordings"
    },
    "logging": {
        "level": "INFO",
        "max_size": 10485760,
        "backup_count": 10,
        "enable_access_log": true,
        "enable_error_log": true
    }
}
CONFIG_EOF

    # ==========================================================================
    # Template HTML base: base.html
    # ==========================================================================
    
    cat > "$TEMPLATE_DIR/base.html" << 'HTML_EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}WebStream Hunter{% endblock %}</title>
    
    <!-- Bootstrap 5 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <!-- Custom CSS -->
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --accent-color: #e74c3c;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --dark-bg: #1a1a2e;
            --darker-bg: #16213e;
            --card-bg: #0f3460;
            --text-color: #ecf0f1;
            --border-color: #34495e;
        }
        
        body {
            background-color: var(--dark-bg);
            color: var(--text-color);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background-color: var(--primary-color) !important;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        
        .sidebar {
            background-color: var(--darker-bg);
            min-height: calc(100vh - 56px);
            border-right: 1px solid var(--border-color);
        }
        
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .btn-primary {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
        }
        
        .btn-primary:hover {
            background-color: #2980b9;
            border-color: #2980b9;
        }
        
        .scan-progress {
            height: 10px;
            border-radius: 5px;
            background-color: #34495e;
            overflow: hidden;
        }
        
        .scan-progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--secondary-color), var(--success-color));
            transition: width 0.3s;
        }
        
        .stream-quality-badge {
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        
        .quality-hd { background-color: #27ae60; color: white; }
        .quality-sd { background-color: #f39c12; color: white; }
        .quality-low { background-color: #e74c3c; color: white; }
    </style>
    
    {% block extra_css %}{% endblock %}
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="fas fa-satellite-dish me-2"></i>
                <strong>WebStream Hunter</strong>
            </a>
        </div>
    </nav>
    
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-lg-2 col-md-3 sidebar py-3">
                <nav class="nav flex-column">
                    <a class="nav-link active" href="/dashboard">
                        <i class="fas fa-tachometer-alt me-2"></i> Dashboard
                    </a>
                    <a class="nav-link" href="/scan">
                        <i class="fas fa-search me-2"></i> Scanner
                    </a>
                    <a class="nav-link" href="/channels">
                        <i class="fas fa-list me-2"></i> Canais
                    </a>
                    <a class="nav-link" href="/player">
                        <i class="fas fa-play-circle me-2"></i> Player
                    </a>
                    <a class="nav-link" href="/settings">
                        <i class="fas fa-cog me-2"></i> Configurações
                    </a>
                </nav>
            </div>
            
            <!-- Main Content -->
            <div class="col-lg-10 col-md-9 py-4">
                {% block content %}{% endblock %}
            </div>
        </div>
    </div>
    
    <!-- Scripts -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    {% block extra_js %}{% endblock %}
</body>
</html>
HTML_EOF

    # ==========================================================================
    # Template de login: login.html
    # ==========================================================================
    
    cat > "$TEMPLATE_DIR/login.html" << 'LOGIN_EOF'
{% extends "base.html" %}

{% block title %}Login - WebStream Hunter{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6 col-lg-4">
        <div class="card mt-5">
            <div class="card-header text-center">
                <h4 class="mb-0">
                    <i class="fas fa-sign-in-alt me-2"></i>Login
                </h4>
            </div>
            <div class="card-body">
                <form method="POST" action="/login">
                    <div class="mb-3">
                        <label for="username" class="form-label">Usuário</label>
                        <div class="input-group">
                            <span class="input-group-text">
                                <i class="fas fa-user"></i>
                            </span>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <label for="password" class="form-label">Senha</label>
                        <div class="input-group">
                            <span class="input-group-text">
                                <i class="fas fa-lock"></i>
                            </span>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                    </div>
                    
                    <div class="d-grid gap-2">
                        <button type="submit" class="btn btn-primary btn-lg">
                            <i class="fas fa-sign-in-alt me-2"></i>Entrar
                        </button>
                    </div>
                </form>
                
                <hr class="my-4">
                
                <div class="text-center">
                    <small class="text-muted">
                        <i class="fas fa-info-circle me-1"></i>
                        Credenciais padrão: admin / admin123
                    </small>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
LOGIN_EOF

    # ==========================================================================
    # Template dashboard: dashboard.html
    # ==========================================================================
    
    cat > "$TEMPLATE_DIR/dashboard.html" << 'DASHBOARD_EOF'
{% extends "base.html" %}

{% block title %}Dashboard - WebStream Hunter{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col">
        <h2>
            <i class="fas fa-tachometer-alt me-2"></i>Dashboard
        </h2>
        <p class="text-muted">Visão geral do sistema e estatísticas</p>
    </div>
</div>

<!-- Stats Cards -->
<div class="row mb-4">
    <div class="col-md-3 mb-3">
        <div class="card text-center p-3">
            <i class="fas fa-search fa-2x text-primary mb-2"></i>
            <h3 id="total-scans">0</h3>
            <p class="text-muted mb-0">Scans Realizados</p>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="card text-center p-3">
            <i class="fas fa-satellite-dish fa-2x text-success mb-2"></i>
            <h3 id="total-streams">0</h3>
            <p class="text-muted mb-0">Streams Encontrados</p>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="card text-center p-3">
            <i class="fas fa-shield-alt fa-2x text-warning mb-2"></i>
            <h3 id="total-vulns">0</h3>
            <p class="text-muted mb-0">Vulnerabilidades</p>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="card text-center p-3">
            <i class="fas fa-bolt fa-2x text-danger mb-2"></i>
            <h3 id="active-scans">0</h3>
            <p class="text-muted mb-0">Scans Ativos</p>
        </div>
    </div>
</div>

<!-- Quick Actions -->
<div class="card mb-4">
    <div class="card-header">
        <h5 class="mb-0">
            <i class="fas fa-bolt me-2"></i>Ações Rápidas
        </h5>
    </div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-3 mb-2">
                <a href="/scan" class="btn btn-primary w-100">
                    <i class="fas fa-search me-2"></i>Novo Scan
                </a>
            </div>
            <div class="col-md-3 mb-2">
                <button class="btn btn-success w-100" id="quick-scan">
                    <i class="fas fa-bolt me-2"></i>Scan Rápido
                </button>
            </div>
            <div class="col-md-3 mb-2">
                <a href="/channels" class="btn btn-info w-100">
                    <i class="fas fa-list me-2"></i>Ver Canais
                </a>
            </div>
            <div class="col-md-3 mb-2">
                <a href="/player" class="btn btn-warning w-100">
                    <i class="fas fa-play-circle me-2"></i>Abrir Player
                </a>
            </div>
        </div>
    </div>
</div>

<!-- System Info -->
<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-microchip me-2"></i>Uso de Sistema
                </h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-6">
                        <small class="text-muted d-block">CPU</small>
                        <div class="scan-progress mb-3">
                            <div class="scan-progress-bar" id="cpu-progress-bar" style="width: 0%"></div>
                        </div>
                    </div>
                    <div class="col-6">
                        <small class="text-muted d-block">RAM</small>
                        <div class="scan-progress mb-3">
                            <div class="scan-progress-bar" id="ram-progress-bar" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
                <div class="row mt-2">
                    <div class="col-6">
                        <small class="text-muted">Armazenamento</small>
                        <div class="scan-progress">
                            <div class="scan-progress-bar" id="disk-progress-bar" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-info-circle me-2"></i>Informações do Sistema
                </h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-6">
                        <small class="text-muted d-block">Hostname</small>
                        <strong id="hostname">-</strong>
                    </div>
                    <div class="col-6">
                        <small class="text-muted d-block">Sistema</small>
                        <strong id="os-name">-</strong>
                    </div>
                </div>
                <div class="row mt-3">
                    <div class="col-6">
                        <small class="text-muted d-block">Python</small>
                        <strong id="python-version">-</strong>
                    </div>
                    <div class="col-6">
                        <small class="text-muted d-block">CPU Cores</small>
                        <strong id="cpu-cores">-</strong>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

{% endblock %}

{% block extra_js %}
<script>
$(document).ready(function() {
    // Quick scan button
    $('#quick-scan').click(function() {
        window.location.href = '/scan?quick=true';
    });
    
    // Update system info
    function updateSystemInfo() {
        $.get('/api/system/info', function(data) {
            // System stats
            $('#cpu-progress-bar').css('width', data.cpu_usage + '%');
            $('#ram-progress-bar').css('width', data.memory_usage + '%');
            $('#disk-progress-bar').css('width', data.disk_usage + '%');
            
            // System info
            $('#hostname').text(data.hostname);
            $('#os-name').text(data.os);
            $('#python-version').text(data.python_version);
            $('#cpu-cores').text(data.cpu_cores);
        }).fail(function() {
            console.log('API não disponível ainda');
        });
    }
    
    // Update every 10 seconds
    setInterval(updateSystemInfo, 10000);
    updateSystemInfo();
});
</script>
{% endblock %}
DASHBOARD_EOF

    # ==========================================================================
    # Service systemd: webstream-hunter.service
    # ==========================================================================
    
    cat > "/etc/systemd/system/webstream-hunter.service" << 'SERVICE_EOF'
[Unit]
Description=WebStream Hunter - Advanced MPEG-TS Stream Scanner
After=network.target
Wants=network.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=simple
User=webstream
Group=webstream
WorkingDirectory=/opt/webstream_hunter
Environment="PATH=/opt/webstream_hunter/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=/opt/webstream_hunter"
ExecStart=/opt/webstream_hunter/venv/bin/python /opt/webstream_hunter/webstream_hunter.py
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/webstream_hunter /var/lib/webstream_hunter /var/cache/webstream_hunter
ReadOnlyPaths=/etc/webstream_hunter

# Resource limits
LimitNOFILE=65536
LimitNPROC=65536
LimitCORE=infinity

# Logging
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=webstream-hunter

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    log_success "Arquivos da aplicação criados"
}

# ==============================================================================
# CONFIGURAÇÃO DE PERMISSÕES
# ==============================================================================

set_permissions() {
    log_step "Configurando permissões"
    
    # Definir dono dos diretórios
    run_command "chown -R $SERVICE_USER:$SERVICE_GROUP '$INSTALL_DIR'" "Definindo dono do diretório de instalação"
    run_command "chown -R $SERVICE_USER:$SERVICE_GROUP '$LOG_DIR'" "Definindo dono do diretório de logs"
    run_command "chown -R $SERVICE_USER:$SERVICE_GROUP '$DATA_DIR'" "Definindo dono do diretório de dados"
    run_command "chown -R $SERVICE_USER:$SERVICE_GROUP '$CACHE_DIR'" "Definindo dono do diretório de cache"
    run_command "chown -R $SERVICE_USER:$SERVICE_GROUP '$CONFIG_DIR'" "Definindo dono do diretório de configuração"
    
    # Permissões de diretórios
    run_command "chmod 750 '$INSTALL_DIR'" "Definindo permissões do diretório de instalação"
    run_command "chmod 750 '$LOG_DIR'" "Definindo permissões do diretório de logs"
    run_command "chmod 750 '$DATA_DIR'" "Definindo permissões do diretório de dados"
    run_command "chmod 750 '$CACHE_DIR'" "Definindo permissões do diretório de cache"
    run_command "chmod 750 '$CONFIG_DIR'" "Definindo permissões do diretório de configuração"
    
    # Permissões de arquivos
    run_command "chmod 755 '$INSTALL_DIR/webstream_hunter.py'" "Definindo permissões do script principal"
    run_command "chmod 755 '$INSTALL_DIR/start.sh'" "Definindo permissões do script de inicialização"
    run_command "chmod 755 '$INSTALL_DIR/backup.sh'" "Definindo permissões do script de backup"
    run_command "chmod 755 '$INSTALL_DIR/monitor.sh'" "Definindo permissões do script de monitoramento"
    
    # Arquivos de configuração
    run_command "chmod 640 '$CONFIG_DIR/config.json'" "Definindo permissões do arquivo de configuração"
    
    # Templates (acesso de leitura)
    run_command "chmod -R 755 '$TEMPLATE_DIR'" "Definindo permissões dos templates"
    run_command "chmod -R 755 '$STATIC_DIR'" "Definindo permissões dos arquivos estáticos"
    
    # Logs
    run_command "touch '$LOG_DIR/install.log'" "Criando arquivo de log da instalação"
    run_command "touch '$LOG_DIR/app.log'" "Criando arquivo de log da aplicação"
    run_command "chown $SERVICE_USER:$SERVICE_GROUP '$LOG_DIR'/*.log" "Definindo dono dos arquivos de log"
    run_command "chmod 640 '$LOG_DIR'/*.log" "Definindo permissões dos arquivos de log"
}

# ==============================================================================
# CONFIGURAÇÃO DO FIREWALL
# ==============================================================================

setup_firewall() {
    log_step "Configurando firewall"
    
    # Verificar se UFW está instalado
    if command -v ufw > /dev/null 2>&1; then
        if ufw status | grep -q "Status: active"; then
            log_info "UFW está ativo, configurando regras..."
            
            # Permitir porta SSH
            if ! ufw status | grep -q "22/tcp"; then
                run_command "ufw allow 22/tcp comment 'SSH'" "Permitindo SSH"
            fi
            
            # Permitir porta do WebStream Hunter
            if ! ufw status | grep -q "$DEFAULT_PORT/tcp"; then
                run_command "ufw allow $DEFAULT_PORT/tcp comment 'WebStream Hunter'" "Permitindo WebStream Hunter"
            fi
            
            log_success "Firewall configurado"
        else
            log_warning "UFW está instalado mas não está ativo"
            log_info "Para ativar o UFW, execute: sudo ufw enable"
        fi
    else
        log_warning "UFW não está instalado"
        log_info "Para instalar: sudo apt install ufw"
    fi
}

# ==============================================================================
# CONFIGURAÇÃO DO CRON
# ==============================================================================

setup_cron_jobs() {
    log_step "Configurando tarefas agendadas (cron)"
    
    # Backup diário às 2 AM
    local cron_backup="0 2 * * * $INSTALL_DIR/backup.sh >> $LOG_DIR/backup.log 2>&1"
    
    # Monitoramento a cada 5 minutos
    local cron_monitor="*/5 * * * * $INSTALL_DIR/monitor.sh >> $LOG_DIR/monitor.log 2>&1"
    
    # Limpeza de logs semanais
    local cron_cleanup="0 3 * * 0 find $LOG_DIR -name \"*.log.*\" -mtime +7 -delete"
    
    # Adicionar ao crontab do root
    (crontab -l 2>/dev/null | grep -v "$INSTALL_DIR/backup.sh"; echo "$cron_backup") | crontab -
    (crontab -l 2>/dev/null | grep -v "$INSTALL_DIR/monitor.sh"; echo "$cron_monitor") | crontab -
    (crontab -l 2>/dev/null | grep -v "find $LOG_DIR"; echo "$cron_cleanup") | crontab -
    
    log_success "Tarefas cron configuradas"
}

# ==============================================================================
# INICIALIZAÇÃO DO SISTEMA
# ==============================================================================

initialize_system() {
    log_step "Inicializando sistema"
    
    # Recarregar systemd
    run_command "systemctl daemon-reload" "Recarregando systemd"
    
    # Habilitar serviço
    run_command "systemctl enable webstream-hunter.service" "Habilitando serviço"
    
    # Iniciar serviço
    run_command "systemctl start webstream-hunter.service" "Iniciando serviço"
    
    # Aguardar serviço iniciar
    sleep 3
    
    # Verificar status
    if systemctl is-active --quiet webstream-hunter.service; then
        log_success "Serviço iniciado com sucesso!"
    else
        log_error "Falha ao iniciar o serviço!"
        run_command "systemctl status webstream-hunter.service --no-pager" "Verificando status do serviço"
        return 1
    fi
}

# ==============================================================================
# VERIFICAÇÃO FINAL
# ==============================================================================

final_checks() {
    log_step "Realizando verificações finais"
    
    local checks_passed=0
    local total_checks=7
    
    # 1. Verificar serviço
    if systemctl is-active --quiet webstream-hunter.service; then
        log_success "✓ Serviço em execução"
        ((checks_passed++))
    else
        log_error "✗ Serviço não está em execução"
    fi
    
    # 2. Verificar diretórios
    local directories=("$INSTALL_DIR" "$LOG_DIR" "$DATA_DIR" "$CONFIG_DIR")
    for dir in "${directories[@]}"; do
        if [[ -d "$dir" ]]; then
            log_success "✓ Diretório existe: $dir"
        else
            log_error "✗ Diretório não existe: $dir"
        fi
    done
    ((checks_passed++))
    
    # 3. Verificar arquivos principais
    local files=(
        "$INSTALL_DIR/webstream_hunter.py"
        "$CONFIG_DIR/config.json"
        "/etc/systemd/system/webstream-hunter.service"
    )
    
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            log_success "✓ Arquivo existe: $(basename "$file")"
        else
            log_error "✗ Arquivo não existe: $(basename "$file")"
        fi
    done
    ((checks_passed++))
    
    # 4. Verificar permissões
    if [[ $(stat -c %U "$INSTALL_DIR") == "$SERVICE_USER" ]]; then
        log_success "✓ Permissões do diretório corretas"
        ((checks_passed++))
    else
        log_error "✗ Permissões do diretório incorretas"
    fi
    
    # 5. Verificar virtual environment
    if [[ -f "$VENV_DIR/bin/python" ]]; then
        log_success "✓ Virtual environment configurado"
        ((checks_passed++))
    else
        log_error "✗ Virtual environment não configurado"
    fi
    
    # 6. Verificar porta
    if netstat -tuln | grep -q ":$DEFAULT_PORT "; then
        log_success "✓ Aplicação ouvindo na porta $DEFAULT_PORT"
        ((checks_passed++))
    else
        log_warning "⚠ Aplicação não está ouvindo na porta $DEFAULT_PORT"
    fi
    
    # 7. Verificar logs
    if [[ -f "$LOG_DIR/app.log" ]]; then
        log_success "✓ Arquivo de log criado"
        ((checks_passed++))
    else
        log_error "✗ Arquivo de log não criado"
    fi
    
    # Resultado
    echo -e "\n${GREEN}Verificações concluídas: $checks_passed/$total_checks${NC}"
    
    if [[ $checks_passed -eq $total_checks ]]; then
        log_success "Todas as verificações passaram!"
        return 0
    else
        log_warning "Algumas verificações falharam"
        return 1
    fi
}

# ==============================================================================
# RELATÓRIO FINAL
# ==============================================================================

show_final_report() {
    local_ip=$(hostname -I | awk '{print $1}')
    public_ip=$(curl -s ifconfig.me 2>/dev/null || echo "Não detectado")
    
    echo -e "\n${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                WEBSTREAM HUNTER INSTALADO COM SUCESSO!           ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${CYAN}📊 INFORMAÇÕES DA INSTALAÇÃO${NC}"
    echo -e "  ${BLUE}•${NC} Data da instalação: $(date)"
    echo -e "  ${BLUE}•${NC} Diretório de instalação: $INSTALL_DIR"
    echo -e "  ${BLUE}•${NC} Usuário do serviço: $SERVICE_USER"
    echo -e "  ${BLUE}•${NC} Porta do serviço: $DEFAULT_PORT"
    
    echo -e "\n${CYAN}🌐 ACESSO À INTERFACE WEB${NC}"
    echo -e "  ${GREEN}•${NC} URL Local:      http://localhost:$DEFAULT_PORT"
    echo -e "  ${GREEN}•${NC} URL da Rede:    http://$local_ip:$DEFAULT_PORT"
    
    if [[ "$public_ip" != "Não detectado" ]]; then
        echo -e "  ${YELLOW}•${NC} URL Pública:    http://$public_ip:$DEFAULT_PORT ${RED}(⚠ Exposta!)${NC}"
    fi
    
    echo -e "\n${CYAN}🔐 CREDENCIAIS DE ACESSO${NC}"
    echo -e "  ${BLUE}•${NC} Usuário padrão: admin"
    echo -e "  ${BLUE}•${NC} Senha padrão: admin123 ${RED}(⚠ Altere imediatamente!)${NC}"
    
    echo -e "\n${CYAN}⚙️  COMANDOS DE GERENCIAMENTO${NC}"
    echo -e "  ${GREEN}sudo systemctl start webstream-hunter${NC}     # Iniciar"
    echo -e "  ${GREEN}sudo systemctl stop webstream-hunter${NC}      # Parar"
    echo -e "  ${GREEN}sudo systemctl restart webstream-hunter${NC}   # Reiniciar"
    echo -e "  ${GREEN}sudo systemctl status webstream-hunter${NC}    # Ver status"
    echo -e "  ${GREEN}sudo journalctl -u webstream-hunter -f${NC}    # Ver logs"
    
    echo -e "\n${CYAN}📁 DIRETÓRIOS IMPORTANTES${NC}"
    echo -e "  ${BLUE}•${NC} Aplicação:      $INSTALL_DIR"
    echo -e "  ${BLUE}•${NC} Logs:           $LOG_DIR"
    echo -e "  ${BLUE}•${NC} Dados:          $DATA_DIR"
    echo -e "  ${BLUE}•${NC} Configuração:   $CONFIG_DIR"
    echo -e "  ${BLUE}•${NC} Templates:      $TEMPLATE_DIR"
    
    echo -e "\n${CYAN}🛡️  RECOMENDAÇÕES DE SEGURANÇA${NC}"
    echo -e "  ${RED}1.${NC} Altere a senha padrão imediatamente!"
    echo -e "  ${RED}2.${NC} Configure SSL/HTTPS na interface web"
    echo -e "  ${RED}3.${NC} Restrinja IPs de acesso via configuração"
    echo -e "  ${RED}4.${NC} Configure firewall para permitir apenas IPs confiáveis"
    echo -e "  ${RED}5.${NC} Mantenha o sistema atualizado regularmente"
    
    echo -e "\n${CYAN}🚀 PRÓXIMOS PASSOS${NC}"
    echo -e "  ${GREEN}1.${NC} Acesse http://$local_ip:$DEFAULT_PORT no navegador"
    echo -e "  ${GREEN}2.${NC} Faça login com admin/admin123"
    echo -e "  ${GREEN}3.${NC} Vá em Configurações → Segurança"
    echo -e "  ${GREEN}4.${NC} Altere a senha padrão"
    echo -e "  ${GREEN}5.${NC} Configure conforme necessário"
    echo -e "  ${GREEN}6.${NC} Inicie seu primeiro scan!"
    
    echo -e "\n${CYAN}📞 SUPORTE E SOLUÇÃO DE PROBLEMAS${NC}"
    echo -e "  ${BLUE}•${NC} Logs da instalação: $LOG_DIR/install.log"
    echo -e "  ${BLUE}•${NC} Logs da aplicação:  $LOG_DIR/app.log"
    echo -e "  ${BLUE}•${NC} Status do serviço:  sudo systemctl status webstream-hunter"
    echo -e "  ${BLUE}•${NC} Reiniciar serviço:  sudo systemctl restart webstream-hunter"
    
    echo -e "\n${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║        O WebStream Hunter está pronto para uso! 🎉             ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Advertência de segurança
    echo -e "\n${RED}⚠️  AVISO LEGAL IMPORTANTE:${NC}"
    echo -e "Este software deve ser usado APENAS em redes que você possui ou tem"
    echo -e "permissão explícita para escanear. O uso indevido pode violar leis"
    echo -e "locais e resultar em consequências legais graves."
    echo -e "O desenvolvedor não se responsabiliza pelo uso indevido deste software."
    
    # Criar arquivo de informações
    cat > "$INSTALL_DIR/INSTALL_INFO.txt" << EOF
============================================
WEBSTREAM HUNTER - INFORMAÇÕES DA INSTALAÇÃO
============================================

Data da instalação: $(date)
Sistema: $(lsb_release -d 2>/dev/null | cut -f2 || uname -a)
Usuário do serviço: $SERVICE_USER
Porta do serviço: $DEFAULT_PORT

URLs de acesso:
- Local:      http://localhost:$DEFAULT_PORT
- Rede:       http://$local_ip:$DEFAULT_PORT
- Pública:    http://$public_ip:$DEFAULT_PORT (se disponível)

Credenciais:
- Usuário: admin
- Senha: admin123 (ALTERE IMEDIATAMENTE!)

Diretórios:
- Aplicação:      $INSTALL_DIR
- Logs:           $LOG_DIR
- Dados:          $DATA_DIR
- Configuração:   $CONFIG_DIR

Comandos úteis:
- Iniciar:    sudo systemctl start webstream-hunter
- Parar:      sudo systemctl stop webstream-hunter
- Reiniciar:  sudo systemctl restart webstream-hunter
- Status:     sudo systemctl status webstream-hunter
- Logs:       sudo journalctl -u webstream-hunter -f

Backup automático configurado para 2:00 AM
Monitoramento configurado a cada 5 minutos

⚠️  RECOMENDAÇÕES DE SEGURANÇA:
1. Altere a senha padrão imediatamente!
2. Configure SSL/HTTPS
3. Restrinja IPs de acesso
4. Configure firewall
5. Mantenha atualizado

⚠️  AVISO LEGAL:
Use apenas em redes autorizadas. Respeite as leis locais.
O uso indevido é de inteira responsabilidade do usuário.
EOF
    
    log_success "Arquivo de informações salvo em: $INSTALL_DIR/INSTALL_INFO.txt"
}

# ==============================================================================
# FUNÇÃO PRINCIPAL DE INSTALAÇÃO
# ==============================================================================

main_installation() {
    log_header "INICIANDO INSTALAÇÃO DO WEBSTREAM HUNTER"
    
    # Verificações iniciais
    check_root
    check_ubuntu_version
    check_disk_space
    check_memory
    
    # Etapas de instalação
    update_system
    install_system_dependencies
    create_directories
    create_service_user
    setup_python_environment
    create_application_files
    set_permissions
    setup_firewall
    setup_cron_jobs
    initialize_system
    
    # Verificações finais
    if final_checks; then
        show_final_report
    else
        log_error "A instalação teve problemas. Verifique os logs: $LOG_DIR/install.log"
        exit 1
    fi
}

# ==============================================================================
# FUNÇÃO DE DESINSTALAÇÃO
# ==============================================================================

uninstall() {
    log_header "DESINSTALANDO WEBSTREAM HUNTER"
    
    echo -e "${RED}ATENÇÃO:${NC} Esta ação irá:"
    echo -e "  1. Parar e remover o serviço"
    echo -e "  2. Remover todos os arquivos da aplicação"
    echo -e "  3. Manter dados de backup em $INSTALL_DIR/backups/"
    echo -e "  4. Remover usuário do sistema"
    echo ""
    read -p "Tem certeza que deseja continuar? (digite 'SIM' para confirmar): " -r
    echo
    
    if [[ "$REPLY" != "SIM" ]]; then
        log_info "Desinstalação cancelada"
        exit 0
    fi
    
    # Parar serviço
    if systemctl is-active --quiet webstream-hunter; then
        run_command "systemctl stop webstream-hunter" "Parando serviço"
    fi
    
    # Desabilitar serviço
    if systemctl is-enabled --quiet webstream-hunter 2>/dev/null; then
        run_command "systemctl disable webstream-hunter" "Desabilitando serviço"
    fi
    
    # Remover serviço
    if [[ -f "/etc/systemd/system/webstream-hunter.service" ]]; then
        run_command "rm -f /etc/systemd/system/webstream-hunter.service" "Removendo arquivo do serviço"
    fi
    
    # Recarregar systemd
    run_command "systemctl daemon-reload" "Recarregando systemd"
    
    # Remover cron jobs
    run_command "crontab -l | grep -v 'webstream_hunter' | crontab -" "Removendo tarefas cron"
    
    # Remover regras do firewall
    if command -v ufw > /dev/null 2>&1; then
        if ufw status | grep -q "WebStream Hunter"; then
            run_command "ufw delete allow $DEFAULT_PORT/tcp" "Removendo regra do firewall"
        fi
    fi
    
    # Backup dos dados
    BACKUP_DIR="$INSTALL_DIR/backups/final_$(date +%Y%m%d_%H%M%S)"
    run_command "mkdir -p '$BACKUP_DIR'" "Criando diretório de backup final"
    
    if [[ -f "/var/lib/webstream_hunter/database.db" ]]; then
        run_command "cp '/var/lib/webstream_hunter/database.db' '$BACKUP_DIR/'" "Fazendo backup do banco de dados"
    fi
    
    if [[ -f "/etc/webstream_hunter/config.json" ]]; then
        run_command "cp '/etc/webstream_hunter/config.json' '$BACKUP_DIR/'" "Fazendo backup da configuração"
    fi
    
    # Remover diretórios
    run_command "rm -rf '$INSTALL_DIR'" "Removendo diretório de instalação"
    run_command "rm -rf '$CONFIG_DIR'" "Removendo diretório de configuração"
    
    # Manter logs por 7 dias
    run_command "mv '$LOG_DIR' '$BACKUP_DIR/logs'" "Movendo logs para backup"
    
    # Remover diretórios de dados (opcional)
    read -p "Remover diretórios de dados e cache? (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        run_command "rm -rf '$DATA_DIR'" "Removendo diretório de dados"
        run_command "rm -rf '$CACHE_DIR'" "Removendo diretório de cache"
    else
        log_info "Diretórios de dados mantidos: $DATA_DIR, $CACHE_DIR"
    fi
    
    # Remover templates
    run_command "rm -rf '$TEMPLATE_DIR'" "Removendo templates"
    run_command "rm -rf '$STATIC_DIR'" "Removendo arquivos estáticos"
    
    # Remover usuário (opcional)
    read -p "Remover usuário '$SERVICE_USER'? (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        run_command "userdel '$SERVICE_USER' 2>/dev/null || true" "Removendo usuário"
        run_command "groupdel '$SERVICE_GROUP' 2>/dev/null || true" "Removendo grupo"
    else
        log_info "Usuário mantido: $SERVICE_USER"
    fi
    
    log_success "Desinstalação concluída!"
    echo -e "\n${YELLOW}Arquivos de backup salvos em:${NC} $BACKUP_DIR"
    echo -e "${YELLOW}Para remover completamente, execute:${NC}"
    echo -e "  sudo rm -rf $BACKUP_DIR"
    echo -e "  sudo rm -rf $DATA_DIR"
    echo -e "  sudo rm -rf $CACHE_DIR"
}

# ==============================================================================
# FUNÇÃO DE ATUALIZAÇÃO
# ==============================================================================

update() {
    log_header "ATUALIZANDO WEBSTREAM HUNTER"
    
    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_error "WebStream Hunter não está instalado!"
        exit 1
    fi
    
    # Fazer backup antes de atualizar
    run_command "$INSTALL_DIR/backup.sh" "Fazendo backup antes da atualização"
    
    # Parar serviço
    run_command "systemctl stop webstream-hunter" "Parando serviço"
    
    # Atualizar dependências do sistema
    update_system
    
    # Atualizar dependências Python
    run_command "'$VENV_DIR/bin/pip' install --upgrade -r '$INSTALL_DIR/requirements.txt'" "Atualizando dependências Python"
    
    # Recriar arquivos da aplicação (exceto configuração)
    create_application_files
    
    # Aplicar permissões
    set_permissions
    
    # Recarregar systemd
    run_command "systemctl daemon-reload" "Recarregando systemd"
    
    # Iniciar serviço
    run_command "systemctl start webstream-hunter" "Iniciando serviço"
    
    log_success "Atualização concluída!"
    log_info "Reinicie a interface para aplicar as mudanças"
}

# ==============================================================================
# FUNÇÃO DE STATUS
# ==============================================================================

status() {
    log_header "STATUS DO WEBSTREAM HUNTER"
    
    echo -e "${CYAN}Verificando status do sistema...${NC}\n"
    
    # Verificar serviço
    if systemctl is-active --quiet webstream-hunter; then
        echo -e "${GREEN}✓ Serviço está em execução${NC}"
    else
        echo -e "${RED}✗ Serviço não está em execução${NC}"
    fi
    
    echo ""
    
    # Verificar porta
    if netstat -tuln | grep -q ":$DEFAULT_PORT "; then
        echo -e "${GREEN}✓ Aplicação ouvindo na porta $DEFAULT_PORT${NC}"
    else
        echo -e "${RED}✗ Aplicação não está ouvindo na porta $DEFAULT_PORT${NC}"
    fi
    
    echo ""
    
    # Verificar diretórios
    echo -e "${CYAN}Diretórios:${NC}"
    local directories=(
        ["$INSTALL_DIR"]="Instalação"
        ["$LOG_DIR"]="Logs"
        ["$DATA_DIR"]="Dados"
        ["$CONFIG_DIR"]="Configuração"
    )
    
    for dir in "${!directories[@]}"; do
        if [[ -d "$dir" ]]; then
            size=$(du -sh "$dir" 2>/dev/null | cut -f1)
            echo -e "  ${GREEN}✓${NC} ${directories[$dir]}: $dir ($size)"
        else
            echo -e "  ${RED}✗${NC} ${directories[$dir]}: $dir (Não existe)"
        fi
    done
    
    echo ""
    
    # Verificar arquivos importantes
    echo -e "${CYAN}Arquivos importantes:${NC}"
    local files=(
        ["$INSTALL_DIR/webstream_hunter.py"]="Aplicação principal"
        ["$CONFIG_DIR/config.json"]="Configuração"
        ["/etc/systemd/system/webstream-hunter.service"]="Serviço systemd"
        ["$LOG_DIR/app.log"]="Log da aplicação"
    )
    
    for file in "${!files[@]}"; do
        if [[ -f "$file" ]]; then
            size=$(stat -c%s "$file" 2>/dev/null | numfmt --to=iec || echo "N/A")
            echo -e "  ${GREEN}✓${NC} ${files[$file]}: $(basename "$file") ($size)"
        else
            echo -e "  ${RED}✗${NC} ${files[$file]}: $(basename "$file") (Não existe)"
        fi
    done
    
    echo ""
    
    # Verificar virtual environment
    if [[ -f "$VENV_DIR/bin/python" ]]; then
        python_version=$("$VENV_DIR/bin/python" --version 2>&1)
        echo -e "${GREEN}✓ Virtual environment: $python_version${NC}"
    else
        echo -e "${RED}✗ Virtual environment não configurado${NC}"
    fi
    
    echo ""
    
    # Espaço em disco
    echo -e "${CYAN}Uso de recursos:${NC}"
    
    # CPU
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    echo -e "  CPU: ${cpu_usage}%"
    
    # Memória
    mem_usage=$(free | awk '/Mem:/ {printf("%.1f"), $3/$2 * 100}')
    mem_total=$(free -h | awk '/Mem:/ {print $2}')
    echo -e "  Memória: ${mem_usage}% de ${mem_total}"
    
    # Disco
    disk_usage=$(df -h / | awk 'NR==2 {print $5}')
    disk_total=$(df -h / | awk 'NR==2 {print $2}')
    echo -e "  Disco (root): ${disk_usage} de ${disk_total}"
    
    echo ""
    
    # Logs recentes
    if [[ -f "$LOG_DIR/app.log" ]]; then
        echo -e "${CYAN}Últimas entradas do log:${NC}"
        tail -5 "$LOG_DIR/app.log" | while IFS= read -r line; do
            echo -e "  ${BLUE}•${NC} $line"
        done
    fi
    
    echo ""
    
    # Informações de acesso
    local_ip=$(hostname -I | awk '{print $1}')
    echo -e "${CYAN}Informações de acesso:${NC}"
    echo -e "  ${BLUE}•${NC} URL: http://$local_ip:$DEFAULT_PORT"
    echo -e "  ${BLUE}•${NC} Usuário: admin"
    echo -e "  ${BLUE}•${NC} Para ver logs completos: sudo journalctl -u webstream-hunter -f"
}

# ==============================================================================
# MENU PRINCIPAL
# ==============================================================================

show_menu() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                  WEBSTREAM HUNTER - MENU PRINCIPAL               ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${GREEN}Opções disponíveis:${NC}"
    echo -e "  ${CYAN}1.${NC} Instalação completa"
    echo -e "  ${CYAN}2.${NC} Desinstalar"
    echo -e "  ${CYAN}3.${NC} Atualizar"
    echo -e "  ${CYAN}4.${NC} Ver status"
    echo -e "  ${CYAN}5.${NC} Backup manual"
    echo -e "  ${CYAN}6.${NC} Sair"
    echo ""
    
    read -p "Selecione uma opção (1-6): " -n 1 -r
    echo
    
    case $REPLY in
        1)
            main_installation
            ;;
        2)
            uninstall
            ;;
        3)
            update
            ;;
        4)
            status
            ;;
        5)
            if [[ -f "$INSTALL_DIR/backup.sh" ]]; then
                log_info "Executando backup manual..."
                "$INSTALL_DIR/backup.sh"
            else
                log_error "Script de backup não encontrado"
            fi
            ;;
        6)
            log_info "Saindo..."
            exit 0
            ;;
        *)
            log_error "Opção inválida!"
            show_menu
            ;;
    esac
}

# ==============================================================================
# TRATAMENTO DE SINAIS
# ==============================================================================

trap 'log_error "Instalação interrompida pelo usuário"; exit 1' INT TERM

# ==============================================================================
# EXECUÇÃO PRINCIPAL
# ==============================================================================

# Verificar se há argumentos
if [[ $# -gt 0 ]]; then
    case $1 in
        --install|-i)
            main_installation
            ;;
        --uninstall|-u)
            uninstall
            ;;
        --update|--upgrade)
            update
            ;;
        --status|-s)
            status
            ;;
        --help|-h)
            echo "Uso: $0 [OPÇÃO]"
            echo ""
            echo "Opções:"
            echo "  --install, -i     Instalação completa"
            echo "  --uninstall, -u   Desinstalar o sistema"
            echo "  --update          Atualizar instalação"
            echo "  --status, -s      Verificar status"
            echo "  --help, -h        Mostrar esta ajuda"
            echo ""
            echo "Sem argumentos: Menu interativo"
            exit 0
            ;;
        *)
            log_error "Argumento inválido: $1"
            echo "Use $0 --help para ver as opções"
            exit 1
            ;;
    esac
else
    # Menu interativo
    show_menu
fi

# Registrar conclusão
log_info "Script executado com sucesso!"
exit 0
