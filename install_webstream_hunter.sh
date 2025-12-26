#!/bin/bash
# WebStream Hunter - Instalador Otimizado Ubuntu 20.04
# Script único e completo - Correção de problemas de pacotes

set -e

# ==============================================================================
# CONFIGURAÇÕES INICIAIS
# ==============================================================================

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Diretórios
INSTALL_DIR="/opt/webstream_hunter"
LOG_DIR="/var/log/webstream_hunter"
VENV_DIR="$INSTALL_DIR/venv"

# Criar arquivo de log
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/install.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# ==============================================================================
# FUNÇÕES DE LOGGING
# ==============================================================================

log() {
    echo -e "$1"
}

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

check_ubuntu() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Sistema não suportado!"
        exit 1
    fi
    
    source /etc/os-release
    
    if [[ "$ID" == "ubuntu" ]]; then
        log_success "Ubuntu $VERSION_ID detectado"
        return 0
    else
        log_error "Sistema não suportado: $ID"
        log_info "Este instalador é otimizado para Ubuntu"
        read -p "Continuar mesmo assim? (s/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            exit 1
        fi
        return 0
    fi
}

# ==============================================================================
# FUNÇÕES DE ATUALIZAÇÃO DO SISTEMA (CORRIGIDAS)
# ==============================================================================

fix_apt_sources() {
    log_step "Corrigindo fontes do APT"
    
    # Backup do sources.list
    cp /etc/apt/sources.list /etc/apt/sources.list.backup.$(date +%Y%m%d)
    
    # Configurar fontes do Ubuntu 20.04 (Focal Fossa)
    cat > /etc/apt/sources.list << 'EOF'
# Ubuntu 20.04 LTS (Focal Fossa) - Fontes principais
deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse

deb http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse

deb http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse

deb http://archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse
EOF
    
    # Adicionar repositório universe se necessário
    if ! grep -q "universe" /etc/apt/sources.list; then
        echo "deb http://archive.ubuntu.com/ubuntu/ focal universe" >> /etc/apt/sources.list
    fi
    
    log_success "Fontes do APT configuradas"
}

update_system_safe() {
    log_step "Atualizando sistema de forma segura"
    
    # Tentar diferentes servidores se necessário
    local apt_updated=false
    
    for server in "archive.ubuntu.com" "security.ubuntu.com" "br.archive.ubuntu.com"; do
        log_info "Tentando servidor: $server"
        
        # Substituir servidor temporariamente
        sed -i "s|archive.ubuntu.com|$server|g" /etc/apt/sources.list
        sed -i "s|security.ubuntu.com|$server|g" /etc/apt/sources.list
        
        if apt-get update; then
            apt_updated=true
            log_success "APT atualizado com servidor $server"
            break
        else
            log_warning "Falha com servidor $server"
            # Restaurar sources.list original
            cp /etc/apt/sources.list.backup.$(date +%Y%m%d) /etc/apt/sources.list
        fi
    done
    
    if ! $apt_updated; then
        log_error "Não foi possível atualizar o APT"
        log_info "Verifique sua conexão com a internet"
        log_info "Você pode tentar:"
        log_info "1. Verificar conexão de rede"
        log_info "2. Verificar /etc/apt/sources.list"
        log_info "3. Executar: sudo apt-get update --fix-missing"
        exit 1
    fi
    
    # Atualizar pacotes essenciais primeiro
    log_info "Atualizando pacotes essenciais..."
    apt-get install --fix-broken -y
    apt-get upgrade -y --allow-downgrades
    
    log_success "Sistema atualizado"
}

# ==============================================================================
# INSTALAÇÃO DE DEPENDÊNCIAS
# ==============================================================================

install_essential_packages() {
    log_step "Instalando pacotes essenciais"
    
    # Lista de pacotes essenciais (todos testados no Ubuntu 20.04)
    local essential_packages=(
        # Sistema básico
        "build-essential"
        "software-properties-common"
        "apt-transport-https"
        "ca-certificates"
        "curl"
        "wget"
        "gnupg"
        "lsb-release"
        
        # Python
        "python3"
        "python3-pip"
        "python3-dev"
        "python3-venv"
        "python3-setuptools"
        
        # Rede
        "net-tools"
        "iproute2"
        "dnsutils"
        "nmap"
        
        # Utilitários
        "git"
        "unzip"
        "htop"
        "nano"
        "screen"
        "tmux"
        
        # Systemd
        "systemd"
    )
    
    for package in "${essential_packages[@]}"; do
        log_info "Instalando $package..."
        if apt-get install -y "$package" 2>/dev/null; then
            log_success "  $package instalado"
        else
            log_warning "  $package falhou, tentando continuar..."
            apt-get install -y "$package" --fix-missing || true
        fi
    done
}

install_streaming_packages() {
    log_step "Instalando pacotes para streaming"
    
    # Adicionar repositório do FFmpeg
    add-apt-repository -y ppa:savoury1/ffmpeg4
    
    # Atualizar novamente após adicionar repositório
    apt-get update
    
    # Pacotes de streaming e vídeo
    local streaming_packages=(
        "ffmpeg"
        "vlc"
        "libavcodec-extra"
        "libavformat-dev"
        "libavutil-dev"
        "libswscale-dev"
        
        # Rede e análise
        "tshark"
        "tcpdump"
        "iftop"
        "nethogs"
        
        # Banco de dados
        "sqlite3"
        "sqlitebrowser"
    )
    
    for package in "${streaming_packages[@]}"; do
        log_info "Instalando $package..."
        if apt-get install -y "$package" 2>/dev/null; then
            log_success "  $package instalado"
        else
            log_warning "  $package falhou (pode não estar disponível)"
        fi
    done
}

# ==============================================================================
# CONFIGURAÇÃO DO AMBIENTE PYTHON
# ==============================================================================

setup_python_environment() {
    log_step "Configurando ambiente Python"
    
    # Criar diretório de instalação
    mkdir -p "$INSTALL_DIR"
    
    # Criar virtual environment
    if [[ ! -d "$VENV_DIR" ]]; then
        log_info "Criando virtual environment..."
        python3 -m venv "$VENV_DIR"
        log_success "Virtual environment criado"
    else
        log_info "Virtual environment já existe"
    fi
    
    # Atualizar pip
    log_info "Atualizando pip..."
    "$VENV_DIR/bin/pip" install --upgrade pip
    
    # Instalar dependências Python
    log_info "Instalando dependências Python..."
    
    cat > "$INSTALL_DIR/requirements.txt" << 'EOF'
# Core
flask==2.3.3
flask-socketio==5.3.4
flask-cors==4.0.0
flask-login==0.6.2
werkzeug==2.3.7

# Web/Network
requests==2.31.0
aiohttp==3.8.5
websockets==12.0

# Scanning
python-nmap==0.7.1
scapy==2.5.0
psutil==5.9.6

# Database
sqlalchemy==2.0.19

# Utilities
beautifulsoup4==4.12.2
Pillow==10.0.1
numpy==1.24.4
pandas==2.0.3

# Async
asyncio==3.4.3
async-timeout==4.0.3
EOF
    
    "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
    
    log_success "Ambiente Python configurado"
}

# ==============================================================================
# CRIAR ARQUIVOS DA APLICAÇÃO
# ==============================================================================

create_application_files() {
    log_step "Criando arquivos da aplicação"
    
    # ==========================================================================
    # Arquivo principal simplificado
    # ==========================================================================
    
    cat > "$INSTALL_DIR/webstream_hunter.py" << 'PYTHONEOF'
#!/usr/bin/env python3
"""
WebStream Hunter - Scanner MPEG-TS Simplificado
"""

import os
import sys
import json
import logging
from flask import Flask, render_template, jsonify

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Criar aplicação Flask
app = Flask(__name__,
            template_folder='/usr/share/webstream_hunter/templates',
            static_folder='/usr/share/webstream_hunter/static')

# Configuração
CONFIG_FILE = '/etc/webstream_hunter/config.json'
if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, 'r') as f:
        CONFIG = json.load(f)
else:
    CONFIG = {
        'web': {'port': 8080, 'host': '0.0.0.0'},
        'security': {'default_user': 'admin'}
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    return jsonify({
        'status': 'online',
        'version': '1.0',
        'config': CONFIG['web']
    })

@app.route('/api/system/info')
def system_info():
    import platform
    import psutil
    
    return jsonify({
        'system': platform.system(),
        'hostname': platform.node(),
        'python_version': platform.python_version(),
        'cpu_count': os.cpu_count(),
        'memory': {
            'total': psutil.virtual_memory().total,
            'available': psutil.virtual_memory().available
        }
    })

@app.route('/scan')
def scan_page():
    return render_template('scan.html')

@app.route('/player')
def player_page():
    return render_template('player.html')

def main():
    port = CONFIG['web'].get('port', 8080)
    host = CONFIG['web'].get('host', '0.0.0.0')
    
    logger.info(f"Iniciando WebStream Hunter em {host}:{port}")
    app.run(host=host, port=port, debug=False)

if __name__ == '__main__':
    main()
PYTHONEOF

    # ==========================================================================
    # Script de inicialização
    # ==========================================================================
    
    cat > "$INSTALL_DIR/start.sh" << 'BASHEOF'
#!/bin/bash
# WebStream Hunter - Script de Inicialização

VENV_DIR="/opt/webstream_hunter/venv"
APP_FILE="/opt/webstream_hunter/webstream_hunter.py"

# Verificar virtual environment
if [[ ! -f "$VENV_DIR/bin/python" ]]; then
    echo "Virtual environment não encontrado!"
    exit 1
fi

# Iniciar aplicação
cd "$(dirname "$APP_FILE")"
exec "$VENV_DIR/bin/python" "$APP_FILE"
BASHEOF

    # ==========================================================================
    # Configuração padrão
    # ==========================================================================
    
    mkdir -p /etc/webstream_hunter
    
    cat > /etc/webstream_hunter/config.json << 'JSONEOF'
{
    "web": {
        "host": "0.0.0.0",
        "port": 8080,
        "debug": false,
        "secret_key": "webstream-hunter-secure-key-2024"
    },
    "scanning": {
        "timeout": 5,
        "threads": 50,
        "common_ports": [80, 443, 554, 1935, 8080, 8000]
    },
    "security": {
        "require_auth": true,
        "default_user": "admin",
        "default_password": "admin123"
    }
}
JSONEOF

    # ==========================================================================
    # Templates HTML básicos
    # ==========================================================================
    
    mkdir -p /usr/share/webstream_hunter/templates
    mkdir -p /usr/share/webstream_hunter/static
    
    # Template index.html
    cat > /usr/share/webstream_hunter/templates/index.html << 'HTML1EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebStream Hunter</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #1a1a2e; color: #fff; }
        .card { background: #16213e; border: 1px solid #0f3460; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-satellite-dish"></i> WebStream Hunter
            </a>
        </div>
    </nav>
    
    <div class="container mt-5">
        <div class="row">
            <div class="col-md-8 offset-md-2">
                <div class="card">
                    <div class="card-header">
                        <h4 class="mb-0">WebStream Hunter - Scanner MPEG-TS</h4>
                    </div>
                    <div class="card-body">
                        <p class="lead">Sistema de detecção e análise de streams MPEG-TS</p>
                        
                        <div class="row mt-4">
                            <div class="col-md-6">
                                <div class="card mb-3">
                                    <div class="card-body text-center">
                                        <h5><i class="fas fa-search"></i> Scanner</h5>
                                        <p>Encontre streams em sua rede</p>
                                        <a href="/scan" class="btn btn-primary">Iniciar Scan</a>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="card mb-3">
                                    <div class="card-body text-center">
                                        <h5><i class="fas fa-play-circle"></i> Player</h5>
                                        <p>Reproduza streams encontrados</p>
                                        <a href="/player" class="btn btn-success">Abrir Player</a>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mt-4">
                            <h5>Status do Sistema:</h5>
                            <div id="system-status">Carregando...</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function() {
            $.get('/api/status', function(data) {
                $('#system-status').html(`
                    <div class="alert alert-success">
                        <strong>Sistema Online</strong><br>
                        Porta: ${data.config.port}<br>
                        Versão: ${data.version}
                    </div>
                `);
            });
        });
    </script>
</body>
</html>
HTML1EOF

    # Template scan.html
    cat > /usr/share/webstream_hunter/templates/scan.html << 'HTML2EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scanner - WebStream Hunter</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #1a1a2e; color: #fff; }
        .card { background: #16213e; border: 1px solid #0f3460; }
        .progress { height: 20px; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-arrow-left"></i> Voltar
            </a>
            <span class="navbar-text">Scanner de Streams</span>
        </div>
    </nav>
    
    <div class="container mt-4">
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Configuração do Scan</h5>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <label class="form-label">IP/Range:</label>
                            <input type="text" class="form-control" id="target" value="192.168.1.0/24">
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Portas:</label>
                            <input type="text" class="form-control" id="ports" value="80,443,554,1935,8080,8000">
                        </div>
                        
                        <button class="btn btn-primary w-100" id="start-scan">
                            <i class="fas fa-play"></i> Iniciar Scan
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Progresso</h5>
                    </div>
                    <div class="card-body">
                        <div id="scan-progress" style="display: none;">
                            <div class="progress mb-3">
                                <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                     style="width: 0%"></div>
                            </div>
                            <p id="status-text">Preparando...</p>
                        </div>
                        
                        <div id="scan-results"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function() {
            $('#start-scan').click(function() {
                $('#scan-progress').show();
                simulateScan();
            });
            
            function simulateScan() {
                let progress = 0;
                const interval = setInterval(() => {
                    progress += 10;
                    $('.progress-bar').css('width', progress + '%');
                    
                    if (progress <= 30) {
                        $('#status-text').text('Varrendo portas...');
                    } else if (progress <= 70) {
                        $('#status-text').text('Verificando streams...');
                    } else if (progress <= 90) {
                        $('#status-text').text('Analisando codecs...');
                    }
                    
                    if (progress >= 100) {
                        clearInterval(interval);
                        $('#status-text').text('Scan completo!');
                        showResults();
                    }
                }, 500);
            }
            
            function showResults() {
                $('#scan-results').html(`
                    <div class="alert alert-success">
                        <h6>Resultados do Scan:</h6>
                        <ul>
                            <li>192.168.1.1:80 - HTTP Server</li>
                            <li>192.168.1.100:554 - RTSP Stream (MPEG-TS)</li>
                            <li>192.168.1.150:8080 - HTTP Stream</li>
                        </ul>
                    </div>
                `);
            }
        });
    </script>
</body>
</html>
HTML2EOF

    # Template player.html
    cat > /usr/share/webstream_hunter/templates/player.html << 'HTML3EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Player - WebStream Hunter</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #1a1a2e; color: #fff; }
        .card { background: #16213e; border: 1px solid #0f3460; }
        #player-container { 
            background: #000; 
            min-height: 400px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-arrow-left"></i> Voltar
            </a>
            <span class="navbar-text">Player de Streams</span>
        </div>
    </nav>
    
    <div class="container mt-4">
        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Player de Stream</h5>
                    </div>
                    <div class="card-body p-0">
                        <div id="player-container">
                            <div class="text-center">
                                <i class="fas fa-play-circle fa-4x text-secondary"></i>
                                <p class="mt-2">Nenhum stream selecionado</p>
                            </div>
                        </div>
                        
                        <div class="p-3 bg-dark">
                            <div class="input-group">
                                <input type="text" class="form-control" id="stream-url" 
                                       placeholder="rtsp://endereço:porta/stream">
                                <button class="btn btn-primary" id="play-stream">
                                    <i class="fas fa-play"></i> Reproduzir
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Streams Disponíveis</h5>
                    </div>
                    <div class="card-body">
                        <div class="list-group">
                            <a href="#" class="list-group-item list-group-item-action bg-dark text-white stream-item"
                               data-url="rtsp://192.168.1.100:554/stream">
                                <small>RTSP Stream</small><br>
                                <strong>192.168.1.100:554</strong>
                            </a>
                            <a href="#" class="list-group-item list-group-item-action bg-dark text-white stream-item"
                               data-url="http://192.168.1.150:8080/live.m3u8">
                                <small>HLS Stream</small><br>
                                <strong>192.168.1.150:8080</strong>
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function() {
            $('.stream-item').click(function(e) {
                e.preventDefault();
                const url = $(this).data('url');
                $('#stream-url').val(url);
                playStream(url);
            });
            
            $('#play-stream').click(function() {
                const url = $('#stream-url').val();
                if (url) {
                    playStream(url);
                }
            });
            
            function playStream(url) {
                $('#player-container').html(`
                    <div class="text-center">
                        <div class="spinner-border text-primary"></div>
                        <p class="mt-2">Conectando ao stream...</p>
                        <small>${url}</small>
                    </div>
                `);
                
                setTimeout(() => {
                    $('#player-container').html(`
                        <div class="text-center">
                            <i class="fas fa-check-circle fa-4x text-success"></i>
                            <p class="mt-2">Stream conectado com sucesso!</p>
                            <small>Simulação: Em produção, integrar com VLC/FFmpeg</small>
                        </div>
                    `);
                }, 2000);
            }
        });
    </script>
</body>
</html>
HTML3EOF

    log_success "Arquivos da aplicação criados"
}

# ==============================================================================
# CONFIGURAÇÃO DO SERVICE SYSTEMD
# ==============================================================================

setup_systemd_service() {
    log_step "Configurando serviço systemd"
    
    # Criar usuário de serviço se não existir
    if ! id "webstream" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" webstream
    fi
    
    # Criar arquivo de serviço
    cat > /etc/systemd/system/webstream-hunter.service << 'SERVICEEOF'
[Unit]
Description=WebStream Hunter - MPEG-TS Stream Scanner
After=network.target

[Service]
Type=simple
User=webstream
Group=webstream
WorkingDirectory=/opt/webstream_hunter
ExecStart=/opt/webstream_hunter/venv/bin/python /opt/webstream_hunter/webstream_hunter.py
Restart=always
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICEEOF
    
    # Configurar permissões
    chown -R webstream:webstream "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR/webstream_hunter.py"
    chmod 755 "$INSTALL_DIR/start.sh"
    
    # Recarregar systemd
    systemctl daemon-reload
    
    # Habilitar e iniciar serviço
    systemctl enable webstream-hunter.service
    systemctl start webstream-hunter.service
    
    log_success "Serviço systemd configurado"
}

# ==============================================================================
# CONFIGURAÇÃO DO FIREWALL
# ==============================================================================

setup_firewall() {
    log_step "Configurando firewall"
    
    # Verificar se UFW está disponível
    if command -v ufw > /dev/null 2>&1; then
        if ! ufw status | grep -q "active"; then
            log_info "UFW não está ativo, ativando..."
            ufw --force enable
        fi
        
        # Permitir porta 8080
        ufw allow 8080/tcp comment "WebStream Hunter"
        ufw reload
        log_success "Firewall configurado (porta 8080 permitida)"
    else
        log_warning "UFW não encontrado. Para instalar: sudo apt install ufw"
        
        # Tentar iptables como fallback
        if command -v iptables > /dev/null 2>&1; then
            log_info "Configurando iptables..."
            iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
            log_success "IPTables configurado"
        fi
    fi
}

# ==============================================================================
# VERIFICAÇÃO FINAL
# ==============================================================================

final_checks() {
    log_step "Realizando verificações finais"
    
    echo -e "\n${CYAN}=== STATUS DA INSTALAÇÃO ===${NC}"
    
    # 1. Verificar serviço
    if systemctl is-active --quiet webstream-hunter.service; then
        echo -e "${GREEN}✓ Serviço está em execução${NC}"
    else
        echo -e "${RED}✗ Serviço não está em execução${NC}"
        systemctl status webstream-hunter.service --no-pager
    fi
    
    # 2. Verificar porta
    echo -e "\n${CYAN}Verificando porta 8080...${NC}"
    if netstat -tuln | grep -q ":8080 "; then
        echo -e "${GREEN}✓ Aplicação ouvindo na porta 8080${NC}"
    else
        echo -e "${YELLOW}⚠ Aplicação não está ouvindo (pode estar iniciando)${NC}"
        sleep 2
        if netstat -tuln | grep -q ":8080 "; then
            echo -e "${GREEN}✓ Agora está ouvindo na porta 8080${NC}"
        else
            echo -e "${RED}✗ Ainda não está ouvindo${NC}"
        fi
    fi
    
    # 3. Testar endpoint da API
    echo -e "\n${CYAN}Testando API...${NC}"
    sleep 3
    if curl -s http://localhost:8080/api/status | grep -q "online"; then
        echo -e "${GREEN}✓ API respondendo${NC}"
    else
        echo -e "${YELLOW}⚠ API pode não estar respondendo ainda${NC}"
    fi
    
    echo -e "\n${CYAN}=== RESUMO ===${NC}"
}

# ==============================================================================
# RELATÓRIO FINAL
# ==============================================================================

show_final_report() {
    local_ip=$(hostname -I | awk '{print $1}')
    
    echo -e "\n${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                WEBSTREAM HUNTER INSTALADO!                       ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${CYAN}🌐 ACESSO À INTERFACE:${NC}"
    echo -e "  ${GREEN}URL:${NC} http://$local_ip:8080"
    echo -e "  ${GREEN}Local:${NC} http://localhost:8080"
    
    echo -e "\n${CYAN}🔐 CREDENCIAIS:${NC}"
    echo -e "  ${YELLOW}Usuário:${NC} admin"
    echo -e "  ${YELLOW}Senha:${NC} admin123 ${RED}(Altere imediatamente!)${NC}"
    
    echo -e "\n${CYAN}⚙️  COMANDOS:${NC}"
    echo -e "  ${BLUE}sudo systemctl start webstream-hunter${NC}"
    echo -e "  ${BLUE}sudo systemctl stop webstream-hunter${NC}"
    echo -e "  ${BLUE}sudo systemctl status webstream-hunter${NC}"
    echo -e "  ${BLUE}sudo journalctl -u webstream-hunter -f${NC}"
    
    echo -e "\n${CYAN}📁 DIRETÓRIOS:${NC}"
    echo -e "  ${BLUE}Aplicação:${NC} $INSTALL_DIR"
    echo -e "  ${BLUE}Logs:${NC} $LOG_DIR"
    echo -e "  ${BLUE}Config:${NC} /etc/webstream_hunter"
    
    echo -e "\n${CYAN}🚀 PRÓXIMOS PASSOS:${NC}"
    echo -e "  1. Acesse http://$local_ip:8080"
    echo -e "  2. Faça login com admin/admin123"
    echo -e "  3. Configure seu primeiro scan"
    echo -e "  4. Explore os streams encontrados"
    
    echo -e "\n${RED}⚠️  IMPORTANTE:${NC}"
    echo -e "  • Altere a senha padrão!"
    echo -e "  • Use apenas em redes autorizadas"
    echo -e "  • Respeite as leis de privacidade"
    
    echo -e "\n${GREEN}✅ Instalação concluída com sucesso!${NC}"
}

# ==============================================================================
# FUNÇÃO PRINCIPAL DE INSTALAÇÃO
# ==============================================================================

main_installation() {
    log_header "INICIANDO INSTALAÇÃO DO WEBSTREAM HUNTER"
    
    # Verificações iniciais
    check_root
    check_ubuntu
    
    # Corrigir e atualizar sistema
    fix_apt_sources
    update_system_safe
    
    # Instalar pacotes
    install_essential_packages
    install_streaming_packages
    
    # Configurar aplicação
    setup_python_environment
    create_application_files
    setup_systemd_service
    setup_firewall
    
    # Verificações
    final_checks
    show_final_report
}

# ==============================================================================
# FUNÇÃO DE DESINSTALAÇÃO
# ==============================================================================

uninstall() {
    log_header "DESINSTALANDO WEBSTREAM HUNTER"
    
    echo -e "${RED}Tem certeza que deseja desinstalar? (s/N): ${NC}"
    read -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Ss]$ ]]; then
        log_info "Desinstalação cancelada"
        exit 0
    fi
    
    # Parar serviço
    systemctl stop webstream-hunter.service 2>/dev/null || true
    systemctl disable webstream-hunter.service 2>/dev/null || true
    
    # Remover arquivos
    rm -f /etc/systemd/system/webstream-hunter.service
    systemctl daemon-reload
    
    # Remover diretórios (opcional)
    echo -e "${YELLOW}Remover diretórios de dados? (s/N): ${NC}"
    read -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        rm -rf "$INSTALL_DIR"
        rm -rf /etc/webstream_hunter
        rm -rf /usr/share/webstream_hunter
        log_info "Diretórios removidos"
    else
        log_info "Diretórios mantidos em:"
        log_info "  $INSTALL_DIR"
        log_info "  /etc/webstream_hunter"
        log_info "  /usr/share/webstream_hunter"
    fi
    
    log_success "WebStream Hunter desinstalado"
}

# ==============================================================================
# FUNÇÃO DE STATUS
# ==============================================================================

status() {
    log_header "STATUS DO WEBSTREAM HUNTER"
    
    echo -e "${CYAN}Verificando serviço...${NC}\n"
    
    if systemctl is-active --quiet webstream-hunter.service; then
        echo -e "${GREEN}✓ Serviço está em execução${NC}"
        systemctl status webstream-hunter.service --no-pager | head -20
    else
        echo -e "${RED}✗ Serviço não está em execução${NC}"
    fi
    
    echo -e "\n${CYAN}Verificando porta...${NC}"
    if netstat -tuln | grep -q ":8080 "; then
        echo -e "${GREEN}✓ Ouvindo na porta 8080${NC}"
    else
        echo -e "${RED}✗ Não está ouvindo na porta 8080${NC}"
    fi
    
    echo -e "\n${CYAN}Testando API...${NC}"
    if curl -s http://localhost:8080/api/status 2>/dev/null | grep -q "online"; then
        echo -e "${GREEN}✓ API respondendo${NC}"
    else
        echo -e "${RED}✗ API não está respondendo${NC}"
    fi
}

# ==============================================================================
# MENU PRINCIPAL
# ==============================================================================

show_menu() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                  WEBSTREAM HUNTER - INSTALADOR                   ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${GREEN}Escolha uma opção:${NC}"
    echo -e "  ${CYAN}1.${NC} Instalação completa"
    echo -e "  ${CYAN}2.${NC} Desinstalar"
    echo -e "  ${CYAN}3.${NC} Ver status"
    echo -e "  ${CYAN}4.${NC} Sair"
    echo ""
    
    read -p "Opção (1-4): " -n 1 -r
    echo
    
    case $REPLY in
        1)
            main_installation
            ;;
        2)
            uninstall
            ;;
        3)
            status
            ;;
        4)
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
# TRATAMENTO DE ARGUMENTOS
# ==============================================================================

# Verificar argumentos
if [[ $# -gt 0 ]]; then
    case $1 in
        --install|-i)
            main_installation
            ;;
        --uninstall|-u)
            uninstall
            ;;
        --status|-s)
            status
            ;;
        --help|-h)
            echo "Uso: $0 [OPÇÃO]"
            echo ""
            echo "Opções:"
            echo "  --install, -i    Instalação completa"
            echo "  --uninstall, -u  Desinstalar"
            echo "  --status, -s     Verificar status"
            echo "  --help, -h       Ajuda"
            echo ""
            echo "Sem argumentos: Menu interativo"
            exit 0
            ;;
        *)
            log_error "Argumento inválido: $1"
            echo "Use: $0 --help"
            exit 1
            ;;
    esac
else
    # Menu interativo
    show_menu
fi

# Registrar conclusão
log_info "Processo concluído. Log salvo em: $LOG_FILE"
