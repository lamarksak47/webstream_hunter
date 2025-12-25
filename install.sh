#!/bin/bash
# WebStream Hunter - Instalador Ubuntu 20.04
# Execute como root: sudo ./install.sh

set -e

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funções de logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script precisa ser executado como root!"
        echo "Use: sudo $0"
        exit 1
    fi
}

# Verificar Ubuntu 20.04
check_ubuntu() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Sistema não suportado!"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" || "$VERSION_ID" != "20.04" ]]; then
        log_warning "Este script foi testado no Ubuntu 20.04"
        read -p "Continuar mesmo assim? (s/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            exit 1
        fi
    fi
}

# Atualizar sistema
update_system() {
    log_info "Atualizando sistema..."
    apt-get update -y
    apt-get upgrade -y
}

# Instalar dependências
install_dependencies() {
    log_info "Instalando dependências do sistema..."
    
    # Dependências principais
    apt-get install -y \
        python3-pip \
        python3-dev \
        build-essential \
        libssl-dev \
        libffi-dev \
        ffmpeg \
        vlc \
        nmap \
        tshark \
        sqlite3 \
        net-tools \
        iproute2 \
        python3-venv \
        git \
        curl \
        wget
    
    log_success "Dependências do sistema instaladas"
}

# Criar estrutura de diretórios
create_directories() {
    log_info "Criando estrutura de diretórios..."
    
    mkdir -p /opt/webstream_hunter
    mkdir -p /var/log/webstream_hunter
    mkdir -p /var/lib/webstream_hunter
    mkdir -p /var/cache/webstream_hunter
    mkdir -p /etc/webstream_hunter
    mkdir -p /usr/share/webstream_hunter/static
    mkdir -p /usr/share/webstream_hunter/templates
    
    log_success "Diretórios criados"
}

# Criar usuário dedicado
create_user() {
    log_info "Criando usuário dedicado..."
    
    if ! id "webstream" &>/dev/null; then
        useradd -r -s /bin/false -d /opt/webstream_hunter webstream
    fi
    
    log_success "Usuário criado"
}

# Copiar arquivos da aplicação
copy_application() {
    log_info "Copiando arquivos da aplicação..."
    
    # Supondo que o script está no mesmo diretório dos arquivos
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Copiar arquivos principais
    cp "$SCRIPT_DIR/webstream_hunter.py" /opt/webstream_hunter/
    chmod +x /opt/webstream_hunter/webstream_hunter.py
    
    # Copiar templates se existirem
    if [[ -d "$SCRIPT_DIR/templates" ]]; then
        cp -r "$SCRIPT_DIR/templates"/* /usr/share/webstream_hunter/templates/
    fi
    
    log_success "Arquivos copiados"
}

# Configurar virtual environment
setup_venv() {
    log_info "Configurando virtual environment..."
    
    cd /opt/webstream_hunter
    python3 -m venv venv
    
    # Instalar dependências Python
    ./venv/bin/pip install --upgrade pip
    
    cat > /opt/webstream_hunter/requirements.txt << 'EOF'
flask>=2.3.0
flask-socketio>=5.3.0
flask-cors>=4.0.0
flask-login>=0.6.0
werkzeug>=2.3.0
aiohttp>=3.8.0
async-timeout>=4.0.0
websockets>=11.0.0
nmap3>=2.0.0
scapy>=2.5.0
psutil>=5.9.0
netifaces>=0.11.0
ifaddr>=0.2.0
ffmpeg-python>=0.2.0
opencv-python-headless>=4.7.0
pillow>=10.0.0
imagehash>=4.3.0
sqlalchemy>=2.0.0
numpy>=1.24.0
python-nmap>=0.7.1
requests>=2.31.0
beautifulsoup4>=4.12.0
EOF
    
    ./venv/bin/pip install -r requirements.txt
    
    log_success "Virtual environment configurado"
}

# Criar configuração padrão
create_config() {
    log_info "Criando configuração padrão..."
    
    cat > /etc/webstream_hunter/config.json << 'EOF'
{
    "web": {
        "host": "0.0.0.0",
        "port": 8080,
        "debug": false,
        "secret_key": "change-this-in-production-12345",
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
        "max_hosts_per_scan": 65536
    },
    "stream_analysis": {
        "sample_duration": 30,
        "analyze_codecs": true,
        "check_encryption": true,
        "validate_stream": true,
        "buffer_size": 8192
    },
    "database": {
        "backup_interval": 3600,
        "max_backups": 30,
        "cleanup_days": 90
    },
    "security": {
        "require_auth": true,
        "default_user": "admin",
        "default_password": "admin123",
        "enable_ssl": false,
        "ssl_cert": "",
        "ssl_key": "",
        "allowed_ips": [],
        "blocked_ips": []
    },
    "notifications": {
        "email_enabled": false,
        "smtp_server": "",
        "smtp_port": 587,
        "email_from": "",
        "telegram_enabled": false,
        "telegram_bot_token": "",
        "telegram_chat_id": ""
    }
}
EOF
    
    log_success "Configuração criada"
}

# Criar service systemd
create_service() {
    log_info "Criando service systemd..."
    
    cat > /etc/systemd/system/webstream-hunter.service << 'EOF'
[Unit]
Description=WebStream Hunter - Advanced MPEG-TS Stream Scanner
After=network.target
Wants=network.target

[Service]
Type=simple
User=webstream
Group=webstream
WorkingDirectory=/opt/webstream_hunter
ExecStart=/opt/webstream_hunter/venv/bin/python3 /opt/webstream_hunter/webstream_hunter.py
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=webstream-hunter

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/webstream_hunter /var/lib/webstream_hunter /var/cache/webstream_hunter

# Resource limits
LimitNOFILE=65536
LimitNPROC=65536

[Install]
WantedBy=multi-user.target
EOF
    
    log_success "Service systemd criado"
}

# Configurar permissões
set_permissions() {
    log_info "Configurando permissões..."
    
    # Diretórios
    chown -R webstream:webstream /opt/webstream_hunter
    chown -R webstream:webstream /var/log/webstream_hunter
    chown -R webstream:webstream /var/lib/webstream_hunter
    chown -R webstream:webstream /var/cache/webstream_hunter
    chown -R webstream:webstream /etc/webstream_hunter
    
    # Permissões
    chmod 750 /opt/webstream_hunter
    chmod 750 /var/log/webstream_hunter
    chmod 750 /var/lib/webstream_hunter
    chmod 750 /var/cache/webstream_hunter
    chmod 750 /etc/webstream_hunter
    
    # Arquivos de configuração
    chmod 640 /etc/webstream_hunter/config.json
    
    # Script principal
    chmod 755 /opt/webstream_hunter/webstream_hunter.py
    
    log_success "Permissões configuradas"
}

# Configurar firewall
setup_firewall() {
    log_info "Configurando firewall..."
    
    # Verificar se ufw está instalado
    if command -v ufw &> /dev/null; then
        ufw allow 8080/tcp comment "WebStream Hunter"
        ufw reload
        log_success "Firewall configurado (porta 8080 aberta)"
    else
        log_warning "UFW não encontrado. Configure o firewall manualmente se necessário."
    fi
}

# Iniciar serviço
start_service() {
    log_info "Iniciando serviço..."
    
    systemctl daemon-reload
    systemctl enable webstream-hunter.service
    systemctl start webstream-hunter.service
    
    # Aguardar serviço iniciar
    sleep 3
    
    if systemctl is-active --quiet webstream-hunter.service; then
        log_success "Serviço iniciado com sucesso!"
    else
        log_error "Falha ao iniciar o serviço!"
        journalctl -u webstream-hunter.service --no-pager -n 20
        exit 1
    fi
}

# Mostrar informações finais
show_summary() {
    local_ip=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo "================================================"
    echo "       WEBSTREAM HUNTER INSTALADO COM SUCESSO!"
    echo "================================================"
    echo ""
    echo "📊 INFORMAÇÕES DO SISTEMA:"
    echo "   • URL de acesso: http://${local_ip}:8080"
    echo "   • URL local: http://localhost:8080"
    echo "   • Usuário: admin"
    echo "   • Senha: admin123"
    echo ""
    echo "🔧 COMANDOS DE GERENCIAMENTO:"
    echo "   sudo systemctl start webstream-hunter"
    echo "   sudo systemctl stop webstream-hunter"
    echo "   sudo systemctl restart webstream-hunter"
    echo "   sudo systemctl status webstream-hunter"
    echo "   sudo journalctl -u webstream-hunter -f"
    echo ""
    echo "📁 DIRETÓRIOS IMPORTANTES:"
    echo "   • Aplicação: /opt/webstream_hunter"
    echo "   • Logs: /var/log/webstream_hunter"
    echo "   • Configuração: /etc/webstream_hunter/config.json"
    echo "   • Banco de dados: /var/lib/webstream_hunter"
    echo ""
    echo "⚠️  RECOMENDAÇÕES DE SEGURANÇA:"
    echo "   1. Altere a senha padrão imediatamente!"
    echo "   2. Configure SSL/HTTPS na interface web"
    echo "   3. Restrinja IPs de acesso via configuração"
    echo "   4. Mantenha o sistema atualizado"
    echo ""
    echo "🚀 PRÓXIMOS PASSOS:"
    echo "   1. Acesse http://${local_ip}:8080"
    echo "   2. Faça login com admin/admin123"
    echo "   3. Altere a senha nas configurações"
    echo "   4. Configure conforme necessário"
    echo "   5. Inicie seu primeiro scan!"
    echo ""
    echo "================================================"
}

# Função principal
main() {
    echo ""
    echo "╔══════════════════════════════════════════════╗"
    echo "║   WEBSTREAM HUNTER - INSTALADOR UBUNTU 20.04 ║"
    echo "╚══════════════════════════════════════════════╝"
    echo ""
    
    # Verificações iniciais
    check_root
    check_ubuntu
    
    # Etapas de instalação
    update_system
    install_dependencies
    create_directories
    create_user
    copy_application
    setup_venv
    create_config
    create_service
    set_permissions
    setup_firewall
    start_service
    
    # Resumo final
    show_summary
}

# Executar
main "$@"
