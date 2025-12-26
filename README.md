🚀 Instalação Passo a Passo

git clone https://github.com/lamarksak47/webstream_hunter.git

cd webstream_hunter

1. Salvar o script:

# Copie todo o conteúdo acima e salve como:

sudo nano install_webstream_hunter.sh

2. Tornar executável:

sudo chmod +x install_webstream_hunter.sh

3. Executar a instalação:
4. 
Opção A - Instalação completa (recomendado):


sudo ./install_webstream_hunter.sh --install

Opção B - Menu interativo:


sudo ./install_webstream_hunter.sh

Opção C - Apenas verificar status:


sudo ./install_webstream_hunter.sh --status

Opção D - Atualizar instalação:


sudo ./install_webstream_hunter.sh --update

Opção E - Desinstalar:


sudo ./install_webstream_hunter.sh --uninstall
🎯 CARACTERÍSTICAS DESTE SCRIPT ÚNICO:
✅ Tudo em um arquivo - Não precisa baixar múltiplos arquivos
✅ Instalação automática - Detecta e configura tudo automaticamente
✅ Sistema completo - Inclui aplicação, templates, scripts, service systemd
✅ Verificações - Checa espaço, memória, dependências antes de instalar
✅ Backup automático - Configura cron jobs para backup diário
✅ Monitoramento - Script de monitoramento incluído
✅ Segurança - Cria usuário dedicado, configura permissões
✅ Firewall - Configura UFW automaticamente
✅ Menu interativo - Interface fácil de usar
✅ Logs detalhados - Registra toda a instalação
✅ Desinstalação limpa - Remove tudo mantendo backups
✅ Atualização - Sistema de atualização integrado

📁 O QUE ESTE SCRIPT INSTALA:
text
/opt/webstream_hunter/
├── webstream_hunter.py          # Aplicação principal
├── start.sh                     # Script de inicialização
├── backup.sh                    # Script de backup
├── monitor.sh                   # Script de monitoramento
├── requirements.txt             # Dependências Python
├── venv/                        # Virtual environment
└── backups/                     # Backups locais

/var/log/webstream_hunter/
├── app.log                      # Logs da aplicação
├── install.log                  # Log da instalação
└── backup.log                   # Logs de backup

/etc/webstream_hunter/
└── config.json                  # Configuração

/usr/share/webstream_hunter/
├── templates/                   # Templates HTML
│   ├── base.html
│   ├── login.html
│   └── dashboard.html
└── static/                      # Arquivos estáticos

/etc/systemd/system/
└── webstream-hunter.service    # Service systemd
🔧 COMANDOS PÓS-INSTALAÇÃO:

# Iniciar serviço
sudo systemctl start webstream-hunter

# Parar serviço
sudo systemctl stop webstream-hunter

# Reiniciar serviço
sudo systemctl restart webstream-hunter

# Ver status
sudo systemctl status webstream-hunter

# Ver logs em tempo real
sudo journalctl -u webstream-hunter -f

# Backup manual
sudo /opt/webstream_hunter/backup.sh

# Monitoramento manual
sudo /opt/webstream_hunter/monitor.sh
🌐 ACESSO À INTERFACE WEB:
Abra o navegador

Acesse: http://seu-ip:8080

Login: admin / admin123

Altere a senha imediatamente!

🛡️ RECOMENDAÇÕES DE SEGURANÇA:
Altere a senha padrão após o primeiro login

Configure SSL na interface de configurações

Restrinja IPs via whitelist no arquivo de configuração

Mantenha atualizado o sistema operacional

Configure firewall para permitir apenas IPs confiáveis

Faça backups regulares dos dados importantes

⚠️ AVISO LEGAL:
Este software é fornecido apenas para fins educacionais e de teste em redes próprias. O uso para escanear redes sem autorização é ilegal e pode resultar em consequências legais graves. O desenvolvedor não se responsabiliza pelo uso indevido deste software.

Este script único contém todo o sistema WebStream Hunter pronto para instalação em Ubuntu
