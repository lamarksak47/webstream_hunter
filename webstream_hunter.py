#!/usr/bin/env python3
"""
WEBSTREAM HUNTER - Sistema Completo de Scanner MPEG-TS
Versão: 4.0 Web Edition
Sistema: Ubuntu 20.04 LTS
Autor: Stream Security Lab
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
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import platform
import signal
import psutil
import netifaces
import uuid

# Web Framework
from flask import Flask, render_template, request, jsonify, send_file, Response, session, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import werkzeug.security

# Async/Streaming
import aiohttp
import async_timeout
from aiohttp import ClientSession, ClientTimeout
import websockets

# Scanner/Network
import nmap3
import scapy.all as scapy
from scapy.all import sniff, IP, TCP, UDP
import dpkt
import ifaddr

# Stream Analysis
import ffmpeg
import cv2
import numpy as np
from PIL import Image
import imagehash

# Database
import sqlalchemy as sa
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, create_engine

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
LOG_DIR = '/var/log/webstream_hunter'
CACHE_DIR = '/var/cache/webstream_hunter'
UPLOAD_DIR = '/var/lib/webstream_hunter/uploads'
STATIC_DIR = '/usr/share/webstream_hunter/static'
TEMPLATE_DIR = '/usr/share/webstream_hunter/templates'

# Criar diretórios se não existirem
for directory in [LOG_DIR, CACHE_DIR, UPLOAD_DIR, os.path.dirname(CONFIG_PATH)]:
    os.makedirs(directory, exist_ok=True, mode=0o755)

# Configuração padrão
DEFAULT_CONFIG = {
    "web": {
        "host": "0.0.0.0",
        "port": 8080,
        "debug": False,
        "secret_key": "change-this-in-production",
        "session_timeout": 3600,
        "max_upload_size": 100 * 1024 * 1024,  # 100MB
        "rate_limit": "1000/hour"
    },
    "scanning": {
        "max_threads": 100,
        "timeout": 10,
        "retry_attempts": 3,
        "scan_delay": 0.05,
        "stealth_mode": True,
        "max_hosts_per_scan": 65536
    },
    "stream_analysis": {
        "sample_duration": 30,
        "analyze_codecs": True,
        "check_encryption": True,
        "validate_stream": True,
        "buffer_size": 8192
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
    },
    "notifications": {
        "email_enabled": False,
        "smtp_server": "",
        "smtp_port": 587,
        "email_from": "",
        "telegram_enabled": False,
        "telegram_bot_token": "",
        "telegram_chat_id": ""
    }
}

# Enums
class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class StreamProtocol(Enum):
    HTTP = "http"
    HTTPS = "https"
    RTSP = "rtsp"
    RTMP = "rtmp"
    UDP = "udp"
    RTP = "rtp"
    HLS = "hls"
    MPEG_DASH = "dash"
    MSS = "mss"

class StreamQuality(Enum):
    UNKNOWN = "unknown"
    SD = "sd"
    HD = "hd"
    FULL_HD = "full_hd"
    UHD_4K = "4k"
    UHD_8K = "8k"

# Data Classes
@dataclass
class ScanTarget:
    ip_range: str
    ports: List[int]
    scan_type: str
    priority: int = 1
    description: str = ""

@dataclass
class StreamInfo:
    url: str
    protocol: str
    ip: str
    port: int
    codec: str
    resolution: str
    bitrate: int
    fps: float
    duration: float
    has_video: bool
    has_audio: bool
    has_subtitles: bool
    encrypted: bool
    quality_score: int
    discovered_at: datetime

@dataclass
class Vulnerability:
    severity: str  # low, medium, high, critical
    title: str
    description: str
    cve: str = ""
    remediation: str = ""

# Database Models
Base = declarative_base()

class User(Base, UserMixin):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    email = Column(String(120), unique=True)
    role = Column(String(32), default='user')  # admin, user, viewer
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    scans = relationship('ScanJob', back_populates='user')
    
    def set_password(self, password):
        self.password_hash = werkzeug.security.generate_password_hash(password)
    
    def check_password(self, password):
        return werkzeug.security.check_password_hash(self.password_hash, password)

class ScanJob(Base):
    __tablename__ = 'scan_jobs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    name = Column(String(128))
    target = Column(Text)
    ports = Column(Text)
    scan_type = Column(String(32))
    status = Column(String(32))
    progress = Column(Float, default=0.0)
    results_count = Column(Integer, default=0)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    error_message = Column(Text)
    
    user = relationship('User', back_populates='scans')
    results = relationship('ScanResult', back_populates='scan_job')

class ScanResult(Base):
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey('scan_jobs.id'))
    ip = Column(String(45))  # IPv4 or IPv6
    port = Column(Integer)
    protocol = Column(String(16))
    service = Column(String(64))
    banner = Column(Text)
    stream_url = Column(Text)
    stream_protocol = Column(String(16))
    codec_video = Column(String(32))
    codec_audio = Column(String(32))
    resolution = Column(String(32))
    bitrate = Column(Integer)
    fps = Column(Float)
    duration = Column(Float)
    has_audio = Column(Boolean)
    has_video = Column(Boolean)
    encrypted = Column(Boolean)
    quality_score = Column(Integer)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    scan_job = relationship('ScanJob', back_populates='results')

class StreamChannel(Base):
    __tablename__ = 'stream_channels'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(128))
    url = Column(Text, unique=True)
    category = Column(String(64))
    country = Column(String(2))
    language = Column(String(8))
    logo_url = Column(Text)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    last_checked = Column(DateTime)
    failure_count = Column(Integer, default=0)
    
    favorites = relationship('UserFavorite', back_populates='channel')

class UserFavorite(Base):
    __tablename__ = 'user_favorites'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    channel_id = Column(Integer, ForeignKey('stream_channels.id'))
    added_at = Column(DateTime, default=datetime.utcnow)
    notes = Column(Text)
    
    user = relationship('User')
    channel = relationship('StreamChannel', back_populates='favorites')

class SystemLog(Base):
    __tablename__ = 'system_logs'
    
    id = Column(Integer, primary_key=True)
    level = Column(String(16))  # INFO, WARNING, ERROR, CRITICAL
    module = Column(String(64))
    message = Column(Text)
    details = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

# Core Scanner Engine
class AdvancedStreamScanner:
    """Motor avançado de scanner de streams"""
    
    def __init__(self):
        self.nmap = nmap3.Nmap()
        self.executor = ThreadPoolExecutor(max_workers=50)
        self.active_scans = {}
        self.common_ports = self._load_common_ports()
        self.common_paths = self._load_common_paths()
        self.user_agents = self._load_user_agents()
        
    def _load_common_ports(self):
        """Carrega portas comuns para streaming"""
        return [
            # HTTP/HTTPS
            80, 443, 8080, 8000, 8008, 8443, 8888,
            # RTSP
            554, 8554,
            # RTMP
            1935, 1936,
            # UDP/RTP
            1234, 5000, 5001, 5002, 5003, 5004,
            # IPTV/Streaming
            8001, 8002, 8003, 8004, 8005,
            # Misc
            8081, 8082, 8083, 8084, 8085,
            # Advanced
            9000, 9001, 9010, 9020, 9030,
            10000, 10001, 10002
        ]
        
    def _load_common_paths(self):
        """Carrega paths comuns para brute force"""
        paths = []
        
        # Paths básicos
        base_paths = [
            "", "/", "/live", "/stream", "/tv", "/iptv",
            "/video", "/hls", "/m3u8", "/ts", "/mpegts",
            "/streaming", "/live/stream", "/live/m3u8"
        ]
        
        # Paths específicos
        specific_paths = [
            "/axis-cgi/mjpg/video.cgi",
            "/cam/realmonitor",
            "/snapshot.cgi",
            "/videostream.cgi",
            "/video.mjpg",
            "/img/video.mjpeg",
            "/mjpg/video.mjpg",
            "/cgi-bin/mjpg/video.cgi"
        ]
        
        # Paths com parâmetros
        param_paths = [
            "/live?stream=channel1",
            "/stream?channel=1",
            "/tv/channel1.m3u8",
            "/iptv/channel1.ts"
        ]
        
        paths.extend(base_paths)
        paths.extend(specific_paths)
        paths.extend(param_paths)
        
        return list(set(paths))
        
    def _load_user_agents(self):
        """Carrega lista de User-Agents"""
        return [
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "VLC/3.0.18 LibVLC/3.0.18",
            "FFmpeg/6.0 (Linux)",
            "Lavf/60.3.100",
            "StreamChecker/2.0",
            "IPTV Player/3.0",
            "python-requests/2.31.0"
        ]
    
    async def comprehensive_scan(self, target: str, ports: List[int] = None) -> Dict[str, Any]:
        """Executa scan completo assíncrono"""
        if ports is None:
            ports = self.common_ports
            
        results = {
            "target": target,
            "start_time": datetime.utcnow(),
            "open_ports": [],
            "services": [],
            "streams": [],
            "vulnerabilities": [],
            "stats": {}
        }
        
        try:
            # 1. Scan de portas
            open_ports = await self._async_port_scan(target, ports)
            results["open_ports"] = open_ports
            
            # 2. Detecção de serviços
            services = await self._detect_services(target, open_ports)
            results["services"] = services
            
            # 3. Busca de streams
            stream_tasks = []
            for service in services:
                if self._is_stream_service(service):
                    stream_tasks.append(
                        self._analyze_stream_service(target, service)
                    )
            
            if stream_tasks:
                stream_results = await asyncio.gather(*stream_tasks, return_exceptions=True)
                results["streams"] = [r for r in stream_results if isinstance(r, dict) and r]
            
            # 4. Scan de vulnerabilidades
            vulns = await self._check_vulnerabilities(target, services)
            results["vulnerabilities"] = vulns
            
            # 5. Estatísticas
            results["stats"] = {
                "total_ports_scanned": len(ports),
                "open_ports_found": len(open_ports),
                "services_found": len(services),
                "streams_found": len(results["streams"]),
                "vulnerabilities_found": len(vulns)
            }
            
        except Exception as e:
            logger.error(f"Erro no scan: {str(e)}")
            results["error"] = str(e)
            
        results["end_time"] = datetime.utcnow()
        results["duration"] = (results["end_time"] - results["start_time"]).total_seconds()
        
        return results
    
    async def _async_port_scan(self, target: str, ports: List[int]) -> List[int]:
        """Scan de portas assíncrono"""
        open_ports = []
        
        # Usar nmap se disponível
        try:
            result = self.nmap.scan_top_ports(target, args="-sS -T4")
            if target in result:
                for port_info in result[target]["ports"]:
                    if port_info["state"] == "open":
                        open_ports.append(port_info["portid"])
        except:
            # Fallback para scan manual
            tasks = []
            for port in ports:
                tasks.append(self._check_port_async(target, port))
            
            results = await asyncio.gather(*tasks)
            open_ports = [port for port, is_open in zip(ports, results) if is_open]
        
        return open_ports
    
    async def _check_port_async(self, target: str, port: int) -> bool:
        """Verifica porta de forma assíncrona"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def _detect_services(self, target: str, ports: List[int]) -> List[Dict]:
        """Detecta serviços nas portas abertas"""
        services = []
        
        for port in ports:
            try:
                # Tentar banner grabbing
                banner = await self._get_banner_async(target, port)
                
                # Identificar serviço
                service_info = await self._identify_service(target, port, banner)
                if service_info:
                    services.append(service_info)
                    
            except Exception as e:
                logger.debug(f"Erro ao detectar serviço {target}:{port}: {e}")
        
        return services
    
    async def _get_banner_async(self, target: str, port: int) -> str:
        """Obtém banner do serviço"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=3.0
            )
            
            # Enviar requisição básica
            if port in [80, 8080, 8000]:
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 554:
                writer.write(b"OPTIONS * RTSP/1.0\r\n\r\n")
            
            await writer.drain()
            
            # Ler resposta
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            
            return banner.decode('utf-8', errors='ignore')
            
        except:
            return ""
    
    async def _identify_service(self, target: str, port: int, banner: str) -> Optional[Dict]:
        """Identifica serviço baseado na porta e banner"""
        service_info = {
            "port": port,
            "banner": banner[:500],
            "protocol": "unknown",
            "service": "unknown"
        }
        
        # Identificar por porta
        if port in [80, 8080, 8000, 8008, 8888]:
            service_info["protocol"] = "http"
            service_info["service"] = "web"
            
            if "Server:" in banner:
                server = banner.split("Server:")[1].split("\r\n")[0].strip()
                service_info["server"] = server
                
        elif port == 554:
            service_info["protocol"] = "rtsp"
            service_info["service"] = "rtsp_server"
            
        elif port == 1935:
            service_info["protocol"] = "rtmp"
            service_info["service"] = "rtmp_server"
            
        elif port in [5000, 5001, 5002, 5003, 5004]:
            service_info["protocol"] = "rtp/udp"
            service_info["service"] = "video_stream"
            
        # Identificar por banner
        if "RTSP" in banner.upper():
            service_info["protocol"] = "rtsp"
            service_info["service"] = "rtsp_server"
        elif "HTTP" in banner.upper():
            service_info["protocol"] = "http"
            service_info["service"] = "web_server"
            
        return service_info
    
    def _is_stream_service(self, service_info: Dict) -> bool:
        """Verifica se serviço pode ser stream"""
        if service_info["protocol"] in ["http", "rtsp", "rtmp"]:
            return True
        
        if "video" in service_info["service"].lower():
            return True
            
        return False
    
    async def _analyze_stream_service(self, target: str, service_info: Dict) -> Optional[Dict]:
        """Analisa serviço de streaming"""
        protocol = service_info["protocol"]
        port = service_info["port"]
        
        # Gerar URLs para teste
        urls_to_test = self._generate_test_urls(target, port, protocol)
        
        for url in urls_to_test:
            try:
                stream_info = await self._verify_stream_url(url)
                if stream_info:
                    # Análise detalhada
                    detailed_info = await self._deep_stream_analysis(url)
                    if detailed_info:
                        stream_info.update(detailed_info)
                        stream_info["discovery_url"] = url
                        stream_info["source_service"] = service_info
                        return stream_info
                        
            except Exception as e:
                continue
        
        return None
    
    def _generate_test_urls(self, target: str, port: int, protocol: str) -> List[str]:
        """Gera URLs para teste baseado no protocolo"""
        urls = []
        
        if protocol == "http":
            schemes = ["http://", "https://"]
            for scheme in schemes:
                base = f"{scheme}{target}:{port}"
                urls.append(base)
                for path in self.common_paths[:20]:  # Limitar para performance
                    urls.append(f"{base}{path}")
                    
        elif protocol == "rtsp":
            urls.append(f"rtsp://{target}:{port}/")
            urls.append(f"rtsp://{target}:{port}/live")
            urls.append(f"rtsp://{target}:{port}/stream")
            
        elif protocol == "rtmp":
            urls.append(f"rtmp://{target}:{port}/")
            urls.append(f"rtmp://{target}:{port}/live")
            urls.append(f"rtmp://{target}:{port}/stream")
            
        return urls
    
    async def _verify_stream_url(self, url: str) -> Optional[Dict]:
        """Verifica se URL contém stream válido"""
        try:
            headers = {
                "User-Agent": self.user_agents[0],
                "Accept": "video/*, audio/*, */*"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        content_type = response.headers.get('Content-Type', '')
                        
                        # Verificar tipos de conteúdo de streaming
                        stream_types = [
                            'video/', 'audio/', 'application/vnd.apple.mpegurl',
                            'application/x-mpegurl', 'video/mp2t', 'video/MP2T',
                            'application/octet-stream'
                        ]
                        
                        if any(st in content_type.lower() for st in stream_types):
                            return {
                                "url": url,
                                "content_type": content_type,
                                "content_length": response.headers.get('Content-Length'),
                                "server": response.headers.get('Server'),
                                "status_code": response.status
                            }
                            
        except Exception as e:
            logger.debug(f"Falha ao verificar {url}: {e}")
            
        return None
    
    async def _deep_stream_analysis(self, url: str) -> Dict:
        """Análise profunda do stream usando ffprobe"""
        try:
            # Usar ffprobe via subprocess assíncrono
            cmd = [
                "ffprobe",
                "-v", "quiet",
                "-print_format", "json",
                "-show_format",
                "-show_streams",
                url
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                data = json.loads(stdout.decode())
                return self._parse_ffprobe_output(data)
                
        except Exception as e:
            logger.error(f"Erro na análise do stream: {e}")
            
        return {}
    
    def _parse_ffprobe_output(self, data: Dict) -> Dict:
        """Parse do output do ffprobe"""
        analysis = {
            "streams": [],
            "format": {},
            "video_info": {},
            "audio_info": {},
            "general_info": {}
        }
        
        # Formato geral
        if "format" in data:
            format_info = data["format"]
            analysis["format"] = {
                "format_name": format_info.get("format_name"),
                "format_long_name": format_info.get("format_long_name"),
                "duration": float(format_info.get("duration", 0)),
                "size": int(format_info.get("size", 0)),
                "bit_rate": int(format_info.get("bit_rate", 0)),
                "tags": format_info.get("tags", {})
            }
        
        # Informações de streams
        video_streams = []
        audio_streams = []
        
        if "streams" in data:
            for stream in data["streams"]:
                stream_type = stream.get("codec_type")
                
                if stream_type == "video":
                    video_info = {
                        "codec": stream.get("codec_name"),
                        "codec_long": stream.get("codec_long_name"),
                        "width": stream.get("width"),
                        "height": stream.get("height"),
                        "fps": self._parse_fps(stream.get("r_frame_rate")),
                        "bit_rate": stream.get("bit_rate"),
                        "pix_fmt": stream.get("pix_fmt")
                    }
                    video_streams.append(video_info)
                    
                elif stream_type == "audio":
                    audio_info = {
                        "codec": stream.get("codec_name"),
                        "codec_long": stream.get("codec_long_name"),
                        "sample_rate": stream.get("sample_rate"),
                        "channels": stream.get("channels"),
                        "channel_layout": stream.get("channel_layout"),
                        "bit_rate": stream.get("bit_rate")
                    }
                    audio_streams.append(audio_info)
        
        analysis["video_info"] = video_streams[0] if video_streams else {}
        analysis["audio_info"] = audio_streams[0] if audio_streams else {}
        
        # Informações gerais
        analysis["general_info"] = {
            "has_video": len(video_streams) > 0,
            "has_audio": len(audio_streams) > 0,
            "video_streams": len(video_streams),
            "audio_streams": len(audio_streams),
            "resolution": self._get_resolution(video_streams[0] if video_streams else {}),
            "estimated_quality": self._estimate_quality(video_streams[0] if video_streams else {})
        }
        
        return analysis
    
    def _parse_fps(self, fps_str: str) -> float:
        """Parse FPS string para float"""
        try:
            if fps_str and '/' in fps_str:
                num, den = fps_str.split('/')
                return float(num) / float(den)
            return float(fps_str) if fps_str else 0
        except:
            return 0
    
    def _get_resolution(self, video_info: Dict) -> str:
        """Obtém resolução do vídeo"""
        width = video_info.get("width")
        height = video_info.get("height")
        
        if width and height:
            return f"{width}x{height}"
        return "unknown"
    
    def _estimate_quality(self, video_info: Dict) -> str:
        """Estima qualidade do stream"""
        width = video_info.get("width", 0)
        bitrate = int(video_info.get("bit_rate", 0))
        
        if width >= 3840:
            return "4K"
        elif width >= 1920:
            return "Full HD"
        elif width >= 1280:
            return "HD"
        elif width >= 720:
            return "SD"
        else:
            return "Low"
    
    async def _check_vulnerabilities(self, target: str, services: List[Dict]) -> List[Dict]:
        """Verifica vulnerabilidades comuns"""
        vulnerabilities = []
        
        for service in services:
            vulns = await self._check_service_vulnerabilities(target, service)
            if vulns:
                vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _check_service_vulnerabilities(self, target: str, service: Dict) -> List[Dict]:
        """Verifica vulnerabilidades específicas do serviço"""
        vulns = []
        port = service["port"]
        protocol = service["protocol"]
        
        # Vulnerabilidades RTSP
        if protocol == "rtsp":
            rtsp_vulns = await self._check_rtsp_vulnerabilities(target, port)
            vulns.extend(rtsp_vulns)
        
        # Vulnerabilidades HTTP
        elif protocol == "http":
            http_vulns = await self._check_http_vulnerabilities(target, port)
            vulns.extend(http_vulns)
        
        # Vulnerabilidades de câmeras IP
        if "camera" in service.get("banner", "").lower() or "axis" in service.get("banner", "").lower():
            camera_vulns = await self._check_camera_vulnerabilities(target, port)
            vulns.extend(camera_vulns)
        
        return vulns
    
    async def _check_rtsp_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Verifica vulnerabilidades RTSP"""
        vulns = []
        
        try:
            # Testar acesso sem autenticação
            url = f"rtsp://{target}:{port}/"
            
            async with aiohttp.ClientSession() as session:
                # Tentar DESCRIBE sem autenticação
                headers = {
                    "CSeq": "1",
                    "User-Agent": "StreamScanner/2.0"
                }
                
                # Usar requests RTSP
                import base64
                
                # Testar métodos comuns
                methods = ["DESCRIBE", "OPTIONS", "SETUP"]
                
                for method in methods:
                    try:
                        # Criar requisição RTSP manual
                        request = f"{method} {url} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                        
                        reader, writer = await asyncio.open_connection(target, port)
                        writer.write(request.encode())
                        await writer.drain()
                        
                        response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                        response_text = response.decode('utf-8', errors='ignore')
                        
                        if "200 OK" in response_text:
                            if "WWW-Authenticate" not in response_text:
                                vulns.append({
                                    "severity": "high",
                                    "title": f"RTSP {method} Access Without Authentication",
                                    "description": f"RTSP server accepts {method} method without authentication",
                                    "remediation": "Enable RTSP authentication"
                                })
                        
                        writer.close()
                        await writer.wait_closed()
                        
                    except:
                        continue
                        
        except Exception as e:
            logger.debug(f"Erro ao verificar vulnerabilidades RTSP: {e}")
        
        return vulns
    
    async def _check_http_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Verifica vulnerabilidades HTTP"""
        vulns = []
        
        try:
            urls = [
                f"http://{target}:{port}/",
                f"http://{target}:{port}/config",
                f"http://{target}:{port}/admin",
                f"http://{target}:{port}/cgi-bin/"
            ]
            
            async with aiohttp.ClientSession() as session:
                for url in urls:
                    try:
                        async with session.get(url, timeout=5) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Verificar informações sensíveis
                                sensitive_patterns = [
                                    ("password", "Password found in page"),
                                    ("admin", "Admin interface accessible"),
                                    ("config", "Configuration file accessible"),
                                    ("backup", "Backup file accessible")
                                ]
                                
                                for pattern, description in sensitive_patterns:
                                    if pattern in content.lower():
                                        vulns.append({
                                            "severity": "medium",
                                            "title": f"Sensitive Information Exposure - {pattern}",
                                            "description": description,
                                            "remediation": "Restrict access to sensitive resources"
                                        })
                                        
                    except:
                        continue
                        
        except Exception as e:
            logger.debug(f"Erro ao verificar vulnerabilidades HTTP: {e}")
        
        return vulns
    
    async def _check_camera_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Verifica vulnerabilidades de câmeras IP"""
        vulns = []
        
        try:
            # URLs comuns de câmeras
            camera_urls = [
                f"http://{target}:{port}/viewer/video.mjpeg",
                f"http://{target}:{port}/img/video.mjpeg",
                f"http://{target}:{port}/video.mjpg",
                f"http://{target}:{port}/snapshot.cgi",
                f"http://{target}:{port}/videostream.cgi"
            ]
            
            async with aiohttp.ClientSession() as session:
                for url in camera_urls:
                    try:
                        async with session.get(url, timeout=5) as response:
                            if response.status == 200:
                                vulns.append({
                                    "severity": "high",
                                    "title": "Camera Accessible Without Authentication",
                                    "description": f"Camera stream accessible at {url}",
                                    "remediation": "Enable camera authentication"
                                })
                                
                    except:
                        continue
                        
        except Exception as e:
            logger.debug(f"Erro ao verificar vulnerabilidades de câmera: {e}")
        
        return vulns

# Web Application
class WebStreamHunter:
    """Aplicação web principal"""
    
    def __init__(self):
        self.app = Flask(__name__, 
                        template_folder=TEMPLATE_DIR,
                        static_folder=STATIC_DIR)
        self._setup_config()
        self._setup_extensions()
        self._setup_database()
        self._setup_scanner()
        self._setup_routes()
        self._setup_web_sockets()
        self._setup_background_tasks()
        
    def _setup_config(self):
        """Configura a aplicação"""
        # Carregar configuração
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
        else:
            config = DEFAULT_CONFIG
            with open(CONFIG_PATH, 'w') as f:
                json.dump(config, f, indent=4)
        
        # Configuração Flask
        web_config = config.get('web', {})
        self.app.config.update({
            'SECRET_KEY': web_config.get('secret_key', 'dev-key-change-in-production'),
            'SESSION_TYPE': 'filesystem',
            'SESSION_FILE_DIR': '/tmp/flask_session',
            'SESSION_PERMANENT': False,
            'SESSION_USE_SIGNER': True,
            'PERMANENT_SESSION_LIFETIME': timedelta(
                seconds=web_config.get('session_timeout', 3600)
            ),
            'MAX_CONTENT_LENGTH': web_config.get('max_upload_size', 100 * 1024 * 1024),
            'SQLALCHEMY_DATABASE_URI': f'sqlite:///{DB_PATH}',
            'SQLALCHEMY_TRACK_MODIFICATIONS': False
        })
        
        self.config = config
        
    def _setup_extensions(self):
        """Configura extensões Flask"""
        CORS(self.app)
        self.socketio = SocketIO(self.app, 
                                cors_allowed_origins="*",
                                async_mode='eventlet',
                                logger=True,
                                engineio_logger=True)
        
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        self.login_manager.login_view = 'login'
        
        @self.login_manager.user_loader
        def load_user(user_id):
            db_session = Session()
            user = db_session.query(User).get(int(user_id))
            db_session.close()
            return user
        
    def _setup_database(self):
        """Configura banco de dados"""
        global Session
        engine = create_engine(f'sqlite:///{DB_PATH}')
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        
        # Criar usuário admin padrão se não existir
        db_session = Session()
        if not db_session.query(User).filter_by(username='admin').first():
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('admin123')
            db_session.add(admin_user)
            db_session.commit()
        db_session.close()
        
    def _setup_scanner(self):
        """Inicializa o scanner"""
        self.scanner = AdvancedStreamScanner()
        self.active_scans = {}
        self.scan_results = {}
        
    def _setup_routes(self):
        """Configura rotas da aplicação"""
        
        @self.app.route('/')
        def index():
            if current_user.is_authenticated:
                return redirect(url_for('dashboard'))
            return redirect(url_for('login'))
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                
                db_session = Session()
                user = db_session.query(User).filter_by(username=username).first()
                
                if user and user.check_password(password) and user.active:
                    login_user(user)
                    user.last_login = datetime.utcnow()
                    db_session.commit()
                    db_session.close()
                    return redirect(url_for('dashboard'))
                
                db_session.close()
                return render_template('login.html', error='Credenciais inválidas')
            
            return render_template('login.html')
        
        @self.app.route('/logout')
        @login_required
        def logout():
            logout_user()
            return redirect(url_for('login'))
        
        @self.app.route('/dashboard')
        @login_required
        def dashboard():
            db_session = Session()
            
            # Estatísticas
            total_scans = db_session.query(ScanJob).count()
            total_streams = db_session.query(ScanResult).filter(
                ScanResult.stream_url.isnot(None)
            ).count()
            
            recent_scans = db_session.query(ScanJob).order_by(
                ScanJob.started_at.desc()
            ).limit(10).all()
            
            db_session.close()
            
            return render_template('dashboard.html',
                                 total_scans=total_scans,
                                 total_streams=total_streams,
                                 recent_scans=recent_scans)
        
        @self.app.route('/scan')
        @login_required
        def scan_page():
            return render_template('scan.html')
        
        @self.app.route('/api/scan/start', methods=['POST'])
        @login_required
        def start_scan():
            data = request.json
            target = data.get('target')
            ports = data.get('ports', '80,443,554,1935,8080,8000')
            scan_type = data.get('type', 'quick')
            
            if not target:
                return jsonify({'error': 'Target required'}), 400
            
            # Converter string de portas para lista
            port_list = []
            for part in ports.split(','):
                part = part.strip()
                if '-' in part:
                    try:
                        start, end = map(int, part.split('-'))
                        port_list.extend(range(start, end + 1))
                    except:
                        continue
                else:
                    try:
                        port_list.append(int(part))
                    except:
                        continue
            
            # Criar job no banco
            db_session = Session()
            scan_job = ScanJob(
                user_id=current_user.id,
                name=f"Scan {target} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
                target=target,
                ports=ports,
                scan_type=scan_type,
                status='pending',
                started_at=datetime.utcnow()
            )
            db_session.add(scan_job)
            db_session.commit()
            job_id = scan_job.id
            db_session.close()
            
            # Iniciar scan em background
            self._start_background_scan(job_id, target, port_list, scan_type)
            
            return jsonify({
                'job_id': job_id,
                'message': 'Scan started',
                'target': target
            })
        
        @self.app.route('/api/scan/status/<int:job_id>')
        @login_required
        def scan_status(job_id):
            db_session = Session()
            job = db_session.query(ScanJob).get(job_id)
            
            if not job:
                db_session.close()
                return jsonify({'error': 'Job not found'}), 404
            
            # Buscar resultados
            results = db_session.query(ScanResult).filter_by(scan_job_id=job_id).all()
            
            response = {
                'id': job.id,
                'name': job.name,
                'target': job.target,
                'status': job.status,
                'progress': job.progress,
                'results_count': job.results_count,
                'started_at': job.started_at.isoformat() if job.started_at else None,
                'completed_at': job.completed_at.isoformat() if job.completed_at else None,
                'error_message': job.error_message,
                'results': [
                    {
                        'id': r.id,
                        'ip': r.ip,
                        'port': r.port,
                        'protocol': r.protocol,
                        'service': r.service,
                        'stream_url': r.stream_url,
                        'resolution': r.resolution,
                        'bitrate': r.bitrate,
                        'quality_score': r.quality_score
                    }
                    for r in results
                ]
            }
            
            db_session.close()
            return jsonify(response)
        
        @self.app.route('/api/scan/results')
        @login_required
        def scan_results():
            db_session = Session()
            
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            
            # Query base
            query = db_session.query(ScanResult).filter(
                ScanResult.stream_url.isnot(None)
            )
            
            # Filtros
            if request.args.get('ip'):
                query = query.filter(ScanResult.ip.like(f"%{request.args.get('ip')}%"))
            
            if request.args.get('port'):
                query = query.filter(ScanResult.port == int(request.args.get('port')))
            
            if request.args.get('protocol'):
                query = query.filter(ScanResult.protocol == request.args.get('protocol'))
            
            # Paginação
            total = query.count()
            results = query.order_by(ScanResult.discovered_at.desc()).offset(
                (page - 1) * per_page
            ).limit(per_page).all()
            
            db_session.close()
            
            return jsonify({
                'total': total,
                'page': page,
                'per_page': per_page,
                'results': [
                    {
                        'id': r.id,
                        'ip': r.ip,
                        'port': r.port,
                        'protocol': r.protocol,
                        'stream_url': r.stream_url,
                        'codec_video': r.codec_video,
                        'resolution': r.resolution,
                        'bitrate': r.bitrate,
                        'quality_score': r.quality_score,
                        'discovered_at': r.discovered_at.isoformat()
                    }
                    for r in results
                ]
            })
        
        @self.app.route('/api/stream/play/<int:result_id>')
        @login_required
        def stream_play(result_id):
            db_session = Session()
            result = db_session.query(ScanResult).get(result_id)
            
            if not result or not result.stream_url:
                db_session.close()
                return jsonify({'error': 'Stream not found'}), 404
            
            # Gerar URL de proxy para o stream
            stream_url = result.stream_url
            
            # Para streams HTTP, podemos servir via proxy
            if stream_url.startswith('http'):
                # Implementar proxy de stream aqui
                pass
            
            db_session.close()
            
            return jsonify({
                'url': stream_url,
                'type': 'direct'  # ou 'proxy'
            })
        
        @self.app.route('/api/system/info')
        @login_required
        def system_info():
            # Informações do sistema
            system_info = {
                'hostname': socket.gethostname(),
                'os': platform.system(),
                'os_version': platform.version(),
                'python_version': platform.python_version(),
                'cpu_count': os.cpu_count(),
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent
                },
                'disk': {
                    'total': psutil.disk_usage('/').total,
                    'free': psutil.disk_usage('/').free,
                    'percent': psutil.disk_usage('/').percent
                },
                'network': self._get_network_info()
            }
            
            return jsonify(system_info)
        
        @self.app.route('/api/network/interfaces')
        @login_required
        def network_interfaces():
            interfaces = netifaces.interfaces()
            interface_info = []
            
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    interface_info.append({
                        'name': iface,
                        'ip': ip_info.get('addr'),
                        'netmask': ip_info.get('netmask'),
                        'broadcast': ip_info.get('broadcast')
                    })
            
            return jsonify(interface_info)
        
        @self.app.route('/player')
        @login_required
        def player_page():
            stream_url = request.args.get('url', '')
            return render_template('player.html', stream_url=stream_url)
        
        @self.app.route('/channels')
        @login_required
        def channels_page():
            return render_template('channels.html')
        
        @self.app.route('/vulnerabilities')
        @login_required
        def vulnerabilities_page():
            return render_template('vulnerabilities.html')
        
        @self.app.route('/settings')
        @login_required
        def settings_page():
            return render_template('settings.html')
        
        @self.app.route('/api/config', methods=['GET', 'PUT'])
        @login_required
        def config_api():
            if current_user.role != 'admin':
                return jsonify({'error': 'Permission denied'}), 403
            
            if request.method == 'GET':
                with open(CONFIG_PATH, 'r') as f:
                    config = json.load(f)
                return jsonify(config)
            
            elif request.method == 'PUT':
                new_config = request.json
                
                # Validar configuração
                if not isinstance(new_config, dict):
                    return jsonify({'error': 'Invalid configuration'}), 400
                
                # Salvar configuração
                with open(CONFIG_PATH, 'w') as f:
                    json.dump(new_config, f, indent=4)
                
                # Recarregar configuração
                self.config = new_config
                
                return jsonify({'message': 'Configuration updated'})
    
    def _setup_web_sockets(self):
        """Configura WebSockets para atualizações em tempo real"""
        
        @self.socketio.on('connect')
        def handle_connect():
            if current_user.is_authenticated:
                emit('connected', {'user': current_user.username})
            else:
                return False
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info(f'Client disconnected')
        
        @self.socketio.on('subscribe_scan')
        def handle_subscribe_scan(data):
            job_id = data.get('job_id')
            if job_id:
                # Adicionar cliente à sala do scan
                self.socketio.join_room(f'scan_{job_id}')
        
        @self.socketio.on('unsubscribe_scan')
        def handle_unsubscribe_scan(data):
            job_id = data.get('job_id')
            if job_id:
                # Remover cliente da sala do scan
                self.socketio.leave_room(f'scan_{job_id}')
    
    def _setup_background_tasks(self):
        """Configura tarefas em background"""
        
        def background_scan_updater():
            """Atualiza progresso de scans em background"""
            while True:
                try:
                    # Verificar scans ativos
                    for job_id in list(self.active_scans.keys()):
                        # Aqui você atualizaria o progresso via WebSocket
                        pass
                    
                    time.sleep(1)
                except Exception as e:
                    logger.error(f"Error in background scan updater: {e}")
                    time.sleep(5)
        
        # Iniciar thread de background
        thread = threading.Thread(target=background_scan_updater, daemon=True)
        thread.start()
    
    def _start_background_scan(self, job_id: int, target: str, ports: List[int], scan_type: str):
        """Inicia scan em background"""
        
        def scan_task():
            try:
                db_session = Session()
                job = db_session.query(ScanJob).get(job_id)
                
                if not job:
                    db_session.close()
                    return
                
                # Atualizar status para running
                job.status = 'running'
                job.started_at = datetime.utcnow()
                db_session.commit()
                
                # Notificar via WebSocket
                self.socketio.emit('scan_update', {
                    'job_id': job_id,
                    'status': 'running',
                    'progress': 0
                }, room=f'scan_{job_id}')
                
                # Executar scan
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                try:
                    results = loop.run_until_complete(
                        self.scanner.comprehensive_scan(target, ports)
                    )
                    
                    # Processar resultados
                    streams_found = 0
                    
                    for stream in results.get('streams', []):
                        # Salvar resultado no banco
                        scan_result = ScanResult(
                            scan_job_id=job_id,
                            ip=target,
                            port=stream.get('port', 0),
                            protocol=stream.get('protocol', ''),
                            service=stream.get('source_service', {}).get('service', ''),
                            stream_url=stream.get('discovery_url', ''),
                            stream_protocol=stream.get('protocol', ''),
                            codec_video=stream.get('video_info', {}).get('codec', ''),
                            resolution=stream.get('general_info', {}).get('resolution', ''),
                            bitrate=stream.get('format', {}).get('bit_rate', 0),
                            fps=stream.get('video_info', {}).get('fps', 0),
                            duration=stream.get('format', {}).get('duration', 0),
                            has_video=stream.get('general_info', {}).get('has_video', False),
                            has_audio=stream.get('general_info', {}).get('has_audio', False),
                            encrypted=False,  # Implementar detecção de encryption
                            quality_score=self._calculate_quality_score(stream)
                        )
                        
                        db_session.add(scan_result)
                        streams_found += 1
                    
                    # Atualizar job
                    job.status = 'completed'
                    job.progress = 100
                    job.results_count = streams_found
                    job.completed_at = datetime.utcnow()
                    db_session.commit()
                    
                    # Notificar conclusão
                    self.socketio.emit('scan_update', {
                        'job_id': job_id,
                        'status': 'completed',
                        'progress': 100,
                        'results_count': streams_found,
                        'message': f'Scan completed. Found {streams_found} streams.'
                    }, room=f'scan_{job_id}')
                    
                except Exception as e:
                    logger.error(f"Scan error: {e}")
                    
                    job.status = 'failed'
                    job.error_message = str(e)
                    job.completed_at = datetime.utcnow()
                    db_session.commit()
                    
                    self.socketio.emit('scan_update', {
                        'job_id': job_id,
                        'status': 'failed',
                        'error': str(e)
                    }, room=f'scan_{job_id}')
                    
                finally:
                    db_session.close()
                    loop.close()
                    
                    # Remover scan da lista ativa
                    if job_id in self.active_scans:
                        del self.active_scans[job_id]
                        
            except Exception as e:
                logger.error(f"Background scan task error: {e}")
        
        # Armazenar referência à thread
        thread = threading.Thread(target=scan_task, daemon=True)
        self.active_scans[job_id] = thread
        thread.start()
    
    def _calculate_quality_score(self, stream_info: Dict) -> int:
        """Calcula pontuação de qualidade do stream"""
        score = 0
        
        # Baseado na resolução
        resolution = stream_info.get('general_info', {}).get('resolution', '')
        if '3840' in resolution or '2160' in resolution:
            score += 40
        elif '1920' in resolution or '1080' in resolution:
            score += 30
        elif '1280' in resolution or '720' in resolution:
            score += 20
        elif '640' in resolution or '480' in resolution:
            score += 10
        
        # Baseado no bitrate
        bitrate = stream_info.get('format', {}).get('bit_rate', 0)
        if bitrate > 10000000:  # > 10 Mbps
            score += 30
        elif bitrate > 5000000:  # > 5 Mbps
            score += 20
        elif bitrate > 1000000:  # > 1 Mbps
            score += 10
        
        # Baseado no codec
        codec = stream_info.get('video_info', {}).get('codec', '').lower()
        if 'h265' in codec or 'hevc' in codec:
            score += 20
        elif 'h264' in codec or 'avc' in codec:
            score += 15
        elif 'vp9' in codec:
            score += 10
        
        return min(score, 100)
    
    def _get_network_info(self) -> Dict:
        """Obtém informações de rede"""
        info = {
            'interfaces': [],
            'gateway': None
        }
        
        try:
            # Interfaces de rede
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for iface, addrs in interfaces.items():
                iface_info = {
                    'name': iface,
                    'addresses': [],
                    'stats': {}
                }
                
                for addr in addrs:
                    iface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                
                if iface in stats:
                    stat = stats[iface]
                    iface_info['stats'] = {
                        'isup': stat.isup,
                        'speed': stat.speed,
                        'mtu': stat.mtu
                    }
                
                info['interfaces'].append(iface_info)
            
            # Gateway padrão
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                info['gateway'] = gateways['default'][netifaces.AF_INET][0]
                
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
        
        return info
    
    def run(self):
        """Executa a aplicação"""
        host = self.config['web'].get('host', '0.0.0.0')
        port = self.config['web'].get('port', 8080)
        debug = self.config['web'].get('debug', False)
        
        logger.info(f"Starting WebStream Hunter on {host}:{port}")
        
        if self.config['security'].get('enable_ssl', False):
            ssl_cert = self.config['security'].get('ssl_cert')
            ssl_key = self.config['security'].get('ssl_key')
            
            if ssl_cert and ssl_key and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
                self.socketio.run(self.app, 
                                 host=host, 
                                 port=port,
                                 debug=debug,
                                 certfile=ssl_cert,
                                 keyfile=ssl_key)
            else:
                logger.warning("SSL enabled but certificates not found. Using HTTP.")
                self.socketio.run(self.app, host=host, port=port, debug=debug)
        else:
            self.socketio.run(self.app, host=host, port=port, debug=debug)

# Templates HTML (serão salvas em arquivos separados)
def create_templates():
    """Cria templates HTML para a aplicação web"""
    
    templates_dir = TEMPLATE_DIR
    os.makedirs(templates_dir, exist_ok=True)
    
    # Base template
    base_html = '''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebStream Hunter - {% block title %}{% endblock %}</title>
    
    <!-- Bootstrap 5 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <!-- DataTables -->
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.11.5/css/dataTables.bootstrap5.min.css">
    
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
        
        .sidebar .nav-link {
            color: var(--text-color);
            padding: 12px 20px;
            margin: 2px 0;
            border-radius: 5px;
            transition: all 0.3s;
        }
        
        .sidebar .nav-link:hover {
            background-color: rgba(52, 152, 219, 0.2);
            color: var(--secondary-color);
        }
        
        .sidebar .nav-link.active {
            background-color: var(--secondary-color);
            color: white;
        }
        
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .card-header {
            background-color: rgba(0,0,0,0.2);
            border-bottom: 1px solid var(--border-color);
        }
        
        .btn-primary {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
        }
        
        .btn-primary:hover {
            background-color: #2980b9;
            border-color: #2980b9;
        }
        
        .btn-danger {
            background-color: var(--accent-color);
            border-color: var(--accent-color);
        }
        
        .stat-card {
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            background: linear-gradient(135deg, var(--card-bg), var(--darker-bg));
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card i {
            font-size: 2.5rem;
            margin-bottom: 15px;
        }
        
        .stat-card .number {
            font-size: 2rem;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-card .label {
            font-size: 0.9rem;
            color: #95a5a6;
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
        
        .table-dark {
            background-color: var(--darker-bg);
            color: var(--text-color);
        }
        
        .table-dark th {
            border-color: var(--border-color);
            background-color: rgba(0,0,0,0.3);
        }
        
        .table-dark td {
            border-color: var(--border-color);
        }
        
        .player-container {
            background-color: #000;
            border-radius: 10px;
            overflow: hidden;
            position: relative;
        }
        
        .player-controls {
            background-color: rgba(0,0,0,0.7);
            padding: 10px;
            position: absolute;
            bottom: 0;
            width: 100%;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .player-controls button {
            background: none;
            border: none;
            color: white;
            font-size: 1.2rem;
        }
        
        .toast {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-color);
        }
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
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <span class="nav-link">
                            <i class="fas fa-user me-1"></i>
                            {{ current_user.username }}
                        </span>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/settings">
                            <i class="fas fa-cog"></i>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">
                            <i class="fas fa-sign-out-alt"></i>
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-lg-2 col-md-3 sidebar py-3">
                <nav class="nav flex-column">
                    <a class="nav-link {% if request.path == '/dashboard' %}active{% endif %}" href="/dashboard">
                        <i class="fas fa-tachometer-alt me-2"></i> Dashboard
                    </a>
                    <a class="nav-link {% if request.path == '/scan' %}active{% endif %}" href="/scan">
                        <i class="fas fa-search me-2"></i> Scanner
                    </a>
                    <a class="nav-link {% if request.path == '/channels' %}active{% endif %}" href="/channels">
                        <i class="fas fa-list me-2"></i> Canais
                    </a>
                    <a class="nav-link {% if request.path == '/player' %}active{% endif %}" href="/player">
                        <i class="fas fa-play-circle me-2"></i> Player
                    </a>
                    <a class="nav-link {% if request.path == '/vulnerabilities' %}active{% endif %}" href="/vulnerabilities">
                        <i class="fas fa-shield-alt me-2"></i> Vulnerabilidades
                    </a>
                    <div class="mt-4">
                        <small class="text-muted">SISTEMA</small>
                    </div>
                    <a class="nav-link" href="/api/system/info" target="_blank">
                        <i class="fas fa-info-circle me-2"></i> Info do Sistema
                    </a>
                    <a class="nav-link" href="/api/network/interfaces" target="_blank">
                        <i class="fas fa-network-wired me-2"></i> Interfaces
                    </a>
                </nav>
                
                <div class="mt-5 p-3" style="background-color: rgba(0,0,0,0.2); border-radius: 8px;">
                    <small class="d-block text-muted mb-2">Status do Sistema</small>
                    <div class="d-flex justify-content-between small">
                        <span>CPU:</span>
                        <span id="cpu-usage">0%</span>
                    </div>
                    <div class="d-flex justify-content-between small">
                        <span>RAM:</span>
                        <span id="ram-usage">0%</span>
                    </div>
                    <div class="mt-2">
                        <small class="text-success">
                            <i class="fas fa-circle me-1"></i> Online
                        </small>
                    </div>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="col-lg-10 col-md-9 py-4">
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        {% for message in messages %}
                            <div class="alert alert-info alert-dismissible fade show" role="alert">
                                {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                {% block content %}{% endblock %}
            </div>
        </div>
    </div>
    
    <!-- Scripts -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.4.1/socket.io.min.js"></script>
    
    <!-- System Stats Updater -->
    <script>
        function updateSystemStats() {
            $.get('/api/system/info', function(data) {
                $('#cpu-usage').text(data.memory.percent.toFixed(1) + '%');
                $('#ram-usage').text(data.memory.percent.toFixed(1) + '%');
            });
        }
        
        // Update every 10 seconds
        setInterval(updateSystemStats, 10000);
        updateSystemStats();
    </script>
    
    {% block extra_js %}{% endblock %}
</body>
</html>'''
    
    with open(os.path.join(templates_dir, 'base.html'), 'w') as f:
        f.write(base_html)
    
    # Login template
    login_html = '''{% extends "base.html" %}

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
                {% if error %}
                <div class="alert alert-danger">
                    {{ error }}
                </div>
                {% endif %}
                
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
{% endblock %}'''
    
    with open(os.path.join(templates_dir, 'login.html'), 'w') as f:
        f.write(login_html)
    
    # Dashboard template
    dashboard_html = '''{% extends "base.html" %}

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
        <div class="stat-card">
            <i class="fas fa-search text-primary"></i>
            <div class="number" id="total-scans">{{ total_scans }}</div>
            <div class="label">Scans Realizados</div>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="stat-card">
            <i class="fas fa-satellite-dish text-success"></i>
            <div class="number" id="total-streams">{{ total_streams }}</div>
            <div class="label">Streams Encontrados</div>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="stat-card">
            <i class="fas fa-shield-alt text-warning"></i>
            <div class="number" id="total-vulns">0</div>
            <div class="label">Vulnerabilidades</div>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="stat-card">
            <i class="fas fa-bolt text-danger"></i>
            <div class="number" id="active-scans">0</div>
            <div class="label">Scans Ativos</div>
        </div>
    </div>
</div>

<!-- Quick Actions -->
<div class="row mb-4">
    <div class="col">
        <div class="card">
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
    </div>
</div>

<!-- Recent Scans -->
<div class="row">
    <div class="col">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-history me-2"></i>Scans Recentes
                </h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-dark table-hover" id="recent-scans-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Nome</th>
                                <th>Alvo</th>
                                <th>Status</th>
                                <th>Progresso</th>
                                <th>Resultados</th>
                                <th>Início</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for scan in recent_scans %}
                            <tr>
                                <td>{{ scan.id }}</td>
                                <td>{{ scan.name }}</td>
                                <td>{{ scan.target|truncate(20) }}</td>
                                <td>
                                    {% if scan.status == 'completed' %}
                                        <span class="badge bg-success">Concluído</span>
                                    {% elif scan.status == 'running' %}
                                        <span class="badge bg-primary">Executando</span>
                                    {% elif scan.status == 'failed' %}
                                        <span class="badge bg-danger">Falhou</span>
                                    {% else %}
                                        <span class="badge bg-secondary">{{ scan.status }}</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <div class="scan-progress">
                                        <div class="scan-progress-bar" style="width: {{ scan.progress }}%"></div>
                                    </div>
                                    <small>{{ scan.progress|round(1) }}%</small>
                                </td>
                                <td>{{ scan.results_count }}</td>
                                <td>{{ scan.started_at.strftime('%H:%M') if scan.started_at else '' }}</td>
                                <td>
                                    {% if scan.status == 'completed' and scan.results_count > 0 %}
                                    <a href="/channels?scan={{ scan.id }}" class="btn btn-sm btn-success">
                                        <i class="fas fa-eye"></i>
                                    </a>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- System Info -->
<div class="row mt-4">
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
                    <div class="col-6">
                        <small class="text-muted">Rede</small>
                        <div class="mt-2">
                            <small id="network-status">
                                <i class="fas fa-wifi text-success me-1"></i>Online
                            </small>
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
    // Initialize DataTable
    $('#recent-scans-table').DataTable({
        pageLength: 5,
        order: [[0, 'desc']]
    });
    
    // Quick scan button
    $('#quick-scan').click(function() {
        window.location.href = '/scan';
    });
    
    // Update system info
    function updateSystemInfo() {
        $.get('/api/system/info', function(data) {
            // System stats
            $('#cpu-progress-bar').css('width', data.memory.percent + '%');
            $('#ram-progress-bar').css('width', data.memory.percent + '%');
            $('#disk-progress-bar').css('width', data.disk.percent + '%');
            
            // System info
            $('#hostname').text(data.hostname);
            $('#os-name').text(data.os + ' ' + data.os_version);
            $('#python-version').text(data.python_version);
            $('#cpu-cores').text(data.cpu_count);
        });
    }
    
    // Update every 5 seconds
    setInterval(updateSystemInfo, 5000);
    updateSystemInfo();
    
    // Socket.io for real-time updates
    const socket = io();
    
    socket.on('scan_update', function(data) {
        // Update active scans count
        if (data.status === 'running') {
            $('#active-scans').text(parseInt($('#active-scans').text()) + 1);
        } else if (data.status === 'completed' || data.status === 'failed') {
            $('#active-scans').text(Math.max(0, parseInt($('#active-scans').text()) - 1));
        }
        
        // Show notification
        showToast(data.message || 'Scan ' + data.status, data.status);
    });
    
    function showToast(message, type) {
        // Create toast element
        const toast = $(`
            <div class="toast align-items-center text-white bg-${type === 'error' ? 'danger' : 'success'} border-0"
                 role="alert" aria-live="assertive" aria-atomic="true">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'check-circle'} me-2"></i>
                        ${message}
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `);
        
        // Add to container and show
        $('.toast-container').append(toast);
        const bsToast = new bootstrap.Toast(toast[0]);
        bsToast.show();
        
        // Remove after hide
        toast.on('hidden.bs.toast', function() {
            $(this).remove();
        });
    }
});
</script>
{% endblock %}'''
    
    with open(os.path.join(templates_dir, 'dashboard.html'), 'w') as f:
        f.write(dashboard_html)
    
    # Scan template
    scan_html = '''{% extends "base.html" %}

{% block title %}Scanner - WebStream Hunter{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col">
        <h2>
            <i class="fas fa-search me-2"></i>Scanner de Streams
        </h2>
        <p class="text-muted">Encontre streams MPEG-TS em sua rede</p>
    </div>
</div>

<div class="row">
    <!-- Scan Configuration -->
    <div class="col-md-4">
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-cog me-2"></i>Configuração do Scan
                </h5>
            </div>
            <div class="card-body">
                <form id="scan-form">
                    <div class="mb-3">
                        <label for="target" class="form-label">Alvo</label>
                        <div class="input-group">
                            <span class="input-group-text">
                                <i class="fas fa-bullseye"></i>
                            </span>
                            <input type="text" class="form-control" id="target" 
                                   placeholder="192.168.1.0/24 ou 192.168.1.1" 
                                   value="192.168.1.0/24" required>
                        </div>
                        <small class="text-muted">
                            IP único, range (192.168.1.1-100) ou CIDR (192.168.1.0/24)
                        </small>
                    </div>
                    
                    <div class="mb-3">
                        <label for="ports" class="form-label">Portas</label>
                        <div class="input-group">
                            <span class="input-group-text">
                                <i class="fas fa-door-open"></i>
                            </span>
                            <input type="text" class="form-control" id="ports" 
                                   value="80,443,554,1935,8080,8000,8001,8002,8003,8004,8005,9000,10000" required>
                        </div>
                        <small class="text-muted">
                            Lista de portas ou range (ex: 80,443,1000-2000)
                        </small>
                    </div>
                    
                    <div class="mb-3">
                        <label for="scan-type" class="form-label">Tipo de Scan</label>
                        <select class="form-select" id="scan-type">
                            <option value="quick">Rápido (portas comuns)</option>
                            <option value="deep">Profundo (todas as portas)</option>
                            <option value="stealth">Stealth (modo furtivo)</option>
                            <option value="service">Detecção de Serviços</option>
                            <option value="vulnerability">Scan de Vulnerabilidades</option>
                        </select>
                    </div>
                    
                    <div class="mb-3">
                        <label for="threads" class="form-label">Threads</label>
                        <input type="range" class="form-range" id="threads" min="1" max="200" value="50">
                        <div class="d-flex justify-content-between">
                            <small>1</small>
                            <small id="threads-value">50</small>
                            <small>200</small>
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <label for="timeout" class="form-label">Timeout (segundos)</label>
                        <input type="range" class="form-range" id="timeout" min="1" max="30" value="5">
                        <div class="d-flex justify-content-between">
                            <small>1s</small>
                            <small id="timeout-value">5s</small>
                            <small>30s</small>
                        </div>
                    </div>
                    
                    <div class="d-grid gap-2">
                        <button type="submit" class="btn btn-primary btn-lg" id="start-scan">
                            <i class="fas fa-play me-2"></i>Iniciar Scan
                        </button>
                        <button type="button" class="btn btn-danger" id="stop-scan" disabled>
                            <i class="fas fa-stop me-2"></i>Parar Scan
                        </button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Presets -->
        <div class="card">
            <div class="card-header">
                <h6 class="mb-0">
                    <i class="fas fa-bolt me-2"></i>Presets Rápidos
                </h6>
            </div>
            <div class="card-body">
                <div class="row g-2">
                    <div class="col-6">
                        <button class="btn btn-outline-primary w-100 preset-btn" 
                                data-target="192.168.1.0/24" 
                                data-ports="80,443,554,1935,8080">
                            Rede Local
                        </button>
                    </div>
                    <div class="col-6">
                        <button class="btn btn-outline-success w-100 preset-btn"
                                data-target="192.168.1.1-254"
                                data-ports="554,1935">
                            Câmeras IP
                        </button>
                    </div>
                    <div class="col-6">
                        <button class="btn btn-outline-warning w-100 preset-btn"
                                data-target="192.168.1.1"
                                data-ports="1-10000">
                            Host Completo
                        </button>
                    </div>
                    <div class="col-6">
                        <button class="btn btn-outline-info w-100 preset-btn"
                                data-target="10.0.0.0/24"
                                data-ports="80,8080,8000-9000">
                            Rede Interna
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Scan Progress & Results -->
    <div class="col-md-8">
        <!-- Active Scan -->
        <div class="card mb-4" id="active-scan-card" style="display: none;">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-sync-alt fa-spin me-2"></i>
                    <span id="scan-title">Scan em Execução</span>
                </h5>
            </div>
            <div class="card-body">
                <div class="mb-3">
                    <div class="d-flex justify-content-between mb-1">
                        <small>Progresso</small>
                        <small id="scan-progress-text">0%</small>
                    </div>
                    <div class="scan-progress">
                        <div class="scan-progress-bar" id="scan-progress-bar" style="width: 0%"></div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <small class="text-muted d-block">Alvo</small>
                        <strong id="current-target">-</strong>
                    </div>
                    <div class="col-md-6">
                        <small class="text-muted d-block">Portas</small>
                        <strong id="current-ports">-</strong>
                    </div>
                </div>
                
                <div class="row mt-3">
                    <div class="col-md-4">
                        <small class="text-muted d-block">Portas Encontradas</small>
                        <h4 id="open-ports-count">0</h4>
                    </div>
                    <div class="col-md-4">
                        <small class="text-muted d-block">Streams Encontrados</small>
                        <h4 id="streams-found-count">0</h4>
                    </div>
                    <div class="col-md-4">
                        <small class="text-muted d-block">Tempo Decorrido</small>
                        <h4 id="elapsed-time">0s</h4>
                    </div>
                </div>
                
                <div class="mt-3" id="scan-messages">
                    <!-- Messages will appear here -->
                </div>
            </div>
        </div>
        
        <!-- Results Table -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-list me-2"></i>Resultados
                </h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-dark table-hover" id="results-table">
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Porta</th>
                                <th>Protocolo</th>
                                <th>Serviço</th>
                                <th>Stream URL</th>
                                <th>Resolução</th>
                                <th>Qualidade</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Results will be populated here -->
                        </tbody>
                    </table>
                </div>
                
                <div class="mt-3 text-end">
                    <button class="btn btn-success" id="export-results">
                        <i class="fas fa-download me-2"></i>Exportar Resultados
                    </button>
                    <button class="btn btn-info" id="clear-results">
                        <i class="fas fa-trash me-2"></i>Limpar Tabela
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Toast Container -->
<div class="toast-container position-fixed bottom-0 end-0 p-3"></div>

{% endblock %}

{% block extra_js %}
<script>
$(document).ready(function() {
    const socket = io();
    let currentScanId = null;
    let scanStartTime = null;
    let scanTimer = null;
    
    // Update range values
    $('#threads').on('input', function() {
        $('#threads-value').text($(this).val());
    });
    
    $('#timeout').on('input', function() {
        $('#timeout-value').text($(this).val() + 's');
    });
    
    // Preset buttons
    $('.preset-btn').click(function() {
        $('#target').val($(this).data('target'));
        $('#ports').val($(this).data('ports'));
    });
    
    // Start scan
    $('#scan-form').submit(function(e) {
        e.preventDefault();
        
        const target = $('#target').val();
        const ports = $('#ports').val();
        const scanType = $('#scan-type').val();
        const threads = $('#threads').val();
        const timeout = $('#timeout').val();
        
        // Disable form
        $('#start-scan').prop('disabled', true);
        $('#stop-scan').prop('disabled', false);
        
        // Show active scan card
        $('#active-scan-card').show();
        $('#current-target').text(target);
        $('#current-ports').text(ports);
        scanStartTime = Date.now();
        
        // Start timer
        if (scanTimer) clearInterval(scanTimer);
        scanTimer = setInterval(updateElapsedTime, 1000);
        updateElapsedTime();
        
        // Start scan via API
        $.ajax({
            url: '/api/scan/start',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                target: target,
                ports: ports,
                type: scanType,
                threads: threads,
                timeout: timeout
            }),
            success: function(response) {
                currentScanId = response.job_id;
                
                // Subscribe to scan updates
                socket.emit('subscribe_scan', { job_id: currentScanId });
                
                // Update title
                $('#scan-title').html(`
                    <i class="fas fa-sync-alt fa-spin me-2"></i>
                    Scan #${currentScanId} em Execução
                `);
                
                // Start polling for updates
                pollScanStatus();
            },
            error: function(xhr) {
                showToast('Erro ao iniciar scan: ' + xhr.responseText, 'error');
                resetScanForm();
            }
        });
    });
    
    // Stop scan
    $('#stop-scan').click(function() {
        if (!currentScanId) return;
        
        // TODO: Implement scan stop API
        showToast('Parando scan...', 'warning');
        resetScanForm();
    });
    
    // Poll scan status
    function pollScanStatus() {
        if (!currentScanId) return;
        
        $.get('/api/scan/status/' + currentScanId, function(data) {
            // Update progress
            $('#scan-progress-bar').css('width', data.progress + '%');
            $('#scan-progress-text').text(data.progress.toFixed(1) + '%');
            
            // Update counts
            $('#open-ports-count').text(data.results_count || 0);
            $('#streams-found-count').text(data.results.filter(r => r.stream_url).length);
            
            // Update results table
            updateResultsTable(data.results);
            
            // Add messages
            if (data.status === 'running') {
                addScanMessage('Scan em andamento...', 'info');
            }
            
            // Check if scan is complete
            if (data.status === 'completed' || data.status === 'failed') {
                if (data.status === 'completed') {
                    showToast('Scan concluído! ' + data.results_count + ' resultados encontrados.', 'success');
                    addScanMessage('Scan concluído com sucesso!', 'success');
                } else {
                    showToast('Scan falhou: ' + data.error_message, 'error');
                    addScanMessage('Scan falhou: ' + data.error_message, 'error');
                }
                
                resetScanForm();
            } else {
                // Continue polling
                setTimeout(pollScanStatus, 2000);
            }
        }).fail(function() {
            setTimeout(pollScanStatus, 5000);
        });
    }
    
    // Update results table
    function updateResultsTable(results) {
        const tbody = $('#results-table tbody');
        tbody.empty();
        
        results.forEach(function(result) {
            if (!result.stream_url) return;
            
            const qualityClass = result.quality_score >= 70 ? 'quality-hd' : 
                                result.quality_score >= 40 ? 'quality-sd' : 'quality-low';
            
            const row = $(`
                <tr>
                    <td>${result.ip}</td>
                    <td>${result.port}</td>
                    <td>${result.protocol}</td>
                    <td>${result.service || '-'}</td>
                    <td>
                        <a href="${result.stream_url}" target="_blank" class="text-info">
                            ${result.stream_url.substring(0, 30)}...
                        </a>
                    </td>
                    <td>${result.resolution || '-'}</td>
                    <td>
                        <span class="stream-quality-badge ${qualityClass}">
                            ${result.quality_score || 0}/100
                        </span>
                    </td>
                    <td>
                        <button class="btn btn-sm btn-success play-stream" 
                                data-url="${result.stream_url}">
                            <i class="fas fa-play"></i>
                        </button>
                        <button class="btn btn-sm btn-info view-details"
                                data-id="${result.id}">
                            <i class="fas fa-info-circle"></i>
                        </button>
                    </td>
                </tr>
            `);
            
            tbody.append(row);
        });
        
        // Initialize DataTable if not already
        if (!$.fn.DataTable.isDataTable('#results-table')) {
            $('#results-table').DataTable({
                pageLength: 10,
                order: [[0, 'desc']]
            });
        }
    }
    
    // Add scan message
    function addScanMessage(text, type) {
        const message = $(`
            <div class="alert alert-${type} alert-dismissible fade show" role="alert">
                <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'info-circle'} me-2"></i>
                ${text}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `);
        
        $('#scan-messages').prepend(message);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            message.alert('close');
        }, 5000);
    }
    
    // Update elapsed time
    function updateElapsedTime() {
        if (!scanStartTime) return;
        
        const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
        $('#elapsed-time').text(elapsed + 's');
    }
    
    // Reset scan form
    function resetScanForm() {
        $('#start-scan').prop('disabled', false);
        $('#stop-scan').prop('disabled', true);
        
        if (scanTimer) {
            clearInterval(scanTimer);
            scanTimer = null;
        }
        
        if (currentScanId) {
            socket.emit('unsubscribe_scan', { job_id: currentScanId });
            currentScanId = null;
        }
        
        // Hide active scan card after 5 seconds
        setTimeout(() => {
            $('#active-scan-card').hide();
        }, 5000);
    }
    
    // Play stream
    $(document).on('click', '.play-stream', function() {
        const url = $(this).data('url');
        window.open('/player?url=' + encodeURIComponent(url), '_blank');
    });
    
    // View details
    $(document).on('click', '.view-details', function() {
        const id = $(this).data('id');
        // TODO: Show stream details modal
        alert('Detalhes do stream #' + id);
    });
    
    // Export results
    $('#export-results').click(function() {
        // TODO: Implement export
        alert('Exportar resultados');
    });
    
    // Clear results
    $('#clear-results').click(function() {
        if (confirm('Limpar todos os resultados?')) {
            $('#results-table').DataTable().clear().draw();
        }
    });
    
    // Show toast
    function showToast(message, type) {
        const toast = $(`
            <div class="toast align-items-center text-white bg-${type === 'error' ? 'danger' : 'success'} border-0"
                 role="alert" aria-live="assertive" aria-atomic="true">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'check-circle'} me-2"></i>
                        ${message}
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `);
        
        $('.toast-container').append(toast);
        const bsToast = new bootstrap.Toast(toast[0]);
        bsToast.show();
        
        toast.on('hidden.bs.toast', function() {
            $(this).remove();
        });
    }
    
    // Socket.io for real-time updates
    socket.on('scan_update', function(data) {
        if (data.job_id === currentScanId) {
            addScanMessage(data.message || 'Update received', 'info');
        }
    });
});
</script>
{% endblock %}'''
    
    with open(os.path.join(templates_dir, 'scan.html'), 'w') as f:
        f.write(scan_html)
    
    # Create other templates
    templates = {
        'player.html': '''{% extends "base.html" %}

{% block title %}Player - WebStream Hunter{% endblock %}

{% block extra_css %}
<style>
    #video-player {
        width: 100%;
        height: 70vh;
        background-color: #000;
    }
    
    .channel-list {
        max-height: 70vh;
        overflow-y: auto;
    }
    
    .channel-item {
        padding: 10px;
        border-bottom: 1px solid var(--border-color);
        cursor: pointer;
        transition: background-color 0.2s;
    }
    
    .channel-item:hover {
        background-color: rgba(52, 152, 219, 0.1);
    }
    
    .channel-item.active {
        background-color: rgba(52, 152, 219, 0.2);
        border-left: 3px solid var(--secondary-color);
    }
</style>
{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col">
        <h2>
            <i class="fas fa-play-circle me-2"></i>Player de Streams
        </h2>
        <p class="text-muted">Reproduza streams encontrados pelo scanner</p>
    </div>
</div>

<div class="row">
    <!-- Player -->
    <div class="col-lg-9">
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-tv me-2"></i>
                    <span id="current-channel">Selecione um canal</span>
                </h5>
            </div>
            <div class="card-body p-0">
                <div id="video-player">
                    <!-- Video player will be embedded here -->
                    <div class="d-flex justify-content-center align-items-center h-100">
                        <div class="text-center">
                            <i class="fas fa-play-circle fa-4x text-secondary mb-3"></i>
                            <h4>Nenhum stream selecionado</h4>
                            <p class="text-muted">Selecione um canal da lista ao lado</p>
                        </div>
                    </div>
                </div>
                
                <div class="player-controls">
                    <button class="btn btn-sm btn-primary" id="play-btn">
                        <i class="fas fa-play"></i>
                    </button>
                    <button class="btn btn-sm btn-secondary" id="pause-btn">
                        <i class="fas fa-pause"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" id="stop-btn">
                        <i class="fas fa-stop"></i>
                    </button>
                    
                    <div class="ms-auto">
                        <input type="text" class="form-control form-control-sm d-inline-block w-auto" 
                               id="stream-url" placeholder="Cole uma URL de stream">
                        <button class="btn btn-sm btn-success" id="load-url">
                            <i class="fas fa-sync-alt"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Stream Info -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-info-circle me-2"></i>Informações do Stream
                </h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <small class="text-muted d-block">URL</small>
                        <code id="info-url">-</code>
                    </div>
                    <div class="col-md-3">
                        <small class="text-muted d-block">Protocolo</small>
                        <strong id="info-protocol">-</strong>
                    </div>
                    <div class="col-md-3">
                        <small class="text-muted d-block">Codec</small>
                        <strong id="info-codec">-</strong>
                    </div>
                </div>
                
                <div class="row mt-3">
                    <div class="col-md-3">
                        <small class="text-muted d-block">Resolução</small>
                        <strong id="info-resolution">-</strong>
                    </div>
                    <div class="col-md-3">
                        <small class="text-muted d-block">Bitrate</small>
                        <strong id="info-bitrate">-</strong>
                    </div>
                    <div class="col-md-3">
                        <small class="text-muted d-block">FPS</small>
                        <strong id="info-fps">-</strong>
                    </div>
                    <div class="col-md-3">
                        <small class="text-muted d-block">Qualidade</small>
                        <strong id="info-quality">-</strong>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Channel List -->
    <div class="col-lg-3">
        <div class="card">
            <div class="card-header">
                <div class="d-flex justify-content-between align-items-center">
                    <h6 class="mb-0">
                        <i class="fas fa-list me-2"></i>Canais
                    </h6>
                    <button class="btn btn-sm btn-primary" id="refresh-channels">
                        <i class="fas fa-sync-alt"></i>
                    </button>
                </div>
            </div>
            <div class="card-body p-0">
                <div class="channel-list">
                    <!-- Channels will be loaded here -->
                    <div class="text-center py-4">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">Carregando...</span>
                        </div>
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
    let currentPlayer = null;
    let currentStreamUrl = null;
    
    // Load channels
    function loadChannels() {
        $('.channel-list').html(`
            <div class="text-center py-4">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Carregando...</span>
                </div>
            </div>
        `);
        
        $.get('/api/scan/results', function(data) {
            if (data.results.length === 0) {
                $('.channel-list').html(`
                    <div class="text-center py-4">
                        <i class="fas fa-satellite-dish fa-2x text-muted mb-3"></i>
                        <p class="text-muted">Nenhum canal encontrado</p>
                    </div>
                `);
                return;
            }
            
            let html = '';
            data.results.forEach(function(channel, index) {
                const qualityClass = channel.quality_score >= 70 ? 'quality-hd' : 
                                   channel.quality_score >= 40 ? 'quality-sd' : 'quality-low';
                
                html += `
                    <div class="channel-item" data-url="${channel.stream_url}" data-index="${index}">
                        <div class="d-flex justify-content-between">
                            <strong>${channel.ip}:${channel.port}</strong>
                            <span class="stream-quality-badge ${qualityClass}">
                                ${channel.quality_score}/100
                            </span>
                        </div>
                        <small class="text-muted d-block">${channel.protocol} • ${channel.resolution || 'N/A'}</small>
                        <small class="d-block text-truncate">${channel.stream_url.substring(0, 40)}...</small>
                    </div>
                `;
            });
            
            $('.channel-list').html(html);
            
            // Select first channel by default
            if (data.results.length > 0) {
                selectChannel(0, data.results[0]);
            }
        });
    }
    
    // Select channel
    function selectChannel(index, channel) {
        $('.channel-item').removeClass('active');
        $(`.channel-item[data-index="${index}"]`).addClass('active');
        
        $('#current-channel').text(`${channel.ip}:${channel.port}`);
        $('#stream-url').val(channel.stream_url);
        
        // Update info
        $('#info-url').text(channel.stream_url.substring(0, 50) + '...');
        $('#info-protocol').text(channel.protocol);
        $('#info-codec').text(channel.codec_video || 'N/A');
        $('#info-resolution').text(channel.resolution || 'N/A');
        $('#info-bitrate').text(channel.bitrate ? Math.round(channel.bitrate / 1000) + ' kbps' : 'N/A');
        $('#info-quality').html(`
            <span class="stream-quality-badge ${channel.quality_score >= 70 ? 'quality-hd' : 
                                                 channel.quality_score >= 40 ? 'quality-sd' : 'quality-low'}">
                ${channel.quality_score}/100
            </span>
        `);
        
        // Load stream
        loadStream(channel.stream_url);
    }
    
    // Load stream
    function loadStream(url) {
        currentStreamUrl = url;
        
        // Stop current player
        if (currentPlayer) {
            currentPlayer.dispose();
            currentPlayer = null;
        }
        
        // Clear player area
        $('#video-player').html(`
            <div class="d-flex justify-content-center align-items-center h-100">
                <div class="text-center">
                    <div class="spinner-border text-primary mb-3" role="status">
                        <span class="visually-hidden">Carregando...</span>
                    </div>
                    <p>Carregando stream...</p>
                </div>
            </div>
        `);
        
        // Try to play with different methods
        setTimeout(() => {
            tryPlayStream(url);
        }, 1000);
    }
    
    // Try to play stream
    function tryPlayStream(url) {
        // Method 1: Use video.js if HLS/m3u8
        if (url.includes('.m3u8') || url.includes('hls')) {
            setupHLSPlayer(url);
        }
        // Method 2: Use video tag for direct video
        else if (url.includes('.mp4') || url.includes('.webm') || url.includes('.ogg')) {
            setupHTML5Player(url);
        }
        // Method 3: Use iframe for other streams
        else {
            setupIFramePlayer(url);
        }
    }
    
    // Setup HLS player
    function setupHLSPlayer(url) {
        $('#video-player').html(`
            <video id="hls-player" class="video-js vjs-default-skin" controls preload="auto" width="100%" height="100%">
                <source src="${url}" type="application/x-mpegURL">
            </video>
        `);
        
        // Load video.js if not already loaded
        if (typeof videojs === 'undefined') {
            $('head').append(`
                <link href="https://vjs.zencdn.net/7.20.3/video-js.css" rel="stylesheet">
                <script src="https://vjs.zencdn.net/7.20.3/video.min.js"><\/script>
                <script src="https://cdn.jsdelivr.net/npm/videojs-contrib-hls@5.15.0/dist/videojs-contrib-hls.min.js"><\/script>
            `);
            
            // Wait for video.js to load
            setTimeout(() => {
                currentPlayer = videojs('hls-player');
            }, 1000);
        } else {
            currentPlayer = videojs('hls-player');
        }
    }
    
    // Setup HTML5 player
    function setupHTML5Player(url) {
        $('#video-player').html(`
            <video id="html5-player" controls width="100%" height="100%">
                <source src="${url}" type="video/mp4">
                Seu navegador não suporta a tag de vídeo.
            </video>
        `);
        
        currentPlayer = document.getElementById('html5-player');
    }
    
    // Setup iframe player
    function setupIFramePlayer(url) {
        $('#video-player').html(`
            <iframe id="iframe-player" src="${url}" width="100%" height="100%" 
                    frameborder="0" allowfullscreen></iframe>
        `);
        
        currentPlayer = document.getElementById('iframe-player');
    }
    
    // Play button
    $('#play-btn').click(function() {
        if (currentPlayer) {
            if (currentPlayer.play) {
                currentPlayer.play();
            }
        }
    });
    
    // Pause button
    $('#pause-btn').click(function() {
        if (currentPlayer) {
            if (currentPlayer.pause) {
                currentPlayer.pause();
            }
        }
    });
    
    // Stop button
    $('#stop-btn').click(function() {
        if (currentPlayer) {
            if (currentPlayer.pause) {
                currentPlayer.pause();
                if (currentPlayer.currentTime) {
                    currentPlayer.currentTime = 0;
                }
            }
        }
    });
    
    // Load URL
    $('#load-url').click(function() {
        const url = $('#stream-url').val();
        if (url) {
            loadStream(url);
        }
    });
    
    // Refresh channels
    $('#refresh-channels').click(loadChannels);
    
    // Channel click
    $(document).on('click', '.channel-item', function() {
        const index = $(this).data('index');
        const url = $(this).data('url');
        
        // Get channel data from API
        $.get('/api/scan/results', function(data) {
            if (data.results[index]) {
                selectChannel(index, data.results[index]);
            }
        });
    });
    
    // Load channels on page load
    loadChannels();
});
</script>
{% endblock %}''',
        
        'channels.html': '''{% extends "base.html" %}

{% block title %}Canais - WebStream Hunter{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col">
        <h2>
            <i class="fas fa-list me-2"></i>Canais Encontrados
        </h2>
        <p class="text-muted">Todos os streams MPEG-TS descobertos</p>
    </div>
</div>

<!-- Filters -->
<div class="card mb-4">
    <div class="card-body">
        <div class="row g-3">
            <div class="col-md-3">
                <label class="form-label">IP</label>
                <input type="text" class="form-control" id="filter-ip" placeholder="Filtrar por IP">
            </div>
            <div class="col-md-2">
                <label class="form-label">Porta</label>
                <input type="number" class="form-control" id="filter-port" placeholder="Porta">
            </div>
            <div class="col-md-2">
                <label class="form-label">Protocolo</label>
                <select class="form-select" id="filter-protocol">
                    <option value="">Todos</option>
                    <option value="http">HTTP</option>
                    <option value="rtsp">RTSP</option>
                    <option value="rtmp">RTMP</option>
                    <option value="udp">UDP</option>
                </select>
            </div>
            <div class="col-md-2">
                <label class="form-label">Qualidade</label>
                <select class="form-select" id="filter-quality">
                    <option value="">Todas</option>
                    <option value="high">Alta (70-100)</option>
                    <option value="medium">Média (40-70)</option>
                    <option value="low">Baixa (0-40)</option>
                </select>
            </div>
            <div class="col-md-3">
                <label class="form-label">&nbsp;</label>
                <div class="d-grid">
                    <button class="btn btn-primary" id="apply-filters">
                        <i class="fas fa-filter me-2"></i>Aplicar Filtros
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Channels Table -->
<div class="card">
    <div class="card-header">
        <div class="d-flex justify-content-between align-items-center">
            <h5 class="mb-0">
                <i class="fas fa-satellite-dish me-2"></i>
                <span id="channels-count">0</span> Canais
            </h5>
            <div>
                <button class="btn btn-sm btn-success" id="refresh-channels">
                    <i class="fas fa-sync-alt me-1"></i>Atualizar
                </button>
                <button class="btn btn-sm btn-info" id="export-channels">
                    <i class="fas fa-download me-1"></i>Exportar
                </button>
            </div>
        </div>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-dark table-hover" id="channels-table">
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Porta</th>
                        <th>Protocolo</th>
                        <th>URL</th>
                        <th>Codec</th>
                        <th>Resolução</th>
                        <th>Bitrate</th>
                        <th>Qualidade</th>
                        <th>Descoberto</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    <!-- Channels will be loaded here -->
                </tbody>
            </table>
        </div>
        
        <!-- Pagination -->
        <nav aria-label="Page navigation" class="mt-3">
            <ul class="pagination justify-content-center" id="pagination">
                <!-- Pagination will be generated here -->
            </ul>
        </nav>
    </div>
</div>

<!-- Channel Details Modal -->
<div class="modal fade" id="channelModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content bg-dark">
            <div class="modal-header">
                <h5 class="modal-title">Detalhes do Canal</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="channel-details">
                    <!-- Details will be loaded here -->
                </div>
            </div>
        </div>
    </div>
</div>

{% endblock %}

{% block extra_js %}
<script>
$(document).ready(function() {
    let currentPage = 1;
    let perPage = 20;
    let totalChannels = 0;
    
    // Load channels
    function loadChannels(page = 1) {
        currentPage = page;
        
        // Build query string
        let query = `?page=${page}&per_page=${perPage}`;
        
        const ip = $('#filter-ip').val();
        const port = $('#filter-port').val();
        const protocol = $('#filter-protocol').val();
        const quality = $('#filter-quality').val();
        
        if (ip) query += `&ip=${encodeURIComponent(ip)}`;
        if (port) query += `&port=${port}`;
        if (protocol) query += `&protocol=${protocol}`;
        if (quality) {
            let min = 0, max = 100;
            if (quality === 'high') { min = 70; max = 100; }
            else if (quality === 'medium') { min = 40; max = 70; }
            else if (quality === 'low') { min = 0; max = 40; }
            // Note: API needs to support quality range filtering
        }
        
        // Show loading
        $('#channels-table tbody').html(`
            <tr>
                <td colspan="10" class="text-center py-4">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Carregando...</span>
                    </div>
                </td>
            </tr>
        `);
        
        $.get('/api/scan/results' + query, function(data) {
            totalChannels = data.total;
            $('#channels-count').text(totalChannels);
            
            // Update table
            let html = '';
            data.results.forEach(function(channel) {
                const qualityClass = channel.quality_score >= 70 ? 'quality-hd' : 
                                   channel.quality_score >= 40 ? 'quality-sd' : 'quality-low';
                
                const discovered = new Date(channel.discovered_at);
                const dateStr = discovered.toLocaleDateString('pt-BR');
                const timeStr = discovered.toLocaleTimeString('pt-BR');
                
                html += `
                    <tr>
                        <td>${channel.ip}</td>
                        <td>${channel.port}</td>
                        <td>${channel.protocol}</td>
                        <td>
                            <a href="${channel.stream_url}" target="_blank" class="text-info" 
                               title="${channel.stream_url}">
                                ${channel.stream_url.substring(0, 30)}...
                            </a>
                        </td>
                        <td>${channel.codec_video || '-'}</td>
                        <td>${channel.resolution || '-'}</td>
                        <td>${channel.bitrate ? Math.round(channel.bitrate / 1000) + ' kbps' : '-'}</td>
                        <td>
                            <span class="stream-quality-badge ${qualityClass}">
                                ${channel.quality_score || 0}/100
                            </span>
                        </td>
                        <td>
                            <small>${dateStr}</small><br>
                            <small class="text-muted">${timeStr}</small>
                        </td>
                        <td>
                            <div class="btn-group btn-group-sm">
                                <button class="btn btn-success play-channel" 
                                        data-url="${channel.stream_url}">
                                    <i class="fas fa-play"></i>
                                </button>
                                <button class="btn btn-info view-channel" 
                                        data-id="${channel.id}">
                                    <i class="fas fa-info-circle"></i>
                                </button>
                                <button class="btn btn-warning favorite-channel" 
                                        data-id="${channel.id}">
                                    <i class="fas fa-star"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            });
            
            $('#channels-table tbody').html(html);
            
            // Update pagination
            updatePagination(data.total, data.page, data.per_page);
        });
    }
    
    // Update pagination
    function updatePagination(total, page, perPage) {
        const totalPages = Math.ceil(total / perPage);
        const pagination = $('#pagination');
        
        if (totalPages <= 1) {
            pagination.html('');
            return;
        }
        
        let html = '';
        
        // Previous button
        html += `
            <li class="page-item ${page === 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${page - 1}">
                    <i class="fas fa-chevron-left"></i>
                </a>
            </li>
        `;
        
        // Page numbers
        const maxVisible = 5;
        let startPage = Math.max(1, page - Math.floor(maxVisible / 2));
        let endPage = Math.min(totalPages, startPage + maxVisible - 1);
        
        if (endPage - startPage + 1 < maxVisible) {
            startPage = Math.max(1, endPage - maxVisible + 1);
        }
        
        for (let i = startPage; i <= endPage; i++) {
            html += `
                <li class="page-item ${i === page ? 'active' : ''}">
                    <a class="page-link" href="#" data-page="${i}">${i}</a>
                </li>
            `;
        }
        
        // Next button
        html += `
            <li class="page-item ${page === totalPages ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${page + 1}">
                    <i class="fas fa-chevron-right"></i>
                </a>
            </li>
        `;
        
        pagination.html(html);
    }
    
    // Apply filters
    $('#apply-filters').click(function() {
        loadChannels(1);
    });
    
    // Refresh channels
    $('#refresh-channels').click(function() {
        loadChannels(currentPage);
    });
    
    // Export channels
    $('#export-channels').click(function() {
        // TODO: Implement export
        alert('Exportar canais para M3U/JSON');
    });
    
    // Play channel
    $(document).on('click', '.play-channel', function() {
        const url = $(this).data('url');
        window.open('/player?url=' + encodeURIComponent(url), '_blank');
    });
    
    // View channel details
    $(document).on('click', '.view-channel', function() {
        const id = $(this).data('id');
        
        // TODO: Load channel details via API
        $('#channel-details').html(`
            <div class="text-center py-4">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Carregando...</span>
                </div>
            </div>
        `);
        
        // For now, show basic info
        setTimeout(() => {
            $('#channel-details').html(`
                <div class="row">
                    <div class="col-md-6">
                        <h6>Informações Básicas</h6>
                        <dl class="row">
                            <dt class="col-sm-4">ID:</dt>
                            <dd class="col-sm-8">${id}</dd>
                            
                            <dt class="col-sm-4">Status:</dt>
                            <dd class="col-sm-8">
                                <span class="badge bg-success">Ativo</span>
                            </dd>
                        </dl>
                    </div>
                    <div class="col-md-6">
                        <h6>Ações</h6>
                        <button class="btn btn-primary w-100 mb-2">
                            <i class="fas fa-play me-2"></i>Reproduzir
                        </button>
                        <button class="btn btn-info w-100 mb-2">
                            <i class="fas fa-chart-line me-2"></i>Monitorar
                        </button>
                        <button class="btn btn-warning w-100">
                            <i class="fas fa-star me-2"></i>Favoritar
                        </button>
                    </div>
                </div>
            `);
        }, 500);
        
        $('#channelModal').modal('show');
    });
    
    // Favorite channel
    $(document).on('click', '.favorite-channel', function() {
        const id = $(this).data('id');
        const button = $(this);
        
        // Toggle favorite
        if (button.hasClass('btn-warning')) {
            button.removeClass('btn-warning').addClass('btn-secondary');
            button.html('<i class="fas fa-star"></i>');
            showToast('Removido dos favoritos', 'info');
        } else {
            button.removeClass('btn-secondary').addClass('btn-warning');
            button.html('<i class="fas fa-star text-warning"></i>');
            showToast('Adicionado aos favoritos', 'success');
        }
    });
    
    // Pagination click
    $(document).on('click', '.page-link', function(e) {
        e.preventDefault();
        const page = $(this).data('page');
        if (page) {
            loadChannels(page);
        }
    });
    
    // Initialize DataTable
    $('#channels-table').DataTable({
        pageLength: perPage,
        ordering: false, // We handle pagination manually
        searching: false,
        info: false,
        lengthChange: false
    });
    
    // Load channels on page load
    loadChannels();
    
    // Show toast
    function showToast(message, type) {
        // Create and show toast (implementation same as before)
        console.log(message);
    }
});
</script>
{% endblock %}''',
        
        'vulnerabilities.html': '''{% extends "base.html" %}

{% block title %}Vulnerabilidades - WebStream Hunter{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col">
        <h2>
            <i class="fas fa-shield-alt me-2"></i>Vulnerabilidades
        </h2>
        <p class="text-muted">Problemas de segurança encontrados durante os scans</p>
    </div>
</div>

<!-- Stats -->
<div class="row mb-4">
    <div class="col-md-3 mb-3">
        <div class="stat-card">
            <i class="fas fa-exclamation-triangle text-danger"></i>
            <div class="number" id="critical-count">0</div>
            <div class="label">Críticas</div>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="stat-card">
            <i class="fas fa-exclamation-circle text-warning"></i>
            <div class="number" id="high-count">0</div>
            <div class="label">Altas</div>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="stat-card">
            <i class="fas fa-info-circle text-info"></i>
            <div class="number" id="medium-count">0</div>
            <div class="label">Médias</div>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="stat-card">
            <i class="fas fa-check-circle text-success"></i>
            <div class="number" id="low-count">0</div>
            <div class="label">Baixas</div>
        </div>
    </div>
</div>

<!-- Vulnerabilities Table -->
<div class="card">
    <div class="card-header">
        <div class="d-flex justify-content-between align-items-center">
            <h5 class="mb-0">
                <i class="fas fa-bug me-2"></i>
                <span id="vulns-count">0</span> Vulnerabilidades
            </h5>
            <button class="btn btn-sm btn-primary" id="scan-vulns">
                <i class="fas fa-search me-1"></i>Novo Scan de Segurança
            </button>
        </div>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-dark table-hover" id="vulns-table">
                <thead>
                    <tr>
                        <th>Severidade</th>
                        <th>Título</th>
                        <th>Alvo</th>
                        <th>Descrição</th>
                        <th>Data</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td colspan="6" class="text-center py-4">
                            <i class="fas fa-shield-alt fa-2x text-muted mb-3"></i>
                            <h5>Nenhuma vulnerabilidade encontrada</h5>
                            <p class="text-muted">Execute um scan de segurança para começar</p>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>

{% endblock %}

{% block extra_js %}
<script>
$(document).ready(function() {
    // TODO: Implement vulnerabilities functionality
    
    $('#scan-vulns').click(function() {
        alert('Esta funcionalidade será implementada em breve!');
    });
});
</script>
{% endblock %}''',
        
        'settings.html': '''{% extends "base.html" %}

{% block title %}Configurações - WebStream Hunter{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col">
        <h2>
            <i class="fas fa-cog me-2"></i>Configurações
        </h2>
        <p class="text-muted">Configurações do sistema e preferências</p>
    </div>
</div>

<!-- Settings Tabs -->
<div class="card">
    <div class="card-header">
        <ul class="nav nav-tabs card-header-tabs" id="settingsTabs">
            <li class="nav-item">
                <a class="nav-link active" data-bs-toggle="tab" href="#general">
                    <i class="fas fa-sliders-h me-2"></i>Geral
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="tab" href="#scanning">
                    <i class="fas fa-search me-2"></i>Scanning
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="tab" href="#security">
                    <i class="fas fa-shield-alt me-2"></i>Segurança
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="tab" href="#notifications">
                    <i class="fas fa-bell me-2"></i>Notificações
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="tab" href="#system">
                    <i class="fas fa-server me-2"></i>Sistema
                </a>
            </li>
        </ul>
    </div>
    
    <div class="card-body">
        <div class="tab-content">
            <!-- General Settings -->
            <div class="tab-pane fade show active" id="general">
                <form id="general-form">
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label">Idioma</label>
                            <select class="form-select" name="language">
                                <option value="pt_BR">Português (Brasil)</option>
                                <option value="en_US">English (US)</option>
                                <option value="es_ES">Español</option>
                            </select>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Tema</label>
                            <select class="form-select" name="theme">
                                <option value="dark">Escuro</option>
                                <option value="light">Claro</option>
                                <option value="auto">Automático</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="auto_update" id="auto_update">
                            <label class="form-check-label" for="auto_update">
                                Atualização automática
                            </label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="save_logs" id="save_logs" checked>
                            <label class="form-check-label" for="save_logs">
                                Salvar logs do sistema
                            </label>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">Tamanho máximo dos logs (MB)</label>
                        <input type="number" class="form-control" name="max_log_size" value="100" min="10" max="1000">
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Salvar</button>
                </form>
            </div>
            
            <!-- Scanning Settings -->
            <div class="tab-pane fade" id="scanning">
                <form id="scanning-form">
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label">Threads máximas</label>
                            <input type="number" class="form-control" name="max_threads" value="50" min="1" max="500">
                            <small class="text-muted">Número máximo de threads simultâneas</small>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Timeout (segundos)</label>
                            <input type="number" class="form-control" name="timeout" value="5" min="1" max="60">
                            <small class="text-muted">Timeout para conexões</small>
                        </div>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label">Tentativas de retry</label>
                            <input type="number" class="form-control" name="retry_attempts" value="3" min="0" max="10">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Delay entre scans (ms)</label>
                            <input type="number" class="form-control" name="scan_delay" value="50" min="0" max="1000">
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="stealth_mode" id="stealth_mode">
                            <label class="form-check-label" for="stealth_mode">
                                Modo stealth (scans furtivos)
                            </label>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">Portas padrão para scan</label>
                        <textarea class="form-control" name="default_ports" rows="3">
80,443,554,1935,8080,8000,8001,8002,8003,8004,8005,9000,10000
                        </textarea>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Salvar</button>
                </form>
            </div>
            
            <!-- Security Settings -->
            <div class="tab-pane fade" id="security">
                <form id="security-form">
                    <div class="mb-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="require_auth" id="require_auth" checked>
                            <label class="form-check-label" for="require_auth">
                                Exigir autenticação
                            </label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="enable_ssl" id="enable_ssl">
                            <label class="form-label" for="enable_ssl">
                                Habilitar SSL/HTTPS
                            </label>
                        </div>
                    </div>
                    
                    <div class="row mb-3" id="ssl-fields" style="display: none;">
                        <div class="col-md-6">
                            <label class="form-label">Certificado SSL</label>
                            <input type="text" class="form-control" name="ssl_cert" placeholder="/caminho/para/certificado.pem">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Chave SSL</label>
                            <input type="text" class="form-control" name="ssl_key" placeholder="/caminho/para/chave.pem">
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">IPs Permitidos (whitelist)</label>
                        <textarea class="form-control" name="allowed_ips" rows="3" placeholder="Um IP por linha&#10;Exemplo:&#10;192.168.1.0/24&#10;10.0.0.1"></textarea>
                        <small class="text-muted">Deixe vazio para permitir todos</small>
                    </div>
                    
                    <div class="mb-4">
                        <label class="form-label">IPs Bloqueados (blacklist)</label>
                        <textarea class="form-control" name="blocked_ips" rows="3" placeholder="Um IP por linha"></textarea>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Salvar</button>
                </form>
            </div>
            
            <!-- Notifications -->
            <div class="tab-pane fade" id="notifications">
                <form id="notifications-form">
                    <h6 class="mb-3">
                        <i class="fas fa-envelope me-2"></i>Email
                    </h6>
                    
                    <div class="mb-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="email_enabled" id="email_enabled">
                            <label class="form-check-label" for="email_enabled">
                                Habilitar notificações por email
                            </label>
                        </div>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label">Servidor SMTP</label>
                            <input type="text" class="form-control" name="smtp_server" placeholder="smtp.gmail.com">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Porta SMTP</label>
                            <input type="number" class="form-control" name="smtp_port" value="587">
                        </div>
                    </div>
                    
                    <div class="row mb-4">
                        <div class="col-md-6">
                            <label class="form-label">Email de origem</label>
                            <input type="email" class="form-control" name="email_from" placeholder="seu@email.com">
                        </div>
                    </div>
                    
                    <h6 class="mb-3">
                        <i class="fab fa-telegram me-2"></i>Telegram
                    </h6>
                    
                    <div class="mb-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="telegram_enabled" id="telegram_enabled">
                            <label class="form-check-label" for="telegram_enabled">
                                Habilitar notificações do Telegram
                            </label>
                        </div>
                    </div>
                    
                    <div class="row mb-4">
                        <div class="col-md-6">
                            <label class="form-label">Bot Token</label>
                            <input type="text" class="form-control" name="telegram_bot_token" placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Chat ID</label>
                            <input type="text" class="form-control" name="telegram_chat_id" placeholder="123456789">
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Salvar</button>
                </form>
            </div>
            
            <!-- System -->
            <div class="tab-pane fade" id="system">
                <div class="row mb-4">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h6 class="mb-0">
                                    <i class="fas fa-database me-2"></i>Banco de Dados
                                </h6>
                            </div>
                            <div class="card-body">
                                <p>Tamanho do banco: <strong id="db-size">Calculando...</strong></p>
                                <p>Registros: <strong id="db-records">Calculando...</strong></p>
                                
                                <div class="d-grid gap-2 mt-3">
                                    <button class="btn btn-success" id="backup-db">
                                        <i class="fas fa-save me-2"></i>Backup
                                    </button>
                                    <button class="btn btn-warning" id="optimize-db">
                                        <i class="fas fa-broom me-2"></i>Otimizar
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h6 class="mb-0">
                                    <i class="fas fa-trash me-2"></i>Limpeza
                                </h6>
                            </div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <label class="form-label">Manter logs por (dias)</label>
                                    <input type="number" class="form-control" id="keep-logs-days" value="30" min="1" max="365">
                                </div>
                                
                                <div class="d-grid gap-2">
                                    <button class="btn btn-danger" id="clean-logs">
                                        <i class="fas fa-trash-alt me-2"></i>Limpar Logs Antigos
                                    </button>
                                    <button class="btn btn-secondary" id="clear-cache">
                                        <i class="fas fa-broom me-2"></i>Limpar Cache
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0">
                            <i class="fas fa-redo me-2"></i>Reinicialização
                        </h6>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            Estas ações reiniciarão o serviço e podem causar interrupção.
                        </div>
                        
                        <div class="d-grid gap-2">
                            <button class="btn btn-warning" id="restart-service">
                                <i class="fas fa-sync-alt me-2"></i>Reiniciar Serviço
                            </button>
                            <button class="btn btn-danger" id="reload-config">
                                <i class="fas fa-cogs me-2"></i>Recarregar Configuração
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Toast Container -->
<div class="toast-container position-fixed bottom-0 end-0 p-3"></div>

{% endblock %}

{% block extra_js %}
<script>
$(document).ready(function() {
    // Load current config
    $.get('/api/config', function(config) {
        // General
        $('select[name="language"]').val(config.general?.language || 'pt_BR');
        $('select[name="theme"]').val(config.general?.theme || 'dark');
        $('input[name="auto_update"]').prop('checked', config.general?.auto_update || false);
        $('input[name="save_logs"]').prop('checked', config.general?.save_logs || true);
        $('input[name="max_log_size"]').val(config.general?.max_log_size || 100);
        
        // Scanning
        $('input[name="max_threads"]').val(config.scanning?.max_threads || 50);
        $('input[name="timeout"]').val(config.scanning?.timeout || 5);
        $('input[name="retry_attempts"]').val(config.scanning?.retry_attempts || 3);
        $('input[name="scan_delay"]').val(config.scanning?.scan_delay || 50);
        $('input[name="stealth_mode"]').prop('checked', config.scanning?.stealth_mode || false);
        
        // Security
        $('input[name="require_auth"]').prop('checked', config.security?.require_auth || true);
        $('input[name="enable_ssl"]').prop('checked', config.security?.enable_ssl || false);
        $('textarea[name="allowed_ips"]').val((config.security?.allowed_ips || []).join('\\n'));
        $('textarea[name="blocked_ips"]').val((config.security?.blocked_ips || []).join('\\n'));
        
        // SSL fields toggle
        $('#enable_ssl').change(function() {
            $('#ssl-fields').toggle(this.checked);
        });
        $('#ssl-fields').toggle($('#enable_ssl').is(':checked'));
        
        // Notifications
        $('input[name="email_enabled"]').prop('checked', config.notifications?.email_enabled || false);
        $('input[name="smtp_server"]').val(config.notifications?.smtp_server || '');
        $('input[name="smtp_port"]').val(config.notifications?.smtp_port || 587);
        $('input[name="email_from"]').val(config.notifications?.email_from || '');
        $('input[name="telegram_enabled"]').prop('checked', config.notifications?.telegram_enabled || false);
        $('input[name="telegram_bot_token"]').val(config.notifications?.telegram_bot_token || '');
        $('input[name="telegram_chat_id"]').val(config.notifications?.telegram_chat_id || '');
    });
    
    // Save forms
    $('form').submit(function(e) {
        e.preventDefault();
        const formId = $(this).attr('id');
        
        // Get form data
        let formData = {};
        $(this).serializeArray().forEach(item => {
            if (item.name.endsWith('_enabled') || item.name.endsWith('_mode') || 
                item.name === 'auto_update' || item.name === 'save_logs' || 
                item.name === 'require_auth' || item.name === 'enable_ssl') {
                formData[item.name] = item.value === 'on';
            } else if (item.name === 'allowed_ips' || item.name === 'blocked_ips') {
                formData[item.name] = item.value.split('\\n').filter(ip => ip.trim());
            } else {
                formData[item.name] = item.value;
            }
        });
        
        // Get current config
        $.get('/api/config', function(currentConfig) {
            // Update only the relevant section
            let updatedConfig = currentConfig;
            
            if (formId === 'general-form') {
                updatedConfig.general = { ...updatedConfig.general, ...formData };
            } else if (formId === 'scanning-form') {
                updatedConfig.scanning = { ...updatedConfig.scanning, ...formData };
            } else if (formId === 'security-form') {
                updatedConfig.security = { ...updatedConfig.security, ...formData };
            } else if (formId === 'notifications-form') {
                updatedConfig.notifications = { ...updatedConfig.notifications, ...formData };
            }
            
            // Save updated config
            $.ajax({
                url: '/api/config',
                method: 'PUT',
                contentType: 'application/json',
                data: JSON.stringify(updatedConfig),
                success: function() {
                    showToast('Configurações salvas com sucesso!', 'success');
                },
                error: function(xhr) {
                    showToast('Erro ao salvar configurações: ' + xhr.responseText, 'error');
                }
            });
        });
    });
    
    // System actions
    $('#backup-db').click(function() {
        alert('Backup do banco de dados será implementado em breve!');
    });
    
    $('#optimize-db').click(function() {
        alert('Otimização do banco de dados será implementada em breve!');
    });
    
    $('#clean-logs').click(function() {
        const days = $('#keep-logs-days').val();
        if (confirm(`Limpar logs com mais de ${days} dias?`)) {
            alert('Limpeza de logs será implementada em breve!');
        }
    });
    
    $('#clear-cache').click(function() {
        if (confirm('Limpar todo o cache?')) {
            alert('Limpeza de cache será implementada em breve!');
        }
    });
    
    $('#restart-service').click(function() {
        if (confirm('Reiniciar o serviço? Isso pode causar interrupção.')) {
            alert('Reinicialização do serviço será implementada em breve!');
        }
    });
    
    $('#reload-config').click(function() {
        if (confirm('Recarregar configuração do arquivo?')) {
            alert('Recarregamento de configuração será implementado em breve!');
        }
    });
    
    // Show toast
    function showToast(message, type) {
        const toast = $(`
            <div class="toast align-items-center text-white bg-${type === 'error' ? 'danger' : 'success'} border-0"
                 role="alert" aria-live="assertive" aria-atomic="true">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'check-circle'} me-2"></i>
                        ${message}
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `);
        
        $('.toast-container').append(toast);
        const bsToast = new bootstrap.Toast(toast[0]);
        bsToast.show();
        
        toast.on('hidden.bs.toast', function() {
            $(this).remove();
        });
    }
});
</script>
{% endblock %}'''
    }
    
    for filename, content in templates.items():
        with open(os.path.join(templates_dir, filename), 'w') as f:
            f.write(content)

# Instalador para Ubuntu 20.04
class UbuntuInstaller:
    """Instalador completo para Ubuntu 20.04"""
    
    def __init__(self):
        self.system = platform.system()
        if self.system != "Linux":
            print("❌ Este instalador é apenas para Linux/Ubuntu")
            sys.exit(1)
            
    def check_ubuntu_version(self):
        """Verifica versão do Ubuntu"""
        try:
            with open('/etc/os-release') as f:
                content = f.read()
                if 'Ubuntu 20.04' in content:
                    return True
        except:
            pass
        return False
        
    def install(self):
        """Executa instalação completa"""
        print("\n" + "="*70)
        print("           WEBSTREAM HUNTER - INSTALADOR UBUNTU 20.04")
        print("="*70)
        
        if not self.check_ubuntu_version():
            print("⚠️  Este instalador é otimizado para Ubuntu 20.04")
            print("   Continuando em outro sistema Linux...")
        
        # Verificar root
        if os.geteuid() != 0:
            print("\n❌ Este instalador precisa ser executado como root!")
            print("   Execute: sudo python3 webstream_hunter.py --install")
            sys.exit(1)
        
        self.install_dependencies()
        self.create_structure()
        self.create_templates()
        self.create_service()
        self.create_config()
        self.set_permissions()
        self.finalize()
        
    def install_dependencies(self):
        """Instala dependências do sistema"""
        print("\n📦 Instalando dependências do sistema...")
        
        # Atualizar pacotes
        self.run_command("apt-get update -y")
        
        # Dependências do sistema
        packages = [
            "python3-pip",
            "python3-dev",
            "build-essential",
            "libssl-dev",
            "libffi-dev",
            "ffmpeg",
            "vlc",
            "nmap",
            "tshark",
            "wireshark-common",
            "sqlite3",
            "net-tools",
            "iproute2",
            "python3-venv"
        ]
        
        for package in packages:
            print(f"  Instalando {package}...")
            self.run_command(f"apt-get install -y {package}")
            
        # Python dependencies
        print("\n🐍 Instalando dependências Python...")
        
        # Criar virtual environment
        self.run_command("python3 -m venv /opt/webstream_hunter/venv")
        
        # Instalar pacotes no venv
        venv_pip = "/opt/webstream_hunter/venv/bin/pip"
        
        python_packages = [
            "flask",
            "flask-socketio",
            "flask-cors",
            "flask-login",
            "werkzeug",
            "aiohttp",
            "async-timeout",
            "websockets",
            "nmap3",
            "scapy",
            "psutil",
            "netifaces",
            "ifaddr",
            "ffmpeg-python",
            "opencv-python-headless",
            "pillow",
            "imagehash",
            "sqlalchemy",
            "numpy"
        ]
        
        for package in python_packages:
            print(f"  Instalando {package}...")
            self.run_command(f"{venv_pip} install {package}")
            
    def create_structure(self):
        """Cria estrutura de diretórios"""
        print("\n📁 Criando estrutura de diretórios...")
        
        directories = [
            "/opt/webstream_hunter",
            "/var/log/webstream_hunter",
            "/var/lib/webstream_hunter",
            "/var/cache/webstream_hunter",
            "/etc/webstream_hunter",
            "/usr/share/webstream_hunter/static",
            "/usr/share/webstream_hunter/templates"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            self.run_command(f"chmod 755 {directory}")
            print(f"  ✓ {directory}")
            
    def create_templates(self):
        """Cria templates HTML"""
        print("\n🎨 Criando templates HTML...")
        create_templates()
        print("  ✓ Templates criados")
        
    def create_service(self):
        """Cria service systemd"""
        print("\n⚙️  Criando service systemd...")
        
        service_content = '''[Unit]
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

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/webstream_hunter /var/lib/webstream_hunter /var/cache/webstream_hunter

[Install]
WantedBy=multi-user.target
'''
        
        with open('/etc/systemd/system/webstream-hunter.service', 'w') as f:
            f.write(service_content)
            
        # Criar usuário dedicado
        self.run_command("useradd -r -s /bin/false webstream 2>/dev/null || true")
        
        # Definir permissões
        self.run_command("chown -R webstream:webstream /opt/webstream_hunter")
        self.run_command("chown -R webstream:webstream /var/log/webstream_hunter")
        self.run_command("chown -R webstream:webstream /var/lib/webstream_hunter")
        self.run_command("chown -R webstream:webstream /var/cache/webstream_hunter")
        
        print("  ✓ Service systemd criado")
        
    def create_config(self):
        """Cria configuração padrão"""
        print("\n⚙️  Criando configuração padrão...")
        
        config = DEFAULT_CONFIG.copy()
        config['web']['host'] = '0.0.0.0'
        config['web']['port'] = 8080
        config['security']['default_user'] = 'admin'
        config['security']['default_password'] = 'admin123'
        
        with open('/etc/webstream_hunter/config.json', 'w') as f:
            json.dump(config, f, indent=4)
            
        print("  ✓ Configuração criada")
        
    def set_permissions(self):
        """Define permissões de segurança"""
        print("\n🔒 Definindo permissões de segurança...")
        
        # Permissões restritivas
        directories = [
            "/opt/webstream_hunter",
            "/var/log/webstream_hunter",
            "/var/lib/webstream_hunter",
            "/var/cache/webstream_hunter",
            "/etc/webstream_hunter"
        ]
        
        for directory in directories:
            self.run_command(f"chmod 750 {directory}")
            self.run_command(f"chown -R webstream:webstream {directory}")
            
        # Arquivo de configuração
        self.run_command("chmod 640 /etc/webstream_hunter/config.json")
        
        # Arquivos de log
        self.run_command("chmod 640 /var/log/webstream_hunter/* 2>/dev/null || true")
        
        print("  ✓ Permissões definidas")
        
    def finalize(self):
        """Finaliza instalação"""
        print("\n🚀 Finalizando instalação...")
        
        # Recarregar systemd
        self.run_command("systemctl daemon-reload")
        
        # Habilitar service
        self.run_command("systemctl enable webstream-hunter.service")
        
        # Iniciar service
        self.run_command("systemctl start webstream-hunter.service")
        
        # Verificar status
        print("\n📊 Verificando status do serviço...")
        self.run_command("systemctl status webstream-hunter.service --no-pager")
        
        print("\n" + "="*70)
        print("✅ INSTALAÇÃO COMPLETA!")
        print("="*70)
        
        print("\n📋 INFORMAÇÕES IMPORTANTES:")
        print(f"   • URL de acesso: http://seu-ip:8080")
        print(f"   • Usuário padrão: admin")
        print(f"   • Senha padrão: admin123")
        print(f"   • Service: webstream-hunter")
        print(f"   • Logs: /var/log/webstream_hunter/app.log")
        print(f"   • Configuração: /etc/webstream_hunter/config.json")
        
        print("\n🔧 COMANDOS ÚTEIS:")
        print(f"   • Iniciar: sudo systemctl start webstream-hunter")
        print(f"   • Parar: sudo systemctl stop webstream-hunter")
        print(f"   • Reiniciar: sudo systemctl restart webstream-hunter")
        print(f"   • Status: sudo systemctl status webstream-hunter")
        print(f"   • Logs: sudo journalctl -u webstream-hunter -f")
        
        print("\n⚠️  RECOMENDAÇÕES DE SEGURANÇA:")
        print(f"   1. Altere a senha padrão na primeira execução")
        print(f"   2. Configure SSL/HTTPS em /etc/webstream_hunter/config.json")
        print(f"   3. Restrinja IPs de acesso via whitelist")
        print(f"   4. Mantenha o sistema atualizado")
        
        print("\n🌐 PRÓXIMOS PASSOS:")
        print(f"   1. Acesse http://seu-ip:8080 no navegador")
        print(f"   2. Faça login com admin/admin123")
        print(f"   3. Configure conforme necessário")
        print(f"   4. Inicie seu primeiro scan!")
        
        print("\n" + "="*70)
        
    def run_command(self, command):
        """Executa comando no sistema"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"  ⚠️  Comando falhou: {command}")
                print(f"     Erro: {result.stderr[:100]}")
            return result.returncode == 0
        except Exception as e:
            print(f"  ❌ Erro executando comando: {e}")
            return False

# Main entry point
def main():
    """Ponto de entrada principal"""
    
    # Verificar argumentos
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install":
            installer = UbuntuInstaller()
            installer.install()
            return
        elif sys.argv[1] == "--help":
            print("Uso: python3 webstream_hunter.py [opção]")
            print("\nOpções:")
            print("  --install    Instalação completa no sistema")
            print("  --help       Mostra esta ajuda")
            print("  (sem opção)  Inicia o servidor web")
            return
    
    # Criar templates se necessário
    if not os.path.exists(TEMPLATE_DIR):
        create_templates()
    
    # Iniciar aplicação
    app = WebStreamHunter()
    app.run()

if __name__ == "__main__":
    main()
