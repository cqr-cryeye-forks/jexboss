from dataclasses import dataclass
from typing import Optional
import ipaddress

@dataclass
class Config:
    # Основные параметры
    target: str  # URL/domain/IPv4 to scan (from --host)
    output: str  # Path to JSON report (from --out or --results)
    mode: str  # Operation mode: 'standalone', 'auto-scan', 'file-scan'
    timeout: int  # HTTP request timeout in seconds
    cookies: Optional[str]  # Cookie header value (from --cookies)
    proxy: Optional[str]  # HTTP proxy URL (from --proxy)
    proxy_cred: Optional[str]  # Proxy authentication credentials (from --proxy-cred)

    # Параметры эксплуатации
    reverse_host: Optional[str]  # "IP:PORT" for reverse shell (from --reverse-host)
    cmd: Optional[str]  # Command to execute remotely (from --cmd)
    dns: Optional[str]  # DNS query for "dns" gadget (from --dns)
    jboss_login: Optional[str]  # Credentials for JBoss admin console (from --jboss-login)
    gadget: str  # Gadget type for deserialization payloads (from --gadget)
    load_gadget: Optional[str]  # Path to custom gadget file (from --load-gadget)
    post_parameter: str  # HTTP POST parameter for Application Deserialization (from --post-parameter)
    show_payload: bool  # Whether to display the generated payload (from --show-payload)
    force: bool  # Force sending all payload formats (from --force)
    windows: bool  # Commands are for Windows (from --windows)
    auto_exploit: bool  # Automatically run exploits when found (from --auto-exploit)

    # Векторы уязвимостей
    jmx_tomcat: bool  # Enable JMX Tomcat exploitation (from --jmxtomcat)
    app_unserialize: bool  # Enable Application Deserialization check (from --app-unserialize)
    servlet_unserialize: bool  # Enable Servlet Deserialization check (from --servlet-unserialize)
    struts2: bool  # Enable Struts2 exploitation (from --struts2)
    jboss: bool  # Enable core JBoss vectors (from --jboss)
    jenkins: bool  # Enable Jenkins exploitation (from --jenkins)

    # Параметры для auto-scan
    network: Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]  # Network in CIDR format (from --network)
    ports: str  # Comma-separated ports for auto-scan (from --ports)
    results: str  # File to store auto-scan results (from --results)

    # Параметры для file-scan
    file: Optional[str]  # File with host list for file-scan (from --file)
    threads: int  # Number of concurrent threads (default from previous Config)

    # Дополнительные параметры
    disable_check_updates: bool  # Disable update checks (from --disable-check-updates)