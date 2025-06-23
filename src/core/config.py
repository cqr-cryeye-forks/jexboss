from dataclasses import dataclass
from typing import Optional

@dataclass
class Config:
    target: str                  # URL/domain/IPv4 to scan
    output: str                  # Path to JSON report
    reverse_host: Optional[str]  # "IP:PORT" for reverse shell or None
    cmd: Optional[str]           # Command to execute remotely
    cookies: Optional[str]       # Cookie header value if needed
    timeout: int                 # HTTP request timeout in seconds
    jboss_login: Optional[str]   # Credentials for JBoss admin console (user:pass)
    gadget: str                  # Gadget type for deserialization payloads
    load_gadget: Optional[str]   # Path to custom gadget file
    show_payload: bool           # Whether to display the generated payload
    post_parameter: str          # HTTP POST parameter for Application Deserialization
    force: bool                  # Force sending all payload formats without initial GET
    threads: int                 # Number of concurrent threads
    auto_exploit: bool           # Automatically run exploits when found
    jmx_tomcat: bool             # Enable JMX Tomcat exploitation
    app_unserialize: bool        # Enable Application Deserialization check
    servlet_unserialize: bool     # Enable Servlet Deserialization check
    struts2: bool                # Enable Struts2 exploitation
    jboss: bool                  # Enable core JBoss vectors (jmx-console, web-console, etc.)
    jenkins: bool                # Enable Jenkins exploitation
