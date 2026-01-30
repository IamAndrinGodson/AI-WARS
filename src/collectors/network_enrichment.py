"""
Network Enrichment Module
Provides contextual information for IPs and ports:
- Port service names and descriptions
- IP type detection (Private/Public/Loopback)
- Hostname resolution (Reverse DNS) with caching
- Geo-location estimation (Stub/Basic)
"""

import socket
import ipaddress
import logging
from typing import Dict, Any, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

# Common ports database
COMMON_PORTS = {
    20: {"service": "FTP-DATA", "desc": "File Transfer Protocol (Data)", "risk": "medium"},
    21: {"service": "FTP", "desc": "File Transfer Protocol (Control)", "risk": "high"},
    22: {"service": "SSH", "desc": "Secure Shell", "risk": "high"},
    23: {"service": "TELNET", "desc": "Telnet (Unencrypted)", "risk": "critical"},
    25: {"service": "SMTP", "desc": "Simple Mail Transfer Protocol", "risk": "medium"},
    53: {"service": "DNS", "desc": "Domain Name System", "risk": "low"},
    67: {"service": "DHCP", "desc": "DHCP Server", "risk": "low"},
    68: {"service": "DHCP", "desc": "DHCP Client", "risk": "low"},
    80: {"service": "HTTP", "desc": "Hypertext Transfer Protocol", "risk": "medium"},
    110: {"service": "POP3", "desc": "Post Office Protocol v3", "risk": "medium"},
    123: {"service": "NTP", "desc": "Network Time Protocol", "risk": "low"},
    135: {"service": "RPC", "desc": "Microsoft RPC", "risk": "high"},
    137: {"service": "NETBIOS", "desc": "NetBIOS Name Service", "risk": "medium"},
    138: {"service": "NETBIOS", "desc": "NetBIOS Datagram Service", "risk": "medium"},
    139: {"service": "NETBIOS", "desc": "NetBIOS Session Service", "risk": "high"},
    143: {"service": "IMAP", "desc": "Internet Message Access Protocol", "risk": "medium"},
    161: {"service": "SNMP", "desc": "Simple Network Management Protocol", "risk": "medium"},
    389: {"service": "LDAP", "desc": "Lightweight Directory Access Protocol", "risk": "medium"},
    443: {"service": "HTTPS", "desc": "HTTP Secure", "risk": "low"},
    445: {"service": "SMB", "desc": "Microsoft DS (Active Directory/SMB)", "risk": "high"},
    500: {"service": "IKE", "desc": "IPSec Internet Key Exchange", "risk": "medium"},
    636: {"service": "LDAPS", "desc": "LDAP over SSL", "risk": "low"},
    993: {"service": "IMAPS", "desc": "IMAP over SSL", "risk": "low"},
    995: {"service": "POP3S", "desc": "POP3 over SSL", "risk": "low"},
    1433: {"service": "MSSQL", "desc": "Microsoft SQL Server", "risk": "high"},
    1521: {"service": "ORACLE", "desc": "Oracle Database", "risk": "high"},
    3306: {"service": "MYSQL", "desc": "MySQL Database", "risk": "high"},
    3389: {"service": "RDP", "desc": "Remote Desktop Protocol", "risk": "high"},
    5432: {"service": "POSTGRES", "desc": "PostgreSQL Database", "risk": "high"},
    5900: {"service": "VNC", "desc": "Virtual Network Computing", "risk": "high"},
    6379: {"service": "REDIS", "desc": "Redis Key-Value Store", "risk": "medium"},
    8000: {"service": "HTTP-ALT", "desc": "Common Web Server API", "risk": "medium"},
    8080: {"service": "HTTP-PROXY", "desc": "HTTP Alternate / Proxy", "risk": "medium"},
    8443: {"service": "HTTPS-ALT", "desc": "HTTPS Alternate", "risk": "medium"},
    27017: {"service": "MONGODB", "desc": "MongoDB", "risk": "high"}
}

class NetworkEnricher:
    def __init__(self):
        self.hostname_cache = {}

    @lru_cache(maxsize=1024)
    def get_port_info(self, port: int) -> Dict[str, str]:
        """Get service info for a port"""
        if port in COMMON_PORTS:
            return COMMON_PORTS[port]
        
        try:
            # Fallback to system services lookup
            service = socket.getservbyport(port)
            return {"service": service.upper(), "desc": f"System Service: {service}", "risk": "unknown"}
        except:
            return {"service": "UNKNOWN", "desc": "Unknown Service", "risk": "unknown"}

    def get_ip_type(self, ip_str: str) -> str:
        """Determine if IP is private, public, loopback, etc."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback:
                return "loopback"
            if ip.is_private:
                return "private"
            if ip.is_multicast:
                return "multicast"
            if ip.is_reserved:
                return "reserved"
            return "public"
        except ValueError:
            return "invalid"

    @lru_cache(maxsize=500)
    def get_hostname(self, ip: str) -> str:
        """Perform reverse DNS lookup with caching"""
        # Don't look up private IPs if configured not to, but for now we'll try everything
        # short timeout for DNS to avoid blocking
        try:
            socket.setdefaulttimeout(1)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return ""

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Get full enrichment data for an IP"""
        ip_type = self.get_ip_type(ip)
        hostname = self.get_hostname(ip)
        
        # Simple/Stub GeoIP for demonstration (Replacing real DB for now)
        geo = "Unknown"
        if ip_type == "loopback":
            geo = "Local Machine"
        elif ip_type == "private":
            geo = "Local Network"
        else:
            # Stub for public IPs
            geo = "Internet" 
            
        return {
            "ip": ip,
            "type": ip_type,
            "hostname": hostname,
            "location": geo
        }

# Global instance
enricher = NetworkEnricher()
