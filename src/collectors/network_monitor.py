"""
Real-Time Network Monitor
Captures live network connections and processes them through the ML detection pipeline
"""

import psutil
import threading
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from collections import deque
import socket

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """
    Real-time network connection monitor using psutil.
    Captures active connections and transforms them into events for ML analysis.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.running = False
        self.paused = False
        self.scan_interval = self.config.get('scan_interval', 2.0)  # seconds
        
        # Data storage
        self.connections_history: deque = deque(maxlen=1000)
        self.alerts: deque = deque(maxlen=500)
        self.current_connections: Dict[str, Dict] = {}
        self.previous_io_stats: Optional[Dict] = None
        
        # Statistics
        self.stats = {
            'total_connections_seen': 0,
            'events_processed': 0,
            'alerts_generated': 0,
            'start_time': None,
            'last_scan': None
        }
        
        # Threading
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Callbacks for ML processing
        self._detection_callback: Optional[Callable] = None
        
    def set_detection_callback(self, callback: Callable):
        """Set callback function for processing detected events through ML pipeline"""
        self._detection_callback = callback
        
    def start(self):
        """Start the network monitoring service"""
        if self.running:
            logger.warning("Network monitor is already running")
            return False
            
        self.running = True
        self.paused = False
        self.stats['start_time'] = datetime.now().isoformat()
        
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        logger.info("Network monitor started")
        return True
        
    def stop(self):
        """Stop the network monitoring service"""
        self.running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None
        logger.info("Network monitor stopped")
        return True
        
    def pause(self):
        """Pause monitoring without clearing data"""
        self.paused = True
        logger.info("Network monitor paused")
        
    def resume(self):
        """Resume monitoring"""
        self.paused = False
        logger.info("Network monitor resumed")
        
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            if not self.paused:
                try:
                    self._capture_connections()
                except Exception as e:
                    logger.error(f"Error in monitor loop: {e}")
                    
            time.sleep(self.scan_interval)
            
    def _capture_connections(self):
        """Capture current network connections and generate events"""
        try:
            # Get current connections
            connections = psutil.net_connections(kind='inet')
            current_io = psutil.net_io_counters(pernic=False)
            
            # Filter for established connections
            established = [c for c in connections if c.status == 'ESTABLISHED' and c.raddr]
            
            # Calculate IO delta
            io_delta = self._calculate_io_delta(current_io)
            
            # Process each connection
            events = []
            for conn in established:
                conn_key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                
                event = self._create_event(conn, io_delta, conn_key)
                if event:
                    events.append(event)
                    
                    with self._lock:
                        self.connections_history.append(event)
                        self.stats['total_connections_seen'] += 1
            
            # Process events through ML pipeline if callback set
            if events and self._detection_callback:
                try:
                    results = self._detection_callback(events)
                    self._process_detection_results(results, events)
                except Exception as e:
                    logger.error(f"Error in detection callback: {e}")
                    
            self.stats['last_scan'] = datetime.now().isoformat()
            self.stats['events_processed'] += len(events)
            
            # Store current IO for next delta calculation
            self.previous_io_stats = {
                'bytes_sent': current_io.bytes_sent,
                'bytes_recv': current_io.bytes_recv,
                'packets_sent': current_io.packets_sent,
                'packets_recv': current_io.packets_recv,
                'timestamp': time.time()
            }
            
        except psutil.AccessDenied:
            logger.warning("Access denied when reading network connections. Some connections may be missed.")
        except Exception as e:
            logger.error(f"Error capturing connections: {e}")
            
    def _calculate_io_delta(self, current_io) -> Dict:
        """Calculate IO stats delta since last scan"""
        if not self.previous_io_stats:
            return {
                'bytes_per_conn': 1000,  # Default estimate
                'packets_per_conn': 10,
                'duration': self.scan_interval
            }
            
        time_delta = time.time() - self.previous_io_stats['timestamp']
        if time_delta <= 0:
            time_delta = self.scan_interval
            
        return {
            'bytes_sent_delta': current_io.bytes_sent - self.previous_io_stats['bytes_sent'],
            'bytes_recv_delta': current_io.bytes_recv - self.previous_io_stats['bytes_recv'],
            'packets_sent_delta': current_io.packets_sent - self.previous_io_stats['packets_sent'],
            'packets_recv_delta': current_io.packets_recv - self.previous_io_stats['packets_recv'],
            'duration': time_delta
        }
        
    def _create_event(self, conn, io_delta: Dict, conn_key: str) -> Optional[Dict]:
        """Create a network event from a connection"""
        try:
            # Determine protocol
            protocol = 6 if conn.type == socket.SOCK_STREAM else 17  # TCP or UDP
            
            # Get process info if available
            process_name = "unknown"
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
            # Estimate per-connection traffic (simplified)
            # In reality, this would need proper per-connection tracking
            active_conns = max(1, self.stats.get('active_connections', 1))
            est_bytes = io_delta.get('bytes_sent_delta', 1000) // active_conns
            est_packets = max(1, io_delta.get('packets_sent_delta', 10) // active_conns)
            
            return {
                'timestamp': datetime.now().isoformat(),
                'src_ip': conn.laddr.ip,
                'src_port': conn.laddr.port,
                'dst_ip': conn.raddr.ip,
                'dst_port': conn.raddr.port,
                'protocol': protocol,
                'packets': est_packets,
                'bytes': max(64, est_bytes),  # Minimum packet size
                'flow_duration': io_delta.get('duration', self.scan_interval),
                'pid': conn.pid,
                'process': process_name,
                'connection_key': conn_key,
                'source': 'realtime'
            }
        except Exception as e:
            logger.debug(f"Error creating event: {e}")
            return None
            
    def _process_detection_results(self, results: List[Dict], events: List[Dict]):
        """Process ML detection results and generate alerts"""
        if not results:
            return
            
        for result in results:
            # Check if this is a significant threat
            risk_score = result.get('risk_score', 0)
            severity = result.get('severity', 'low')
            
            # Always generate alert for real-time visibility in dashboard
            # The dashboard handles severity filtering/coloring
            alert = {
                'timestamp': datetime.now().isoformat(),
                'threat_id': result.get('threat_id'),
                'src_ip': result.get('src_ip'),
                'dst_ip': result.get('dst_ip'),
                'dst_port': result.get('dst_port'),
                'severity': severity,
                'risk_score': risk_score,
                'action': result.get('action'),
                'process': result.get('process', 'unknown'),
                'source': 'realtime'
            }
            
            with self._lock:
                self.alerts.append(alert)
                self.stats['alerts_generated'] += 1
            
            if severity in ['medium', 'high', 'critical'] or risk_score > 30:
                logger.warning(f"REAL-TIME ALERT: {severity.upper()} threat from {result.get('src_ip')} (Risk: {risk_score:.1f})")
                
    def get_status(self) -> Dict[str, Any]:
        """Get current monitor status"""
        with self._lock:
            return {
                'running': self.running,
                'paused': self.paused,
                'scan_interval': self.scan_interval,
                'stats': self.stats.copy(),
                'recent_connections': len(self.connections_history),
                'pending_alerts': len(self.alerts)
            }
            
    def get_recent_connections(self, limit: int = 50) -> List[Dict]:
        """Get recent captured connections"""
        with self._lock:
            return list(self.connections_history)[-limit:]
            
    def get_alerts(self, limit: int = 50, clear: bool = False) -> List[Dict]:
        """Get recent alerts, optionally clearing them"""
        with self._lock:
            alerts = list(self.alerts)[-limit:]
            if clear:
                self.alerts.clear()
            return alerts
            
    def clear_data(self):
        """Clear all stored data"""
        with self._lock:
            self.connections_history.clear()
            self.alerts.clear()
            self.stats['total_connections_seen'] = 0
            self.stats['events_processed'] = 0
            self.stats['alerts_generated'] = 0


# Singleton instance for global access
_monitor_instance: Optional[NetworkMonitor] = None


def get_monitor() -> NetworkMonitor:
    """Get or create the global network monitor instance"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = NetworkMonitor()
    return _monitor_instance
