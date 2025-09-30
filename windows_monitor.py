#!/usr/bin/env python3
"""
Windows File System Monitor for Ransomware Detection
Real-time monitoring of file system operations on Windows

Requirements:
pip install pywin32 watchdog psutil requests

This monitor captures actual file system events and sends them to your detection platform.
"""

import os
import sys
import time
import json
import logging
import requests
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent

# Windows-specific imports
try:
    import win32file
    import win32con
    import win32api
    import win32security
    import win32process
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    print("Warning: Windows-specific monitoring not available. Install pywin32 for full functionality.")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("file_monitor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("file_monitor")

class FileSystemMonitor(FileSystemEventHandler):
    """Monitor file system events and send to detection platform"""
    
    def __init__(self, detection_server_url="http://localhost:8000"):
        super().__init__()
        self.server_url = detection_server_url
        self.process_cache = {}
        self.recent_events = []
        self.max_events = 1000
        
        # Track suspicious file extensions
        self.crypto_extensions = {
            '.encrypted', '.locked', '.crypto', '.vault', '.axx', '.zzz',
            '.micro', '.dharma', '.wallet', '.cerber', '.locky', '.zepto'
        }
        
        # Track important directories
        self.important_dirs = {
            Path.home() / "Documents",
            Path.home() / "Pictures",
            Path.home() / "Desktop",
            Path.home() / "Videos",
            Path("C:/Users/Public"),
            
        }
        
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self._handle_file_event("write", event.src_path)
            
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self._handle_file_event("write", event.src_path)
            
    def on_deleted(self, event):
        """Handle file deletion events"""
        if not event.is_directory:
            self._handle_file_event("delete", event.src_path)
            
    def _handle_file_event(self, operation: str, file_path: str):
        """Process a file system event"""
        try:
            path = Path(file_path)
            
            # Skip system/temporary files
            if self._should_skip_file(path):
                return
                
            # Get process information
            process_info = self._get_process_info_for_file(file_path)
            
            # Create trace data
            trace_data = {
                "timestamp": time.time(),
                "operation_type": operation,
                "file_path": str(path),
                "offset": 0,
                "size": self._get_file_size(path),
                "process_id": process_info.get('pid', 0),
                "process_name": process_info.get('name', 'unknown.exe')
            }
            
            # Check for suspicious activity
            suspicion_level = self._assess_suspicion(path, operation, process_info)
            
            # Send to detection platform
            self._send_trace(trace_data, suspicion_level)
            
            # Log suspicious activity
            if suspicion_level > 2:
                logger.warning(f"Suspicious activity: {process_info.get('name')} {operation} {path}")
                
        except Exception as e:
            logger.error(f"Error handling file event: {e}")
            
    def _should_skip_file(self, path: Path) -> bool:
        """Determine if file should be skipped"""
        # Skip system directories
        skip_dirs = {'Windows', 'System32', 'Program Files', 'Program Files (x86)'}
        if any(part in skip_dirs for part in path.parts):
            return True
            
        # Skip temporary files
        if path.suffix in {'.tmp', '.temp', '.log', '.cache'}:
            return True
            
        # Skip very small files (likely metadata)
        try:
            if path.exists() and path.stat().st_size < 10:
                return True
        except:
            pass
            
        return False
        
    def _get_process_info_for_file(self, file_path: str) -> Dict:
        """Try to determine which process is accessing the file"""
        # This is a simplified approach - in production you'd use ETW or similar
        try:
            # Check recently active processes
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    proc_info = proc.info
                    if time.time() - proc_info['create_time'] < 300:  # Recent processes
                        return {
                            'pid': proc_info['pid'],
                            'name': proc_info['name'] or 'unknown.exe'
                        }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            # Fallback to system process
            return {'pid': 0, 'name': 'system'}
            
        except Exception:
            return {'pid': 0, 'name': 'unknown.exe'}
            
    def _get_file_size(self, path: Path) -> int:
        """Get file size safely"""
        try:
            if path.exists():
                return path.stat().st_size
        except:
            pass
        return 0
        
    def _assess_suspicion(self, path: Path, operation: str, process_info: Dict) -> int:
        """Assess suspicion level of file operation (0-5 scale)"""
        suspicion = 0
        
        # Check file extension
        if path.suffix.lower() in self.crypto_extensions:
            suspicion += 3
            
        # Check if it's in important directory
        if any(str(path).startswith(str(imp_dir)) for imp_dir in self.important_dirs):
            suspicion += 1
            
        # Check process name
        proc_name = process_info.get('name', '').lower()
        suspicious_names = ['encrypt', 'lock', 'crypto', 'ransom', 'virus']
        if any(sus in proc_name for sus in suspicious_names):
            suspicion += 2
            
        # Check operation pattern
        if operation == 'delete':
            suspicion += 1
        elif operation == 'write' and path.suffix in {'.doc', '.pdf', '.jpg', '.png'}:
            suspicion += 1
            
        return min(suspicion, 5)
        
    def _send_trace(self, trace_data: Dict, suspicion_level: int = 0):
        """Send trace to detection platform"""
        try:
            # Add suspicion level to trace
            trace_data['suspicion_level'] = suspicion_level
            
            response = requests.post(
                f"{self.server_url}/predict",
                json=trace_data,
                timeout=2
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('alert_triggered', False):
                    self._handle_alert(result, trace_data)
            elif response.status_code == 202:
                # Trace accepted but not enough data for prediction
                pass
            else:
                logger.warning(f"Unexpected response: {response.status_code}")
                
        except requests.RequestException as e:
            logger.debug(f"Failed to send trace: {e}")
            
    def _handle_alert(self, result: Dict, trace_data: Dict):
        """Handle detection alert"""
        print("\n" + "🚨" * 30)
        print("🚨 RANSOMWARE ALERT DETECTED! 🚨")
        print("🚨" * 30)
        print(f"Process: {result.get('process_name')} (PID: {result.get('process_id')})")
        print(f"File: {result.get('file_path')}")
        print(f"Risk Level: {result.get('risk_level')}")
        print(f"Detection Score: {result.get('hybrid_prediction', 0):.4f}")
        print(f"Confidence: {result.get('confidence', 0):.2f}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("🚨" * 30 + "\n")
        
        # Log to file
        logger.critical(f"RANSOMWARE DETECTED: {result.get('process_name')} - {result.get('risk_level')}")


class ProcessMonitor:
    """Monitor process activities for suspicious behavior"""
    
    def __init__(self, detection_server_url="http://localhost:8000"):
        self.server_url = detection_server_url
        self.monitoring = False
        self.process_stats = {}
        
    def start_monitoring(self):
        """Start process monitoring"""
        self.monitoring = True
        monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        monitor_thread.start()
        logger.info("Process monitoring started")
        
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.monitoring = False
        
    def _monitor_processes(self):
        """Monitor process behavior"""
        while self.monitoring:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'io_counters', 'cpu_percent', 'memory_percent']):
                    try:
                        self._analyze_process(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Process monitoring error: {e}")
                time.sleep(5)
                
    def _analyze_process(self, proc):
        """Analyze individual process for suspicious activity"""
        try:
            info = proc.info
            pid = info['pid']
            name = info['name'] or 'unknown'
            io = info['io_counters']
            
            if not io:
                return
                
            # Track I/O changes
            key = f"{name}_{pid}"
            if key not in self.process_stats:
                self.process_stats[key] = {
                    'last_read': io.read_bytes,
                    'last_write': io.write_bytes,
                    'last_check': time.time(),
                    'write_rate': 0,
                    'read_rate': 0
                }
                return
                
            prev = self.process_stats[key]
            now = time.time()
            time_diff = now - prev['last_check']
            
            if time_diff < 0.5:  # Too frequent checks
                return
                
            # Calculate I/O rates
            read_diff = io.read_bytes - prev['last_read']
            write_diff = io.write_bytes - prev['last_write']
            
            read_rate = read_diff / time_diff if time_diff > 0 else 0
            write_rate = write_diff / time_diff if time_diff > 0 else 0
            
            # Update stats
            self.process_stats[key].update({
                'last_read': io.read_bytes,
                'last_write': io.write_bytes,
                'last_check': now,
                'read_rate': read_rate,
                'write_rate': write_rate
            })
            
            # Check for suspicious patterns
            if self._is_suspicious_io_pattern(read_rate, write_rate, name):
                self._generate_process_traces(name, pid, read_diff, write_diff)
                
        except Exception as e:
            logger.debug(f"Process analysis error: {e}")
            
    def _is_suspicious_io_pattern(self, read_rate: float, write_rate: float, process_name: str) -> bool:
        """Determine if I/O pattern is suspicious"""
        # High I/O rates (> 1MB/s)
        if read_rate > 1024*1024 or write_rate > 1024*1024:
            return True
            
        # Suspicious process names
        suspicious_keywords = ['crypt', 'lock', 'encrypt', 'ransom', 'virus', 'malware']
        if any(keyword in process_name.lower() for keyword in suspicious_keywords):
            return True
            
        # High write-to-read ratio (encryption behavior)
        if read_rate > 0 and write_rate / read_rate > 0.8:
            return True
            
        return False
        
    def _generate_process_traces(self, process_name: str, pid: int, read_bytes: int, write_bytes: int):
        """Generate traces from process I/O activity"""
        traces = []
        
        if read_bytes > 0:
            traces.append({
                "timestamp": time.time(),
                "operation_type": "read",
                "file_path": f"C:\\Users\\{os.getenv('USERNAME', 'user')}\\Documents\\data_{pid}.tmp",
                "offset": 0,
                "size": int(read_bytes),
                "process_id": pid,
                "process_name": process_name
            })
            
        if write_bytes > 0:
            traces.append({
                "timestamp": time.time(),
                "operation_type": "write", 
                "file_path": f"C:\\Users\\{os.getenv('USERNAME', 'user')}\\Documents\\data_{pid}.tmp",
                "offset": 0,
                "size": int(write_bytes),
                "process_id": pid,
                "process_name": process_name
            })
            
        # Send traces
        for trace in traces:
            try:
                requests.post(f"{self.server_url}/predict", json=trace, timeout=1)
            except:
                pass  # Ignore send failures


class WindowsSystemMonitor:
    """Main Windows system monitor"""
    
    def __init__(self, detection_server_url="http://localhost:8000", monitor_paths=None):
        self.server_url = detection_server_url
        self.file_monitor = FileSystemMonitor(detection_server_url)
        self.process_monitor = ProcessMonitor(detection_server_url)
        self.observer = None
        self.running = False
        
        # Default paths to monitor
        if monitor_paths is None:
            self.monitor_paths = [
                str(Path.home() / "Documents"),
                str(Path.home() / "Desktop"),
                str(Path.home() / "Pictures"),
                str(Path.home() / "Downloads"),
                "C:\\Users\\Public"
            ]
        else:
            self.monitor_paths = monitor_paths
            
    def start_monitoring(self):
        """Start all monitoring components"""
        if self.running:
            logger.warning("Monitor already running")
            return
            
        logger.info("Starting Windows System Monitor...")
        
        # Start file system monitoring
        self.observer = Observer()
        for path in self.monitor_paths:
            if Path(path).exists():
                self.observer.schedule(self.file_monitor, path, recursive=True)
                logger.info(f"Monitoring path: {path}")
            else:
                logger.warning(f"Path not found: {path}")
                
        self.observer.start()
        
        # Start process monitoring
        self.process_monitor.start_monitoring()
        
        self.running = True
        logger.info("Windows System Monitor started successfully")
        
    def stop_monitoring(self):
        """Stop all monitoring"""
        if not self.running:
            return
            
        logger.info("Stopping Windows System Monitor...")
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
            
        self.process_monitor.stop_monitoring()
        
        self.running = False
        logger.info("Windows System Monitor stopped")
        
    def get_statistics(self) -> Dict:
        """Get monitoring statistics"""
        return {
            "running": self.running,
            "monitored_paths": len(self.monitor_paths),
            "monitored_processes": len(self.process_monitor.process_stats),
            "recent_events": len(self.file_monitor.recent_events)
        }


def test_detection_server(server_url: str) -> bool:
    """Test if detection server is accessible"""
    try:
        response = requests.get(f"{server_url}/status", timeout=5)
        if response.status_code == 200:
            status = response.json()
            print(f"✅ Detection server is running")
            print(f"   Status: {status.get('status', 'unknown')}")
            print(f"   Uptime: {status.get('uptime', 0):.1f} seconds")
            return True
        else:
            print(f"❌ Server responded with status {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"❌ Cannot connect to detection server: {e}")
        print(f"   Make sure your detection platform is running on {server_url}")
        return False


def main():
    """Main entry point for Windows monitor"""
    print("Windows File System Monitor for Ransomware Detection")
    print("=" * 60)
    
    # Configuration
    server_url = "http://localhost:8000"
    if len(sys.argv) > 1:
        server_url = sys.argv[1]
        
    # Test server connection
    if not test_detection_server(server_url):
        print("\nPlease start your detection server first:")
        print("python main.py")
        return 1
        
    # Create monitor
    monitor = WindowsSystemMonitor(server_url)
    
    try:
        # Start monitoring
        monitor.start_monitoring()
        
        print("\n🔍 File system monitoring active...")
        print("📊 Process monitoring active...")
        print("\nMonitored directories:")
        for path in monitor.monitor_paths:
            print(f"  📁 {path}")
            
        print(f"\nSending detections to: {server_url}")
        print("\n⚠️  Now run ransomware simulations or real ransomware to test detection!")
        print("Press Ctrl+C to stop monitoring...\n")
        
        # Keep running
        while True:
            time.sleep(10)
            stats = monitor.get_statistics()
            logger.info(f"Monitor stats: {stats}")
            
    except KeyboardInterrupt:
        print("\n🛑 Stopping monitor...")
        
    finally:
        monitor.stop_monitoring()
        print("✅ Monitor stopped successfully")
        
    return 0


if __name__ == "__main__":
    sys.exit(main())