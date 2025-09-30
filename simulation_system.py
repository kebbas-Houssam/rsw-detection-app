#!/usr/bin/env python3
"""
Ransomware Detection Simulation System
For Master's Degree Defense - Comprehensive System Monitoring & Ransomware Simulation

This script provides:
1. Real-time system monitoring (file I/O operations)
2. Ransomware behavior simulation
3. Integration with your detection platform
4. VMware-friendly implementation
"""

import os
import sys
import time
import json
import random
import threading
import requests
import psutil
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("simulation.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("ransomware_simulation")

class SystemMonitor:
    """Monitor real system I/O operations and send to detection platform"""
    
    def __init__(self, detection_server_url="http://localhost:8000"):
        self.server_url = detection_server_url
        self.monitoring = False
        self.processes_cache = {}
        self.io_stats = defaultdict(list)
        
    def start_monitoring(self):
        """Start monitoring system I/O operations"""
        self.monitoring = True
        monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("System monitoring started")
        
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        logger.info("System monitoring stopped")
        
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self._capture_io_operations()
                time.sleep(0.1)  # Check every 100ms
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(1)
                
    def _capture_io_operations(self):
        """Capture current I/O operations from running processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    io = proc.info['io_counters']
                    
                    if io and name:
                        # Check for new I/O activity
                        key = f"{name}_{pid}"
                        if key not in self.processes_cache:
                            self.processes_cache[key] = {
                                'read_bytes': io.read_bytes,
                                'write_bytes': io.write_bytes
                            }
                        else:
                            prev = self.processes_cache[key]
                            read_diff = io.read_bytes - prev['read_bytes']
                            write_diff = io.write_bytes - prev['write_bytes']
                            
                            if read_diff > 0 or write_diff > 0:
                                self._send_io_trace(name, pid, read_diff, write_diff)
                                
                            self.processes_cache[key] = {
                                'read_bytes': io.read_bytes,
                                'write_bytes': io.write_bytes
                            }
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"I/O capture error: {e}")
            
    def _send_io_trace(self, process_name: str, pid: int, read_bytes: int, write_bytes: int):
        """Send I/O trace to detection platform"""
        try:
            # Simulate file operations based on I/O activity
            operations = []
            
            if read_bytes > 0:
                operations.append({
                    "timestamp": time.time(),
                    "operation_type": "read",
                    "file_path": f"C:\\Users\\{os.getenv('USERNAME', 'user')}\\Documents\\file_{random.randint(1,1000)}.txt",
                    "offset": random.randint(0, 10000),
                    "size": read_bytes,
                    "process_id": pid,
                    "process_name": process_name
                })
                
            if write_bytes > 0:
                operations.append({
                    "timestamp": time.time(),
                    "operation_type": "write",
                    "file_path": f"C:\\Users\\{os.getenv('USERNAME', 'user')}\\Documents\\file_{random.randint(1,1000)}.txt",
                    "offset": random.randint(0, 10000),
                    "size": write_bytes,
                    "process_id": pid,
                    "process_name": process_name
                })
                
            # Send to detection platform
            for op in operations:
                try:
                    response = requests.post(f"{self.server_url}/predict", json=op, timeout=1)
                    if response.status_code == 200:
                        result = response.json()
                        if result.get('alert_triggered', False):
                            logger.warning(f"ALERT: {process_name} (PID: {pid}) - Risk: {result.get('risk_level', 'UNKNOWN')}")
                except requests.RequestException:
                    pass  # Server might be down, continue monitoring
                    
        except Exception as e:
            logger.error(f"Send trace error: {e}")


class RansomwareSimulator:
    """Simulate various ransomware behaviors for testing"""
    
    def __init__(self, detection_server_url="http://localhost:8000"):
        self.server_url = detection_server_url
        self.simulation_dir = Path("./simulation_files")
        self.simulation_dir.mkdir(exist_ok=True)
        self.running_simulations = []
        
    def create_test_files(self, count=100):
        """Create test files for simulation"""
        logger.info(f"Creating {count} test files...")
        for i in range(count):
            file_path = self.simulation_dir / f"test_file_{i:03d}.txt"
            with open(file_path, 'w') as f:
                # Create files with varying content sizes
                content_size = random.randint(100, 5000)
                content = "A" * content_size
                f.write(content)
        logger.info(f"Created {count} test files in {self.simulation_dir}")
        
    # def simulate_crypto_ransomware(self, duration=60):
        # """Simulate CryptoLocker-style ransomware behavior"""
        # logger.info("Starting CryptoLocker simulation...")
        # 
        # def crypto_behavior():
            # process_name = "crypto_sim.exe"
            # pid = random.randint(2000, 9999)
            # 
            # start_time = time.time()
            # file_count = 0
            # 
            # while time.time() - start_time < duration:
                # try:
                    # Select random test file
                    # files = list(self.simulation_dir.glob("*.txt"))
                    # if not files:
                        # break
                        # 
                    # target_file = random.choice(files)
                    # 
                    # Simulate ransomware I/O pattern
                    # traces = self._generate_crypto_traces(target_file, process_name, pid)
                    # 
                    # Send traces to detection platform
                    # for trace in traces:
                        # self._send_trace(trace)
                        # time.sleep(random.uniform(0.01, 0.05))  # Rapid I/O
                        # 
                    # file_count += 1
                    # 
                    # Simulate file encryption (rename to .encrypted)
                    # encrypted_path = target_file.with_suffix('.encrypted')
                    # if target_file.exists():
                        # target_file.rename(encrypted_path)
                    # 
                    # if file_count % 10 == 0:
                        # logger.info(f"Crypto simulation: {file_count} files processed")
                        # 
                # except Exception as e:
                    # logger.error(f"Crypto simulation error: {e}")
                    # 
            # logger.info(f"CryptoLocker simulation completed: {file_count} files processed")
            # 
        # thread = threading.Thread(target=crypto_behavior, daemon=True)
        # thread.start()
        # self.running_simulations.append(thread)
        # return thread
    def simulate_crypto_ransomware_direct(self):
        """Direct injection - sends 100 traces immediately"""
        process_name = "crypto_sim.exe"
        pid = 9999
        
        print(f"\nDirect Crypto Injection: {process_name}")
        print("Generating 100 I/O traces...")
        
        traces = []
        base_time = time.time()
        
        for i in range(100):
            offset = i * 4096
            
            # Read operation
            traces.append({
                "timestamp": base_time + (i * 0.01),
                "operation_type": "read",
                "file_path": "C:\\Users\\test\\document.pdf",
                "offset": offset,
                "size": 4096,
                "process_id": pid,
                "process_name": process_name
            })
            
            # Write operation (encryption)
            traces.append({
                "timestamp": base_time + (i * 0.01) + 0.005,
                "operation_type": "write",
                "file_path": "C:\\Users\\test\\document.pdf",
                "offset": offset,
                "size": 4096,
                "process_id": pid,
                "process_name": process_name
            })
        
        print(f"Sending {len(traces)} traces via batch API...")
        
        try:
            response = requests.post(
                f"{self.server_url}/traces/batch",
                json=traces,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"\nBatch Result:")
                print(f"  Traces processed: {result.get('traces_processed')}")
                print(f"  Predictions made: {result.get('predictions_made')}")
                
                predictions = result.get('predictions', [])
                if predictions:
                    for pred in predictions:
                        print(f"\n{'='*60}")
                        print(f"DETECTION:")
                        print(f"  Process: {pred['process_name']} (PID: {pred['process_id']})")
                        print(f"  Primary: {pred['primary_prediction']:.4f}")
                        print(f"  Hybrid: {pred['hybrid_prediction']:.4f}")
                        print(f"  Risk: {pred['risk_level']}")
                        print(f"  ALERT: {'YES' if pred['alert_triggered'] else 'NO'}")
                        print(f"{'='*60}")
                else:
                    print("\nNo predictions generated (need more traces)")
                    
                    # Check buffer
                    time.sleep(1)
                    check = requests.get(f"{self.server_url}/debug/force_predict/{process_name}/{pid}")
                    if check.status_code == 200:
                        print(f"Buffer status: {check.json()}")
            else:
                print(f"Batch failed with status: {response.status_code}")
                
        except Exception as e:
            print(f"Error: {e}")
    
    def simulate_locker_ransomware_direct(self):
        """Direct locker simulation"""
        process_name = "locker_sim.exe"
        pid = 8888
        
        print(f"\nDirect Locker Injection: {process_name}")
        
        traces = []
        base_time = time.time()
        
        system_files = [
            "C:\\Windows\\System32\\kernel32.dll",
            "C:\\Windows\\System32\\user32.dll",
            "C:\\Windows\\System32\\ntdll.dll",
            "C:\\Windows\\explorer.exe"
        ]
        
        # Generate many rapid reads of system files
        for i in range(50):
            for sys_file in system_files:
                traces.append({
                    "timestamp": base_time + (len(traces) * 0.01),
                    "operation_type": "read",
                    "file_path": sys_file,
                    "offset": i * 1000,
                    "size": random.randint(1000, 10000),
                    "process_id": pid,
                    "process_name": process_name
                })
        
        print(f"Sending {len(traces)} traces...")
        self._send_batch(traces, process_name, pid)   
    
    def simulate_wiper_ransomware_direct(self):
        """Direct wiper simulation"""
        process_name = "wiper_sim.exe"
        pid = 7777
        
        print(f"\nDirect Wiper Injection: {process_name}")
        
        traces = []
        base_time = time.time()
        
        # Aggressive large writes
        for i in range(100):
            traces.append({
                "timestamp": base_time + (i * 0.01),
                "operation_type": "write",
                "file_path": f"C:\\Users\\test\\important_{i % 10}.doc",
                "offset": 0,
                "size": random.randint(50000, 500000),
                "process_id": pid,
                "process_name": process_name
            })
        
        print(f"Sending {len(traces)} traces...")
        self._send_batch(traces, process_name, pid)   
    
    def _send_batch(self, traces, process_name, pid):
        """Helper to send batch and show results"""
        try:
            response = requests.post(
                f"{self.server_url}/traces/batch",
                json=traces,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"Processed: {result.get('traces_processed')} traces")
                
                predictions = result.get('predictions', [])
                if predictions:
                    for pred in predictions:
                        print(f"\nDETECTION: {pred['risk_level']} "
                              f"(Hybrid: {pred['hybrid_prediction']:.4f})")
                else:
                    print("No predictions yet")
                    
        except Exception as e:
            print(f"Error: {e}")    


    def simulate_crypto_ransomware(self, duration=60):
        """Send traces in batches for faster detection"""
    def crypto_behavior():
            process_name = "crypto_sim.exe"
            pid = random.randint(2000, 9999)
            start_time = time.time()
            
            while time.time() - start_time < duration:
                files = list(self.simulation_dir.glob("*.txt"))
                if not files:
                    break
                
                target_file = random.choice(files)
                
                # Generate batch of 60 traces (more than sequence_length=50)
                traces_batch = []
                
                for i in range(60):
                    offset = random.randint(0, 10000)
                    size = random.randint(512, 8192)
                    
                    # Read trace
                    traces_batch.append({
                        "timestamp": time.time() + (i * 0.001),
                        "operation_type": "read",
                        "file_path": str(target_file),
                        "offset": offset,
                        "size": size,
                        "process_id": pid,
                        "process_name": process_name
                    })
                    
                    # Write trace
                    traces_batch.append({
                        "timestamp": time.time() + (i * 0.001) + 0.0005,
                        "operation_type": "write",
                        "file_path": str(target_file),
                        "offset": offset,
                        "size": size,
                        "process_id": pid,
                        "process_name": process_name
                    })
                
                # Send batch
                print(f"Sending batch of {len(traces_batch)} traces for {process_name}...")
                
                try:
                    response = requests.post(
                        f"{self.server_url}/traces/batch",
                        json=traces_batch,
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        print(f"  Batch processed: {result.get('traces_processed')} traces")
                        print(f"  Predictions made: {result.get('predictions_made')}")
                        
                        if result.get('predictions'):
                            for pred in result['predictions']:
                                print(f"  PREDICTION: {pred.get('hybrid_prediction', 0):.4f} - {pred.get('risk_level')}")
                except Exception as e:
                    print(f"  Batch send error: {e}")
                
                time.sleep(2)  # Wait between batches      
    def simulate_locker_ransomware(self, duration=30):
        """Simulate screen-locker ransomware behavior"""
        logger.info("Starting Locker simulation...")
        
        def locker_behavior():
            process_name = "locker_sim.exe"
            pid = random.randint(3000, 9999)
            
            start_time = time.time()
            
            while time.time() - start_time < duration:
                try:
                    # Simulate system file access patterns
                    system_files = [
                        "C:\\Windows\\System32\\kernel32.dll",
                        "C:\\Windows\\System32\\user32.dll",
                        "C:\\Windows\\System32\\ntdll.dll",
                        "C:\\Windows\\explorer.exe"
                    ]
                    
                    for sys_file in system_files:
                        traces = [{
                            "timestamp": time.time(),
                            "operation_type": "read",
                            "file_path": sys_file,
                            "offset": random.randint(0, 100000),
                            "size": random.randint(1000, 10000),
                            "process_id": pid,
                            "process_name": process_name
                        }]
                        
                        for trace in traces:
                            self._send_trace(trace)
                            
                    time.sleep(random.uniform(0.5, 2.0))
                    
                except Exception as e:
                    logger.error(f"Locker simulation error: {e}")
                    
            logger.info("Locker simulation completed")
            
        thread = threading.Thread(target=locker_behavior, daemon=True)
        thread.start()
        self.running_simulations.append(thread)
        return thread
        
    def simulate_wiper_ransomware(self, duration=45):
        """Simulate data-wiper ransomware behavior"""
        logger.info("Starting Wiper simulation...")
        
        def wiper_behavior():
            process_name = "wiper_sim.exe"
            pid = random.randint(4000, 9999)
            
            start_time = time.time()
            files_wiped = 0
            
            while time.time() - start_time < duration:
                try:
                    # Target user documents
                    user_dirs = [
                        Path.home() / "Documents",
                        Path.home() / "Pictures",
                        Path.home() / "Desktop"
                    ]
                    
                    # Simulate aggressive file overwriting
                    for _ in range(random.randint(3, 8)):
                        trace = {
                            "timestamp": time.time(),
                            "operation_type": "write",
                            "file_path": f"C:\\Users\\{os.getenv('USERNAME')}\\Documents\\important_{random.randint(1,100)}.doc",
                            "offset": 0,
                            "size": random.randint(50000, 500000),  # Large writes
                            "process_id": pid,
                            "process_name": process_name
                        }
                        self._send_trace(trace)
                        files_wiped += 1
                        
                    time.sleep(random.uniform(0.1, 0.3))  # Aggressive timing
                    
                except Exception as e:
                    logger.error(f"Wiper simulation error: {e}")
                    
            logger.info(f"Wiper simulation completed: {files_wiped} operations")
            
        thread = threading.Thread(target=wiper_behavior, daemon=True)
        thread.start()
        self.running_simulations.append(thread)
        return thread
        
    def _generate_crypto_traces(self, file_path: Path, process_name: str, pid: int) -> List[Dict]:
        """Generate realistic crypto-ransomware I/O traces"""
        traces = []
        file_size = file_path.stat().st_size if file_path.exists() else 1000
        
        # Read original file
        for offset in range(0, file_size, 4096):
            traces.append({
                "timestamp": time.time(),
                "operation_type": "read",
                "file_path": str(file_path),
                "offset": offset,
                "size": min(4096, file_size - offset),
                "process_id": pid,
                "process_name": process_name
            })
            
        # Write encrypted data back
        for offset in range(0, file_size, 4096):
            traces.append({
                "timestamp": time.time(),
                "operation_type": "write",
                "file_path": str(file_path),
                "offset": offset,
                "size": min(4096, file_size - offset),
                "process_id": pid,
                "process_name": process_name
            })
            
        return traces
        
    def _send_trace(self, trace: Dict):
        """Send trace to detection platform"""
        try:
            response = requests.post(f"{self.server_url}/predict", json=trace, timeout=2)
            if response.status_code == 200:
                result = response.json()
                if result.get('alert_triggered', False):
                    logger.warning(f"🚨 RANSOMWARE DETECTED: {trace['process_name']} - Risk: {result.get('risk_level')}")
                    print(f"\n{'='*60}")
                    print(f"🚨 RANSOMWARE ALERT TRIGGERED!")
                    print(f"Process: {trace['process_name']} (PID: {trace['process_id']})")
                    print(f"Risk Level: {result.get('risk_level', 'UNKNOWN')}")
                    print(f"Confidence: {result.get('confidence', 0):.2f}")
                    print(f"File: {trace['file_path']}")
                    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"{'='*60}\n")
                    
        except requests.RequestException as e:
            logger.debug(f"Failed to send trace: {e}")


class SimulationController:
    
    """Main controller for the simulation system"""
    
    def __init__(self, detection_server_url="http://localhost:8000"):
        self.server_url = detection_server_url
        self.monitor = SystemMonitor(detection_server_url)
        self.simulator = RansomwareSimulator(detection_server_url)
        self.running = False
        
    def start_simulation(self):
        # """Start the complete simulation system"""
        # print("\n" + "="*80)
        # print("🛡️  RANSOMWARE DETECTION SIMULATION SYSTEM")
        # print("    Master's Degree Defense - Live Demonstration")
        # print("="*80)
        # 
        
        # if not self._check_server():
            # print("❌ Detection server is not running!")
            # print("   Please start your detection platform first: python main.py")
            # return False
            # 
        # print("✅ Detection server is running")
        # 
        
        # self.simulator.create_test_files(50)
        
        
        # self.monitor.start_monitoring()
        # print("✅ System monitoring started")
        # 
        print("System monitoring DISABLED for direct injection testing")
        self.running = True
        
        # Show menu
        self._show_menu()
        
        # return True
        
    def _check_server(self) -> bool:
        """Check if detection server is accessible"""
        try:
            response = requests.get(f"{self.server_url}/status", timeout=5)
            return response.status_code == 200
        except:
            return False
            
    def _show_menu(self):
        """Show interactive menu"""
        while self.running:
            print("\n" + "-"*50)
            print("SIMULATION CONTROL MENU:")
            print("1. CryptoLocker Direct Injection (Fast)")
            print("2. Screen Locker Direct Injection (Fast)")
            print("3. Data Wiper Direct Injection (Fast)")
            print("4. CryptoLocker Slow Simulation (60s)")
            print("5. Generate Test Alert")
            print("6. Check System Status")
            print("7. View Recent Alerts")
            print("0. Exit")
            print("-"*50)
            
            try:
                choice = input("Select option (0-7): ").strip()
                
                if choice == "1":
                    self.simulator.simulate_crypto_ransomware_direct()
                    
                elif choice == "2":
                    self.simulator.simulate_locker_ransomware_direct()
                    
                elif choice == "3":
                    self.simulator.simulate_wiper_ransomware_direct()
                    
                elif choice == "4":
                    self.simulator.simulate_crypto_ransomware(60)
                    print("Slow simulation started (60 seconds)")
                    
                elif choice == "5":
                    self._generate_test_alert()
                    
                elif choice == "6":
                    self._show_system_status()
                    
                elif choice == "7":
                    self._show_recent_alerts()
                    
                elif choice == "0":
                    print("Exiting simulation system...")
                    self.running = False
                    
                else:
                    print("Invalid option. Please select 0-7.")

            except KeyboardInterrupt:
                print("\n🛑 Interrupted by user")
                self.running = False
                
        self.cleanup()
        
    def _generate_test_alert(self):
        """Generate a test alert"""
        try:
            response = requests.post(f"{self.server_url}/test/alert", timeout=5)
            if response.status_code == 200:
                print("✅ Test alert generated successfully!")
            else:
                print(f"❌ Failed to generate test alert: {response.status_code}")
        except Exception as e:
            print(f"❌ Error generating test alert: {e}")
            
    def _show_system_status(self):
        """Show current system status"""
        try:
            response = requests.get(f"{self.server_url}/status", timeout=5)
            if response.status_code == 200:
                status = response.json()
                print(f"\n📊 SYSTEM STATUS:")
                print(f"   Status: {status['status']}")
                print(f"   Uptime: {status['uptime']:.1f} seconds")
                print(f"   Total Predictions: {status['total_predictions']}")
                print(f"   Alerts Triggered: {status['alerts_triggered']}")
                print(f"   Active Processes: {status['current_load']['active_processes']}")
            else:
                print("❌ Failed to get system status")
        except Exception as e:
            print(f"❌ Error getting status: {e}")
            
    def _show_recent_alerts(self):
        """Show recent alerts"""
        try:
            response = requests.get(f"{self.server_url}/alerts?limit=10", timeout=5)
            if response.status_code == 200:
                data = response.json()
                alerts = data.get('recent_alerts', [])
                print(f"\n🚨 RECENT ALERTS ({len(alerts)} shown):")
                for alert in alerts[-5:]:  # Show last 5
                    print(f"   • {alert['process_name']} (PID: {alert['process_id']})")
                    print(f"     Risk: {alert['risk_level']}, Score: {alert['hybrid_prediction']:.3f}")
                    print(f"     Time: {alert['timestamp']}")
                    print()
            else:
                print("❌ Failed to get recent alerts")
        except Exception as e:
            print(f"❌ Error getting alerts: {e}")
            
    def cleanup(self):
        """Clean up resources"""
        self.monitor.stop_monitoring()
        print("✅ Simulation system stopped")


def main():
    """Main entry point"""
    print("Initializing Ransomware Detection Simulation System...")
    
    # Default detection server URL
    server_url = "http://localhost:8000"
    
    # Allow command line argument for server URL
    if len(sys.argv) > 1:
        server_url = sys.argv[1]
        
    controller = SimulationController(server_url)
    
    try:
        if controller.start_simulation():
            print("\n✅ Simulation system started successfully!")
        else:
            print("\n❌ Failed to start simulation system")
            return 1
            
    except KeyboardInterrupt:
        print("\n🛑 Simulation interrupted by user")
        controller.cleanup()
        return 0
        
    return 0


if __name__ == "__main__":
    sys.exit(main())