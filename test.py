#!/usr/bin/env python3
"""
DNS Port 53 Bind Tester - Automatic multi-platform tool.
Automatically detects, reports, and attempts to free port 53.

Just run: python3 dns_test.py
"""

import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time

__version__ = "1.0.0"

# =============================================================================
# COLORS & OUTPUT
# =============================================================================
IS_TTY = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
IS_WINDOWS = platform.system() == "Windows"

# Windows color support
if IS_WINDOWS and IS_TTY:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        IS_TTY = False

def c(text, code):
    """Colorize text."""
    return f"\033[{code}m{text}\033[0m" if IS_TTY else text

def green(t): return c(t, "32")
def red(t): return c(t, "31")
def yellow(t): return c(t, "33")
def cyan(t): return c(t, "36")
def bold(t): return c(t, "1")

def header(text):
    """Print section header."""
    line = "═" * 55
    print(f"\n{cyan(line)}")
    print(f"{cyan('║')} {bold(text)}")
    print(f"{cyan(line)}")

def ok(text): 
    print(f"  {green('✓')} {text}")

def fail(text): 
    print(f"  {red('✗')} {text}")

def warn(text): 
    print(f"  {yellow('!')} {text}")

def info(text): 
    print(f"  {cyan('•')} {text}")

# =============================================================================
# SYSTEM UTILITIES
# =============================================================================
def is_root():
    """Check for admin/root privileges."""
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0

def run(cmd, timeout=10):
    """Run command and return output."""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", -1
    except Exception as e:
        return str(e), -1

def run_silent(cmd):
    """Run command, return success bool."""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False

# =============================================================================
# PORT TESTING
# =============================================================================
def test_bind(port=53):
    """Test TCP and UDP binding on port."""
    results = {"tcp": False, "udp": False, "tcp_err": "", "udp_err": ""}
    
    # TCP test
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            results["tcp"] = True
    except OSError as e:
        results["tcp_err"] = e.strerror or str(e)
    
    # UDP test
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            results["udp"] = True
    except OSError as e:
        results["udp_err"] = e.strerror or str(e)
    
    return results

# =============================================================================
# PROCESS DETECTION
# =============================================================================
def find_processes_windows(port):
    """Find processes using port on Windows."""
    procs = []
    seen = set()
    
    out, _ = run(f"netstat -ano | findstr :{port}")
    
    for line in out.splitlines():
        line = line.strip()
        if not line or f":{port}" not in line:
            continue
        
        parts = line.split()
        if len(parts) < 5:
            continue
        
        try:
            pid = int(parts[-1])
            if pid == 0 or pid in seen:
                continue
            seen.add(pid)
            
            # Get process name
            name_out, _ = run(f'tasklist /FI "PID eq {pid}" /FO CSV /NH')
            name = "Unknown"
            if name_out:
                try:
                    name = name_out.strip().split(",")[0].strip('"')
                except Exception:
                    pass
            
            proto = "TCP" if "TCP" in line.upper() else "UDP"
            procs.append({"pid": pid, "name": name, "proto": proto})
        except (ValueError, IndexError):
            continue
    
    return procs

def find_processes_linux(port):
    """Find processes using port on Linux/macOS."""
    procs = []
    seen = set()
    
    # Try lsof (most reliable)
    if shutil.which("lsof"):
        out, _ = run(f"lsof -nP -i :{port} 2>/dev/null")
        for line in out.splitlines()[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 2:
                try:
                    pid = int(parts[1])
                    if pid not in seen:
                        seen.add(pid)
                        proto = "TCP" if "TCP" in line.upper() else "UDP"
                        procs.append({"pid": pid, "name": parts[0], "proto": proto})
                except ValueError:
                    continue
        return procs
    
    # Try ss
    if shutil.which("ss"):
        for proto_flag, proto_name in [("-tln", "TCP"), ("-uln", "UDP")]:
            out, _ = run(f"ss {proto_flag}p 'sport = :{port}' 2>/dev/null")
            for line in out.splitlines():
                match = re.search(r'pid=(\d+)', line)
                if match:
                    pid = int(match.group(1))
                    if pid not in seen:
                        seen.add(pid)
                        name_match = re.search(r'"([^"]+)"', line)
                        name = name_match.group(1) if name_match else "Unknown"
                        procs.append({"pid": pid, "name": name, "proto": proto_name})
        return procs
    
    # Fallback to netstat
    if shutil.which("netstat"):
        out, _ = run(f"netstat -tlnp 2>/dev/null | grep ':{port} '")
        for line in out.splitlines():
            if "/" in line:
                try:
                    pid_prog = line.split()[-1]
                    pid, name = pid_prog.split("/", 1)
                    pid = int(pid)
                    if pid not in seen:
                        seen.add(pid)
                        procs.append({"pid": pid, "name": name, "proto": "TCP/UDP"})
                except (ValueError, IndexError):
                    continue
    
    return procs

def find_processes(port=53):
    """Find processes using port (cross-platform)."""
    if IS_WINDOWS:
        return find_processes_windows(port)
    return find_processes_linux(port)

# =============================================================================
# SERVICE DETECTION
# =============================================================================
def detect_services_windows():
    """Detect DNS services on Windows."""
    services = []
    
    dns_services = [
        ("DNS Client", "Dnscache"),
        ("DNS Server", "DNS"),
    ]
    
    for display_name, service_name in dns_services:
        out, code = run(f'sc query {service_name} | findstr "RUNNING"')
        if code == 0 and "RUNNING" in out:
            services.append({
                "name": display_name,
                "service": service_name,
                "stop_cmd": f"net stop {service_name}"
            })
    
    return services

def detect_services_linux():
    """Detect DNS services on Linux."""
    services = []
    
    dns_services = [
        ("systemd-resolved", "systemd-resolved"),
        ("dnsmasq", "dnsmasq"),
        ("bind9", "bind9"),
        ("named", "named"),
        ("unbound", "unbound"),
        ("coredns", "coredns"),
    ]
    
    for name, service in dns_services:
        if run_silent(f"systemctl is-active --quiet {service}"):
            services.append({
                "name": name,
                "service": service,
                "stop_cmd": f"systemctl stop {service}"
            })
    
    return services

def detect_services():
    """Detect DNS services (cross-platform)."""
    if IS_WINDOWS:
        return detect_services_windows()
    return detect_services_linux()

# =============================================================================
# PROCESS/SERVICE MANAGEMENT
# =============================================================================
def kill_process(pid):
    """Kill process by PID."""
    if IS_WINDOWS:
        return run_silent(f"taskkill /PID {pid} /F")
    return run_silent(f"kill -9 {pid}")

def stop_service(svc):
    """Stop a service."""
    cmd = svc.get("stop_cmd", "")
    if not cmd:
        return False
    return run_silent(cmd)

# =============================================================================
# MAIN LOGIC
# =============================================================================
def attempt_free_port(port=53):
    """Attempt to free the port by stopping services and killing processes."""
    freed = False
    
    # Stop services first
    services = detect_services()
    if services:
        header("Stopping DNS Services")
        for svc in services:
            info(f"Stopping {svc['name']}...")
            if stop_service(svc):
                ok(f"Stopped {svc['name']}")
                freed = True
            else:
                fail(f"Could not stop {svc['name']}")
        time.sleep(1)
    
    # Kill remaining processes
    procs = find_processes(port)
    if procs:
        header("Killing Blocking Processes")
        for p in procs:
            info(f"Killing PID {p['pid']} ({p['name']})...")
            if kill_process(p["pid"]):
                ok(f"Killed {p['name']} (PID {p['pid']})")
                freed = True
            else:
                fail(f"Could not kill PID {p['pid']}")
        time.sleep(0.5)
    
    return freed

def main():
    port = 53
    
    # Banner
    print()
    print(bold(cyan("╔═══════════════════════════════════════════════════════╗")))
    print(bold(cyan("║")) + bold("   🔍 DNS Port 53 Bind Tester v" + __version__) + bold(cyan("                    ║")))
    print(bold(cyan("╚═══════════════════════════════════════════════════════╝")))
    
    # System info
    header("System Information")
    info(f"Platform: {platform.system()} {platform.release()}")
    info(f"Python: {platform.python_version()}")
    
    root = is_root()
    if root:
        ok("Running with administrator/root privileges")
    else:
        warn("Running without admin/root privileges")
        if not IS_WINDOWS:
            warn("Port 53 requires root - run with: sudo python3 " + sys.argv[0])
    
    # Initial bind test
    header(f"Initial Port {port} Bind Test")
    result = test_bind(port)
    
    tcp_status = green("Available") if result["tcp"] else red("Blocked")
    udp_status = green("Available") if result["udp"] else red("Blocked")
    
    info(f"TCP: {tcp_status}" + (f" ({result['tcp_err']})" if result["tcp_err"] else ""))
    info(f"UDP: {udp_status}" + (f" ({result['udp_err']})" if result["udp_err"] else ""))
    
    # If already available, we're done
    if result["tcp"] and result["udp"]:
        header("Result")
        ok(green(bold(f"Port {port} is AVAILABLE! ✓")))
        print()
        return 0
    
    # Detect what's using the port
    header("Detecting Port Usage")
    
    # Check services
    services = detect_services()
    if services:
        warn("Active DNS services found:")
        for svc in services:
            print(f"      - {yellow(svc['name'])}")
    else:
        ok("No known DNS services detected")
    
    # Check processes
    procs = find_processes(port)
    if procs:
        warn(f"Processes using port {port}:")
        for p in procs:
            print(f"      - PID {yellow(str(p['pid']))}: {p['name']} ({p['proto']})")
    else:
        ok("No processes found on port (may need root to detect)")
    
    # Attempt to free port if we have privileges
    if root and (services or procs):
        attempt_free_port(port)
        
        # Re-test after cleanup
        header(f"Re-testing Port {port}")
        time.sleep(0.5)
        result = test_bind(port)
        
        tcp_status = green("Available") if result["tcp"] else red("Blocked")
        udp_status = green("Available") if result["udp"] else red("Blocked")
        
        info(f"TCP: {tcp_status}")
        info(f"UDP: {udp_status}")
    
    # Final result
    header("Final Result")
    
    if result["tcp"] and result["udp"]:
        ok(green(bold(f"Port {port} is now AVAILABLE! ✓")))
        print()
        return 0
    
    elif result["tcp"] or result["udp"]:
        proto_ok = "TCP" if result["tcp"] else "UDP"
        proto_fail = "UDP" if result["tcp"] else "TCP"
        warn(yellow(bold(f"Partial: {proto_ok} available, {proto_fail} blocked")))
        print()
        return 1
    
    else:
        fail(red(bold(f"Port {port} is NOT available ✗")))
        print()
        
        # Show help
        header("Troubleshooting")
        
        if not root:
            info("Run with administrator/root privileges:")
            if IS_WINDOWS:
                print(f"      Right-click → Run as Administrator")
            else:
                print(f"      sudo python3 {sys.argv[0]}")
        
        if services:
            info("Manually stop DNS services:")
            for svc in services:
                print(f"      {svc['stop_cmd']}")
        
        if procs:
            info("Manually kill processes:")
            for p in procs:
                if IS_WINDOWS:
                    print(f"      taskkill /PID {p['pid']} /F")
                else:
                    print(f"      sudo kill -9 {p['pid']}")
        
        info("Or use an alternate port (5353, 5533, etc.)")
        print()
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{yellow('Interrupted by user')}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{red('Error:')} {e}")
        sys.exit(1)
