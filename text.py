import socket
import sys

HOST = "0.0.0.0"
PORT = 53  # DNS port

def test_bind():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.bind((HOST, PORT))
        print(f"[+] Successfully bound to port {PORT} on {HOST}")
        print("[*] Port 53 is available!")
    except PermissionError:
        print("[-] Permission denied! On Linux/macOS, run with sudo.")
    except OSError as e:
        print(f"[-] Failed to bind port 53: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    test_bind()