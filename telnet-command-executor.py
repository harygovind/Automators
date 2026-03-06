import socket
import sys
import time

def main():
    # 1. Ask the user for the IP address
    ip_address = input("Enter the IP address to scan: ").strip()
    if not ip_address:
        print("Error: IP address cannot be empty.")
        sys.exit(1)

    # 2. Ask the user for the ports
    ports_input = input("Enter the ports required (comma-separated, e.g., 80,443,22): ").strip()
    if not ports_input:
        print("Error: Ports cannot be empty.")
        sys.exit(1)

    # Clean and parse the input into a list of integers
    try:
        ports = [int(p.strip()) for p in ports_input.split(',')]
    except ValueError:
        print("Error: Invalid port format. Please enter numbers separated by commas.")
        sys.exit(1)

    print("-" * 50)

    # 3. Loop through each port
    for port in ports:
        # Replicate the exact native telnet starting output
        print(f"[*] Command: telnet {ip_address} {port}")
        print(f"Trying {ip_address}...")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # 3-second timeout for the initial connection
                s.settimeout(3.0) 
                s.connect((ip_address, port))
                
                # Replicate the native telnet successful connection output
                print(f"Connected to {ip_address}.")
                print("Escape character is '^]'.")
                
                # Check for any initial welcome banner the server might send
                try:
                    s.settimeout(1.0)
                    banner = s.recv(4096).decode('utf-8', errors='ignore')
                    if banner:
                        print(banner, end='') # end='' prevents adding extra blank lines
                except socket.timeout:
                    pass 
                
                # --- VISUALLY ENTER THE HELP COMMAND ---
                print("help")
                s.sendall(b"help\r\n")
                
                # Give the server a brief moment to process and respond
                time.sleep(1) 
                
                # Receive and print the response to 'help'
                try:
                    s.settimeout(3.0) 
                    response = s.recv(4096).decode('utf-8', errors='ignore')
                    if response:
                        print(response, end='')
                except socket.timeout:
                    pass
                
                # --- VISUALLY ENTER THE EXIT COMMAND ---
                print("exit")
                s.sendall(b"exit\r\n")
                
                # Replicate the native telnet closing output
                print("Connection closed by foreign host.")
                
        except ConnectionRefusedError:
            print(f"telnet: Unable to connect to remote host: Connection refused")
        except socket.timeout:
            print(f"telnet: Unable to connect to remote host: Connection timed out")
        except Exception as e:
            print(f"telnet: Unable to connect to remote host: {e}")
            
        print("-" * 50)

if __name__ == "__main__":
    main()
