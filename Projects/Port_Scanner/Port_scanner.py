import sys
import socket
from datetime import datetime

# defining target
if len(sys.argv) == 2:
    target = socket.gethostbyname(sys.argv[1])
else:
    print("Syntax Error: <IP>")
    sys.exit()

# Banner
print("_" * 50)
print("[+]  Scanning Target: " + target)
print("[+]  Time Started: " + str(datetime.now()))
print("_" * 50)

socket.setdefaulttimeout(1)

# scanning ports
try:
    for ports in range(1,65535):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((target, ports))  # 0 means port is open
        if result == 0:
            print(f"{ports} OPEN")
        s.close()

except KeyboardInterrupt:
    print("Exiting the program")
    sys.exit()

except socket.gaierror:
    print("Host name could not be resolved")
    sys.exit()

except socket.error:
    print("Error: could not connect to the server")
    sys.exit()