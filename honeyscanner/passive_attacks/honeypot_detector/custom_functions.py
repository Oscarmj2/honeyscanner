import paramiko
import time
import socket


def cowrie_memory_persistence(ip, port):
    """
    Custom function that checks file persistence between sessions,
    by starting two sessions simultaneously and creating a file for
    session 1 and then check whether the file exist for both sessions 
    """
    score = []

    # Check if SSH instance
    try:
        with socket.create_connection((ip, port), timeout=2) as sock:
            banner = sock.recv(1024)
            if b'SSH' not in banner:
                return score
    except Exception:
        return score
    try:
        print(f'Running custom cowrie function')
        client1 = paramiko.SSHClient()
        client1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client1.connect(ip, port=port, username='root', password='1234')
        channel1 = client1.invoke_shell()

        client2 = paramiko.SSHClient()
        client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client2.connect(ip, port=port, username='root', password='1234')
        channel2 = client2.invoke_shell()

        channel1.send('touch IsThisAHoneypot.honeypot\n')
        time.sleep(2)
        r = channel1.recv(9999).decode('utf-8')

        # Check if file has been created
        channel1.send('ls\n')
        channel2.send('ls\n')
        time.sleep(2)
        r1 = channel1.recv(9999).decode('utf-8')
        r2 = channel2.recv(9999).decode('utf-8')

        if 'IsThisAHoneypot.honeypot' in r1 and 'IsThisAHoneypot.honeypot' not in r2:
            return [0.9]
        return score
    except Exception:
        return score
    


