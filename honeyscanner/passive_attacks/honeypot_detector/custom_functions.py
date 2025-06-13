import paramiko
import time
import requests
import socket


def cowrie_memory_persistence(ip, port):
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
            return [0.8]
        return score
    except Exception:
        return score

def gopot_timing(ip, port):
    timings = [0, 2,  4, 6, 8, 10, 15, 20, 25, 30, 40, 50]
    delta_delay = [2, 2, 2, 2, 2, 5, 5, 5, 5, 10, 10]
    port_list = [80, 8080, 8000, 8888]
    if port not in port_list:
        return []
    verbose = True
    url = 'http://' + ip + ':' + str(port) + '/IsThisAHoneypot.json'
    request_times = []
    timeouts = 0
    print(f'[*] Generating timing data')
    for i in range(15):
        try:
            start_time = time.time()
            r = requests.get(url, timeout=10)
            request_time = time.time() - start_time
            request_times.append(request_time)
            if verbose:
                print(f'#{i} -> {request_time}')
        except requests.exceptions.Timeout:
            print(f'Request #{i+1} Timed out')
            if timeouts == 1:
                print(f'2 Requests have timed out. Check if website is offline.')
                break
            timeouts += 1
        except requests.exceptions.ConnectionError:
            print('**Error** Could not connect to the website ... Stopping program')
            return []
    # Calculate The delaying
    delta_timings = []
    for i in range(len(request_times)-1):
        delta_timings.append(request_times[i+1]-request_times[i])
    
    # Find starting index (We have at the very least made two previous connections)
    for i in range(len(request_times)):
        if request_times[0]-2 < timings[i]:
            start_index = i
    
    if not start_index:
        return []
    
    for i in range(start_index+1, len(request_times)):
        pass
    


