import socket
import paramiko
import telnetlib
import paramiko.ssh_exception
import requests
import time
import pynetdicom
import pydicom

def socket_communication(ip, port, signature, result_dict):
    """
        Sends fingerprinting signatures from the signature dictionary,
        and checks if they correspond with the output.
        Communicates using the socket library.

        Args:
            ip (str): IP address to communicate with
            port (int): port number to communicate on.
            signature (list[dict]): list of signatures (uses the steps format from signatures.yaml).
            result (dict): A dictionary where data on fingerprint of the honeypot is stored.

        Returns:
            score (list[int]): a list of the scores from the fingerprinting.
    """
    score = []
    try:
        for i in range(len(signature)):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            s.send(signature[i]['input'].encode())
            o = s.recv(4096)
            comp_result = compare_output(o, signature[i]['output'].encode(), signature[i]['match_type'])
            if comp_result:
                score.append(signature[i]['score'])
                result_dict[i] = signature[i]['score']

            with open('detection_communcation.log', 'a') as f:
                f.write(f'Input index {i} resulting output: {o}\n')
    except Exception:
        return score
    return score

def ssh_communication(ip, port, signature, result_dict):
    """
        Sends fingerprinting signatures from the signature dictionary,
        and checks if they correspond with the output.
        Communicates using the paramiko library (ssh).

        Args:
            ip (str): IP address to communicate with
            port (int): port number to communicate on.
            signature (list[dict]): list of signatures (uses the steps format from signatures.yaml).
            result (dict): A dictionary where data on fingerprint of the honeypot is stored.

        Returns:
            score (list[int]): a list of the scores from the fingerprinting.
    """
    score = []
    # Check if port is SSH
    if not check_ssh_connection(ip, port):
        return score
    
    # Connect to ssh server
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username='root', password='1234', timeout=4)
        channel = client.invoke_shell()
        # Execute the commands
        for i in range(len(signature)):
            channel.send(signature[i]['input'] + '\n')
            
            time.sleep(2)
            r = channel.recv(9999).decode('utf-8')
            comp_result = compare_output(r, signature[i]['output'], signature[i]['match_type'])
            if comp_result:
                score.append(signature[i]['score'])
                result_dict[i] = signature[i]['score']
            
            with open('detection_communcation.log', 'a') as f:
                f.write(f'Input index {i} resulting output: {r}\n')
        return score
    except TimeoutError:
        return score
    except paramiko.ssh_exception.SSHException:
        return score
    


def telnet_communication(ip, port, signature, result_dict):
    """
        Sends fingerprinting signatures from the signature dictionary,
        and checks if they correspond with the output.
        Communicates using the telnetlib library.

        Args:
            ip (str): IP address to communicate with
            port (int): port number to communicate on.
            signature (list[dict]): list of signatures (uses the steps format from signatures.yaml).
            result (dict): A dictionary where data on fingerprint of the honeypot is stored.

        Returns:
            score (list[int]): a list of the scores from the fingerprinting.
    """
    score = []
    try:
        tn = telnetlib.Telnet(ip, port)
        for i in range(len(signature)):
            tn.write(signature[i]['input'].encode())
            time.sleep(2)
            r = tn.read_very_eager()
            comp_result = compare_output(r, signature[i]['output'].encode(), signature[i]['match_type'])
            if comp_result:
                score.append(signature[i]['score'])
                result_dict[i] = signature[i]['score']
        return score
    except Exception:
        return score

def requests_communication(ip, port, protocol, signature, result_dict = None):
    """
        Sends fingerprinting signatures from the signature dictionary,
        and checks if they correspond with the output.
        Communicates using the requests library (http/https).

        Args:
            ip (str): IP address to communicate with
            port (int): port number to communicate on.
            signature (list[dict]): list of signatures (uses the steps format from signatures.yaml).
            result (dict): A dictionary where data on fingerprint of the honeypot is stored.

        Returns:
            score (list[int]): a list of the scores from the fingerprinting.
    """
    score = []
    base_url = protocol + '://' + ip + ':' + str(port)
    for i in range(len(signature)):
        try:
            url = base_url + signature[i]['input']
            if signature[i]['method'] == 'get':
                r = requests.get(url, timeout=5, verify=False)
            elif signature[i]['method'] == 'post':
                r = requests.post(url, timeout=5, verify=False)
            else:
                print(f'Does not recognise signature method valid are \"get\" and \"post\" but got \"{signature['method']}\"')
        except requests.exceptions.ConnectionError:
            return score
        except requests.exceptions.ConnectTimeout:
            return score
        except requests.exceptions.ReadTimeout:
            return score
        
        comp_result = r.status_code == signature[i]['response_code'] and compare_output(r.content, signature[i]['output'].encode(), signature[i]['match_type'])

        if comp_result:
            score.append(signature[i]['score'])
            result_dict[i] = signature[i]['score']

        with open('detection_communcation.log', 'a') as f:
                f.write(f'Input index {i} resulting output: status_code={r.status_code}, body={r.content}\n')
    return score


def dicom_communcation(ip, port, signature, result_dict):
    """
        Sends fingerprinting signatures from the signature dictionary,
        and checks if they correspond with the output.
        Communicates using the pydicom and pynetdicom library (DICOM).

        Args:
            ip (str): IP address to communicate with
            port (int): port number to communicate on.
            signature (list[dict]): list of signatures (uses the steps format from signatures.yaml).
            result (dict): A dictionary where data on fingerprint of the honeypot is stored.

        Returns:
            score (list[int]): a list of the scores from the fingerprinting.
    """
    score = []
    ae = pynetdicom.AE()
    ae.add_requested_context(pynetdicom.sop_class.PatientRootQueryRetrieveInformationModelGet)
    ae.acse_timeout = 2
    ds = pydicom.dataset.Dataset()
    try:
        for i in range(len(signature)):
            ds.PatientID = signature[i]['input']
            ds.QueryRetrieveLevel = "PATIENT"
            
            assoc = ae.associate(ip, port, ae_title='ANY-SCP')

            if assoc.is_established:
                responses = assoc.send_c_get(ds, pynetdicom.sop_class.PatientRootQueryRetrieveInformationModelGet)
                for (status, identifier) in responses:
                    if status:
                        comp_result = compare_output(str(status), signature[i]['output'], signature[i]['match_type'])
                        with open('detection_communcation.log', 'a') as f:
                            f.write(f'Input index {i} resulting output: {status}\n')
                assoc.release()

            if comp_result:
                score.append(signature[i]['score'])
                result_dict[i] = signature[i]['score']

        return score
    except Exception:
        return score

def compare_output(response_string : str, signature_string : str, match_type : str):
    if match_type == 'fuzzy':
        return signature_string in response_string
    elif match_type == 'precise':
        return signature_string == response_string
    


def check_ssh_connection(ip, port):
    """
        Checks if the port is using ssh.

        Args:
            ip (str): IP address to communicate with.
            port (int): port number to check.

        Returns:
            bool: Boolean whether port is ssh or not.
    """
    try:
        with socket.create_connection((ip, port), timeout=2) as sock:
            banner = sock.recv(1024)
            return b'SSH' in banner
    except Exception:
        return False