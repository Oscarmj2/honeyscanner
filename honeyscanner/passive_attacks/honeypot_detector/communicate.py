import socket
import paramiko
import telnetlib
import requests
import time
import pynetdicom
import pydicom
import difflib

def socket_communication(ip, port, signature, result_dict):
    # For now check if port is something we want
    valid_list = []
    if port not in valid_list:
        return []    
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
                score.append(signature['score'])
            if result_dict:
                log_signature_result(result_dict, comp_result, i+1, signature[i]['comment'])
    except socket.timeout:
        return score
    return score

def ssh_communication(ip, port, signature, result_dict):
    # For now check if port is something we want
    valid_list = [22, 2222]
    if port not in valid_list:
        return []
    score = []

    # Connect to ssh server
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username='root', password='1234')
    channel = client.invoke_shell()
    # Execute the commands
    for i in range(len(signature)):
        channel.send(signature[i]['input'] + '\n')
        
        time.sleep(2)
        r = channel.recv(9999).decode('utf-8')
        comp_result = compare_output(r, signature[i]['output'], signature[i]['match_type'])
        if comp_result:
            score.append(signature[i]['score'])
        if result_dict:
            log_signature_result(result_dict, comp_result, i+1, signature[i]['comment'])
    return score


def telnet_communication(ip, port, signature, result_dict):
    # For now check if port is something we want
    valid_list = [9100, 6379, 6380]
    if port not in valid_list:
        return []
    score = []
    tn = telnetlib.Telnet(ip, port)
    for i in range(len(signature)):
        tn.write(signature[i]['input'].encode())
        time.sleep(2)
        r = tn.read_very_eager()
        comp_result = compare_output(r, signature[i]['output'].encode(), signature[i]['match_type'])
        if comp_result:
            score.append(signature[i]['score'])
        
        if result_dict:
            log_signature_result(result_dict, comp_result, i+1, signature[i]['comment'])
    
    return score

def requests_communication(ip, port, protocol, signature, result_dict = None):
    # For now check if port is something we want
    valid_list = [80, 443, 8000, 8080, 8888]
    if port not in valid_list:
        return []
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
        #print(f'Reponse: {r.content}')
        #print(f'Expected: {signature[i]['output'].encode()}')
        #print(f'status_code: {r.status_code} & {signature[i]['response_code']}')
        if comp_result:
            score.append(signature[i]['score'])

        if result_dict:
            log_signature_result(result_dict, comp_result, i+1, signature[i]['comment'])

    return score


def dicom_communcation(ip, port, signature, result_dict):
    # For now check if port is something we want
    valid_list = [11112, 104]
    if port not in valid_list:
        return []
    score = []
    ae = pynetdicom.AE()
    ae.add_requested_context(pynetdicom.sop_class.PatientRootQueryRetrieveInformationModelGet)
    ds = pydicom.dataset.Dataset()

    for i in range(len(signature)):
        ds.PatientName = signature[i]['input'] # For now we only use first input
        ds.QueryRetrieveLevel = "PATIENT"

        #assoc = ae.associate('198.244.176.149', port, ae_title='ANY-SCP') # IP of a public DICOM server
        assoc = ae.associate(ip, port, ae_title='ANY-SCP')

        response_string = ''
        if assoc.is_established:
            responses = assoc.send_c_get(ds, pynetdicom.sop_class.PatientRootQueryRetrieveInformationModelGet)
            for (status, identifier) in responses:
                if status:
                    print(status)
                    if pydicom.tag.BaseTag(0x00001022) in status._dict:
                        response_string += str(status._dict[pydicom.tag.BaseTag(0x00001022)])
            assoc.release()
        else:
            print('Association failed')
        comp_result = compare_output(response_string, signature[i]['output'], signature[i]['match_type'])
        if comp_result:
            score
        if result_dict:
            log_signature_result(result_dict, comp_result, 1, signature[i]['comment'])

    return score

def compare_output(response_string : str, signature_string : str, match_type : str):
    if match_type == 'fuzzy':
        return signature_string in response_string
    elif match_type == 'precise':
        return signature_string == response_string
    

def log_signature_result(result : dict, match : bool, signature_id, comment):
    result['total_signatures'] += 1
    if match:
        result['found_signatures'] += 1
        result['signature_id'].append(signature_id)
        result['comments'][str(signature_id)] = comment