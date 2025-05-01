import requests
import socket
import ssl
import yaml
import datetime

from colorama import Fore
from core import Honeyscanner
from pathlib import Path
from typing import TypeAlias
from passive_attacks.honeypot_detector import custom_functions

from .communicate import socket_communication, ssh_communication, telnet_communication, requests_communication, dicom_communcation
PortSet: TypeAlias = set[int]


class HoneypotDetector:

    def __init__(self, ip: str) -> None:
        """
        Initializes a new HoneypotDetector object.

        Args:
            ip (str): IP address of the host to check.
        """
        self.ip = ip
        signatures_path = Path(__file__).parent / "signatures.yaml"
        signature_score_path = Path(__file__).parent / "scoring.yaml"
        self.log_file = "test.log"
        with open(signatures_path, "r") as stream:
            self.signatures: dict = yaml.safe_load(stream)

        with open(signature_score_path, "r") as stream:
            self.score_signatures: dict = yaml.safe_load(stream)


    def check_port(self, port: int) -> bool:
        """
        Checks if a specific port is open.

        Args:
            port (int): The port number to check.

        Returns:
            bool: True if the port is open and accepting connections, False
                  otherwise.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((self.ip, port))
                return True
        except socket.timeout:
            return False
        except socket.error:
            return False


    def check_open_ports(self) -> PortSet:
        """
        Scans a given IP address to get set of open ports.

        Args:
            ip (str): The IP address of the host to scan.

        Returns:
            PortSet: A set of open ports on the given IP address.
        """
        ports: PortSet = {port for port in range(1, 65536)}
        open_ports = set()
        print(f"{Fore.GREEN}[+]{Fore.RESET} Starting port scan on {self.ip}")

        for port in ports:
            if self.check_port(port):
                open_ports.add(port)

        print(f"{Fore.GREEN}[+]{Fore.RESET} Open ports: {open_ports}")
        return open_ports


    def write_log(self, open_ports, port_results):
        with open('test.log', 'a') as f:
            # Beggining of this log entry
            f.write('------------------------ \n')
            f.write(str(datetime.datetime.now()))
            f.write('\n')

            # Open ports
            f.write('[*] Open ports: \n' + str(open_ports) + '\n\n')

            # Results of each port
            for result in port_results:
                f.write('[*] Port ' + str(result[0]) + '\n\t')
                if result[1] is None:
                    f.write('Found no signatures\n\n')
                else:
                    
                    for r in result[1]:
                        f.write('Found ' + str(r['found_signatures']) + '/' + str(r['total_signatures']) + ' ' + str(r['honeypot']) + ': input ' + str(r['signature_id']) + '\n\t')
                        f.write('Comments: \n\t\t')
                        
                        for id in r['signature_id']:
                            f.write(str(id) + ': ' + str(r['comments'][str(id)]) + '\n\t\t')
                        f.write('Overall comment: ' + str(r['comments']['overall_comment']) + '\n\n')


    def detect_honeypot(
                        self,
            username: str = "",
            password: str = ""
            ) -> Honeyscanner | None:
        """
        Detects if a given IP address is running a known honeypot based on
        open ports and responses.

        Args:
            username (str, optional): The username to use for authentication.
                                      Defaults to "".
            password (str, optional): The password to use for authentication.
                                      Defaults to "".

        Returns:
            Honeyscanner: A Honeyscanner object representing the detected
                          honeypot.
        """
        self.open_ports: PortSet = self.check_open_ports()
        if not self.open_ports:
            return

        signature_results = []


        for port in self.open_ports:
            print(f"{Fore.YELLOW}[~]{Fore.RESET} Matching signatures for port {port}...")
            for honeypot, value in self.score_signatures.items():
                result = self.create_result_dict()
                score = self.signature_check(port, value['protocol'], value['steps'])
                
                # Run possible custom functions
                if 'custom_functions' in value:
                    for f in value['custom_functions']:
                        func = getattr(custom_functions, f['function_name'])
                        s = func(self.ip, port)
                        score = score + s

                if len(score) > 0:
                    # Calculate score
                    print(f'Score list: {score}')
                    product = 1.0
                    for p in score:
                        product *= (1-p)
                    confidence = 1 - product
                    print(f'{Fore.GREEN}[*]{Fore.RESET} detected {honeypot} with confidence {confidence} on port {port}')

                    # Comment logging
                    #signature_results.append(result)
                #else:
                    #signature_results.append((port, None))

        #self.write_log(self.open_ports, signature_results)


    def signature_check(self, port, protocol, signature, result = None):
        match protocol:
            case 'ssh':
                score = ssh_communication(self.ip, port, signature, result)
            case 'http':
                score = requests_communication(self.ip, port, protocol, signature, result)
            case 'https':
                score = requests_communication(self.ip, port, protocol, signature, result)
            case 'telnet':
                score = telnet_communication(self.ip, port, signature, result)
            case 'socket':
                score = socket_communication(self.ip, port, signature, result)
            case 'dicom':
                score = dicom_communcation(self.ip, port, signature, result)
        return score
    

    def create_result_dict(honeypot_name : str):
        return {'total_signatures' : 0, 'found_signatures' : 0, 'signature_id' : [], 'honeypot' : honeypot_name, 'comments' : {}}