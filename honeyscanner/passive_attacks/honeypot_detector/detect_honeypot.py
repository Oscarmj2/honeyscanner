import socket
import yaml
import datetime
import time
import math

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
        with open(signatures_path, "r") as stream:
            self.signatures: dict = yaml.safe_load(stream)

        self.detection_log = 'detection.log' # Log where detection scores will be written
        self.communcation_log = 'detection_communcation.log' # Log where all communication with server during detection will be written


    def get_version(self, name):
        """
        returns the latest supported version of the following four honeypots, 
        based on input name, cowrie, kipo, dionaea, conpot

        Args:
            name (str): name of the honeypot.

        Returns:
            version (str): Latest version of the honeypot supported.
        """
        if name == 'cowrie':
            return '2.5.0'
        if name == 'kippo':
            return '0.9'
        if name == 'dionaea':
            return '0.11.0'
        if name == 'conpot':
            return '0.6.0'
        
        return ''

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
            None

        Returns:
            PortSet: A set of open ports on the given IP address.
        """
        ports: PortSet = {port for port in range(1, 65536)}
        # T-pot port set
        #ports: PortSet = {19, 21, 22, 23, 25, 42, 53, 69, 80, 102, 110, 123, 135, 143, 161, 389, 443, 445, 502, 623, 631, 1025, 1080, 1433, 1521, 1723, 1883, 1900, 2404, 2575, 3000, 3306, 3389,
        #                   5000, 5060, 5432, 5555, 5900, 6379, 6667, 8080, 8081, 8090, 8443, 9100, 9200, 10001, 11112, 11211, 11434, 25565, 44818, 47808, 50100, 64294, 64295}
        open_ports = set()
        print(f"{Fore.GREEN}[+]{Fore.RESET} Starting port scan on {self.ip}")

        for port in ports:
            if self.check_port(port):
                open_ports.add(port)

        print(f"{Fore.GREEN}[+]{Fore.RESET} Open ports: {open_ports}")
        return open_ports


    def write_log(self, open_ports, port_results):
        """
        Writes a log file of the resulting scores on all ports where there was a successful fingerprint

        Args:
            open_ports (set[int]): The set of open ports.
            port_results (list[dict]): A list of all positive results of fingerprints and their final scores

        Returns:
            None
        """
        with open(self.detection_log, 'a') as f:
            f.write('------------ New log start ---------- \n') # To easily search the log for all new entries
            f.write(str(datetime.datetime.now()))
            f.write('\n')

            # Open ports
            f.write('[*] Open ports: \n' + str(open_ports) + '\n\n')

            # Results of each port
            for result in port_results:
                f.write(f'[*] Port {result['port']} - Detected following from honeypot {result['name']} with confidence {result['score']}\n\t')

                for index, score in result.items():
                    if index != 'port' and index != 'name':
                        f.write(f'Positive result on input #{index} with score {score}')
                        f.write('\n\t')
                
                f.write('\n')


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

            with open(self.communcation_log, 'a') as f:
                f.write(f'\n----- Fingerprint matching on port {port} ----- \n')

            for honeypot, value in self.signatures.items():
                with open(self.communcation_log, 'a') as f:
                    f.write(f'*** Matching for honeypot: {honeypot} ***\n')

                result = {'port' : port, 'name' : honeypot}
                score = self.signature_check(port, value['protocol'], value['steps'], result)
                
                # Run possible custom functions
                if 'custom_functions' in value:
                    for f in value['custom_functions']:
                        func = getattr(custom_functions, f['function_name'])
                        s = func(self.ip, port)
                        score = score + s
                        result['custom'] = s

                if len(score) > 0:
                    # Calculate score
                    print(f'Score list: {score}')
                    product = 1.0
                    for p in score:
                        product *= (1-p)
                    product *= 10
                    product = 10 - product
                    confidence = 1 / (1 + math.e**(-product+5))
                    result['score'] = confidence
                    print(f'{Fore.GREEN}[*]{Fore.RESET} detected {honeypot} with confidence {confidence} on port {port}')
                    signature_results.append(result)

                    with open(self.communcation_log, 'a') as f:
                        f.write(f'score array {result} with end score {confidence} \n')
        self.write_log(self.open_ports, signature_results)

        # Return Honeyscanner object
        for honeypot in signature_results:
            name = honeypot['name']
            if name == 'cowrie' or name == 'kippo':
                version = self.get_version(name)
                if not username:
                    username = 'root'
                if not password:
                    password = '1234'
                return Honeyscanner(
                    name,
                    version,
                    self.ip,
                    honeypot['port'],
                    username,
                    password
                )
            
            if 'dionaea' in name or 'conpot' in name:
                version = self.get_version(name)
                return Honeyscanner(
                    name,
                    version,
                    self.ip,
                    honeypot['port'],
                    '',
                    ''
                )


    def signature_check(self, port, protocol, signature, result = None):
        """
        Sends the signature to the corresponding function based on which protocol to interact with.

        Args:
            port (int): port to be commincating with.
            protocol (str): which protocol to use, currently supported: (ssh, http, https, telnet, socket, dicom).
            signature (list[dict]): list of signatures (uses the steps format from signatures.yaml).
            result (dict): A dictionary where data on fingerprint of the honeypot is stored.

        Returns:
            score (list[int]): a list of the scores from the fingerprinting.
        """
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
    