import argparse
import re


class Input:

    def __init__(self):
        self.__parser = argparse.ArgumentParser(description='This script allows you to perform Denial of Service attacks.\n'
                                         'WARNING! This script is only for legal use!\n'
                                         'Developed by Lev Mordvinkov a.k.a llevt\n')
        self.__parser.add_argument('-P', '--protocol', choices=['TCP', 'UDP'], default='TCP', help='This flag is used to determine which protocol\\n'
                                                                    'would you use for attack. Available options (default is TCP):\n'
                                                                    'TCP\n'
                                                                    'UDP\n')
        self.__parser.add_argument('-t', '--type', choices=['flood', 'reflection'], help='Additional flag, which is required if -p is set to UDP\n', nargs='?')
        self.__parser.add_argument('-m', '--intermediate_target', help='This should be an IP address for intermediate target\n', nargs='?')
        self.__parser.add_argument('-a', '--target_ip_address', help='This flag is responsible for setting target IP address\n')
        self.__parser.add_argument('-p', '--target_port', default='80', help='This flag defines which port will be attacked')
        self.__parser.add_argument('-T', '--time_frame', default='0.0', help='This flag defines how frequently requests would be sent')
        self.__parser.add_argument('-s', '--source_ip', help='This flag is used to define fake IP address for spoofed packets')
        self.args = self.__parser.parse_args()
        print(f'================================\n'
              f'Protocol: {self.args.protocol},\n'
              f'Type of attack: {self.args.type}\n'
              f'Target IP address: {self.args.target_ip_address}\n'
              f'Target port: {self.args.target_port}\n'
              f'Time frame: {self.args.time_frame}\n'
              f'================================\n')

    def __check(self):
        if self.args.protocol == 'UDP':
            if self.args.type is None:
                self.__parser.error('Flag -t (--type) is required for UDP protocol')
            elif self.args.type == 'reflection' and not re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', self.args.intermediate_target):
                self.__parser.error('You have not specified intermediate target IP address.\n'
                                    'This parameter is required for reflection attacks')
        if not self.args.target_ip_address:
            self.__parser.error('Target IP address is not specified! Use flag -a to define target IP')
        elif not re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', self.args.target_ip_address):
            self.__parser.error('You have specified IP address in wrong way.\n'
                                'Use only valid IPv4 IP addresses!')
        if not re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', self.args.source_ip):
            self.__parser.error('You have not specified source IP address.\n'
                                'You can do so by using -s flag.')

        if not re.search(r'\b(0*([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))\b', self.args.target_port):
            self.__parser.error('Target port specified incorrectly. To specify port correctly, use number in range 0 - 65535')


