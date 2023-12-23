#!/Users/llevvt/PycharmProjects/DoS/venv/bin/python3

from management.input_handler import Input
from management.packet import Packet


def main():
    input_handler = Input()
    packet = Packet(protocol=input_handler.args.protocol, type=input_handler.args.type, dip=input_handler.args.target_ip_address, sip=input_handler.args.source_ip, dport=input_handler.args.target_port)
    # packet = Packet(protocol='UDP', type='reflection',
    #                dip='192.168.0.11', sip='0.0.0.0', idip='192.168.0.11',
    #                dport='80')
    packet.dos()


if __name__ == '__main__':
    main()
