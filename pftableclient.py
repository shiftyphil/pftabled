import argparse
import os
import socket
import ssl
import sys


class PFTableClient:
    def __init__(self, socket_path: str, ca_config: dict):
        self._socket = None
        self._connect(socket_path, ca_config)

    def __del__(self):
        try:
            if self._socket:
                self._socket.close()
        except AttributeError:
            pass

    def _connect(self, socket_path: str, ca_config: dict):
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_config['ssl_ca'])
        ssl_context.check_hostname = False  # TODO
        ssl_context.load_cert_chain(certfile=ca_config['ssl_cert'], keyfile=ca_config['ssl_key'])
        client_socket = ssl_context.wrap_socket(client_socket, server_side=False)
        client_socket.connect(socket_path)

        self._socket = client_socket

    def send_command(self, cmd: str) -> str:
        if not cmd.endswith('\n'):
            cmd += '\n'
        self._socket.send(cmd.encode('utf-8'))
        data = self._socket.recv(1024)
        return data.decode('utf-8')


def main():
    parser = argparse.ArgumentParser(description='PF Table Client')
    parser.add_argument('-s', '--socket', help='Control Socket', type=str)
    parser.add_argument('-a', '--ca', help='CA Cert', type=str)
    parser.add_argument('-c', '--cert', help='SSL Cert', type=str)
    parser.add_argument('-k', '--key', help='SSL Cert Key', type=str)
    parser.add_argument('command', help='Optional command', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if '--' in args.command:
        args.command.remove('--')

    config = {'cmd': None, 'socket_file': '/var/run/pftabled.sock',
              'ssl_ca': 'ca.pem', 'ssl_cert': 'cert.pem', 'ssl_key': 'cert.key'}
    env_map = {'cmd': 'TABLE_COMMAND', 'socket_file': 'SOCKET_FILE',
               'ssl_ca': 'SSL_CA', 'ssl_cert': 'SSL_CERT', 'ssl_key': 'SSL_KEY'}
    arg_map = {'cmd': ' '.join(args.command), 'socket_file': args.socket,
               'ssl_ca': args.ca, 'ssl_cert': args.cert, 'ssl_key': args.key}

    for var in config.keys():
        if arg_map[var]:
            config[var] = arg_map[var]
        elif env_map[var] in os.environ:
            config[var] = os.environ[env_map[var]]

    client = PFTableClient(config['socket_file'], config)
    if config['cmd']:
        print(client.send_command(config['cmd']))
    else:
        while command := sys.stdin.readline():
            print(client.send_command(command))


if __name__ == '__main__':
    main()
