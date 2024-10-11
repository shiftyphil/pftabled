import argparse
import os
import ssl
import sys
import socketserver
from typing import Callable, Any

from pftable import PfTable
from pledge import pledge, unveil


def process_command(command: str, reply: Callable[[str], Any], table: PfTable) -> None:
    try:
        if command[0] == "+":
            if len(command) >= 2:
                table.add(command[1:])
                reply("OK\n")
            else:
                reply("ERROR: MISSING ADDRESS\n")
        elif command[0] == "-":
            if len(command) >= 2:
                table.remove(command[1:])
                reply("OK\n")
            else:
                reply("ERROR: MISSING ADDRESS\n")
        elif command == '?':
            reply("\n".join(table.list()) + "\n")
        elif command == '.':
            table.clear()
            reply("OK\n")
        else:
            reply("ERROR: UNKNOWN COMMAND\n")
    except ValueError:
        reply("ERROR: INVALID ADDRESS\n")


class CommandHandler(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            command = line.decode().strip()
            if command:
                process_command(command, lambda x: self.wfile.write(x.encode()), self.server.pf_table)


def main():
    parser = argparse.ArgumentParser(description='PF Table Manipulation Daemon')
    parser.add_argument('-t', '--table', help='PF Table Name', type=str)
    parser.add_argument('-s', '--socket', help='Control Socket', type=str)
    parser.add_argument('-a', '--ca', help='CA Cert', type=str)
    parser.add_argument('-c', '--cert', help='SSL Cert', type=str)
    parser.add_argument('-k', '--key', help='SSL Cert Key', type=str)
    args = parser.parse_args()

    config = {'table_name': 'pftabled', 'socket_file': '/var/run/pftabled.sock',
              'ssl_ca': 'ca.pem', 'ssl_cert': 'cert.pem', 'ssl_key': 'cert.key'}
    env_map = {'table_name': 'TABLE_NAME', 'socket_file': 'SOCKET_FILE',
               'ssl_ca': 'SSL_CA', 'ssl_cert': 'SSL_CERT', 'ssl_key': 'SSL_KEY'}
    arg_map = {'table_name': args.table, 'socket_file': args.socket,
               'ssl_ca': args.ca, 'ssl_cert': args.cert, 'ssl_key': args.key}

    for var in config.keys():
        if arg_map[var]:
            config[var] = arg_map[var]
        elif env_map[var] in os.environ:
            config[var] = os.environ[env_map[var]]

    table = PfTable(config['table_name'])  # Opens /dev/pf

    pledges = {'unveil', 'stdio', 'rpath', 'cpath', 'unix', 'pf', 'error'}
    pledge(pledges)

    for path in sys.path:
        unveil(path, 'r')  # Required during error handling.
    for file in [config['ssl_ca'], config['ssl_cert'], config['ssl_key']]:
        unveil(file, 'r')
    unveil(config['socket_file'], 'rc')
    unveil(None, None)
    pledges -= {'unveil'}
    pledge(pledges)

    if os.path.exists(config['socket_file']):
        os.unlink(config['socket_file'])

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=config['ssl_ca'])
    ssl_context.load_cert_chain(certfile=config['ssl_cert'], keyfile=config['ssl_key'])
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    os.umask(0o055)
    try:
        with (socketserver.ThreadingUnixStreamServer(config['socket_file'], CommandHandler) as command_server):
            command_server.socket = ssl_context.wrap_socket(command_server.socket, server_side=True)
            command_server.pf_table = table
            command_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if os.path.exists(config['socket_file']):
            os.unlink(config['socket_file'])


if __name__ == "__main__":
    main()
