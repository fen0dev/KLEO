import socket
import threading
import ssl
import json
import logging

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Function to handle client connections
def handle_client(client_socket, address):
    logging.info(f"Connection from {address} established.")
    try:
        while True:
            command = input(f"{address}> ")
            if not command.strip():
                continue

            client_socket.send(command.encode())

            if command.lower() == 'exit':
                break
            elif command.startswith('download '):
                filename = command.split(' ', 1)[1]
                with open(filename, 'wb') as f:
                    while True:
                        data = client_socket.recv(1024)
                        if data.endswith(b"EOF"):
                            f.write(data[:-3])
                            break
                        f.write(data)
                logging.info(f"Downloaded {filename}")
            else:
                response = client_socket.recv(4096).decode()
                print(response)
    except Exception as e:
        logging.error(f"Error handling client: {e}")
    finally:
        client_socket.close()
        logging.info(f"Connection from {address} closed.")

# Function to start the server
def start_server(host, port, use_ssl=False, certfile=None, keyfile=None):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if use_ssl:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if certfile and keyfile:
            context.load_cert_chain(certfile, keyfile)
        server = context.wrap_socket(server, server_side=True)
    server.bind((host, port))
    server.listen(5)
    logging.info(f"Server listening on {host}:{port}")

    try:
        while True:
            client_socket, addr = server.accept()
            client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_handler.start()
    except KeyboardInterrupt:
        logging.info("Server shutting down...")
    finally:
        server.close()

# Function to load configuration from a file
def load_config(config_file):
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
            return (config.get('host', '0.0.0.0'), 
                    config.get('port', 9999), 
                    config.get('use_ssl', False), 
                    config.get('certfile'), 
                    config.get('keyfile'))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Error reading config file: {e}")
        return '0.0.0.0', 9999, False, None, None

if __name__ == '__main__':
    host, port, use_ssl, certfile, keyfile = load_config('config.json')
    start_server(host, port, use_ssl=use_ssl, certfile=certfile, keyfile=keyfile)