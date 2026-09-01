import logging
import multiprocessing
import socket
import os
import threading
from Encrypter import Crypto
from cryptography.fernet import Fernet, InvalidToken

logging.basicConfig(format="%(levelname)s - %(asctime)s: %(message)s", datefmt="%H:%M:%S", level=logging.INFO)

HOST = "localhost"
PORT = 2067

def recvall(conn, n):
    """Receives exactly n bytes from a socket, blocking until completed."""
    data = bytearray()
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None # Return None if connection is closed prematurely
        data.extend(packet)
    return bytes(data) # Return as bytes, not bytearray

def handle_client(conn, addr):
    logging.info(f"New connection from {addr}")
    crypto = Crypto()
    buffer = b""
    
    try:
        key = recvall(conn, 44)
        if key:
            crypto.key = key
            crypto.f = Fernet(key)
            logging.info(f"\n----- Received encryption key from {addr} ✅ -----")
        else:
            logging.error("\n----- Failed to receive full key. X -----")
            return

        while True:
            data = conn.recv(1024)
            if not data:
                break
            buffer += data
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                decoded_line = line.decode('utf-8').strip()
                parts = decoded_line.split("::")

                if parts[0].upper() == "UPLOAD" and len(parts) == 3:
                    filename = os.path.basename(parts[1])
                    filesize = int(parts[2])
                    logging.info(f"Receiving file '{filename}' ({filesize} bytes)")
                    conn.sendall(b"OK\n")

                    received_bytes = 0
                    os.makedirs("server_uploads", exist_ok=True)
                    filepath = os.path.join("server_uploads", filename)

                    with open(filepath, "wb") as file:
                        while received_bytes < filesize:
                            len_header = recvall(conn, 8)
                            if len_header is None:
                                logging.warning("Client disconnected during file transfer header reception.")
                                break
                            
                            chunk_len = int.from_bytes(len_header, 'big')
                            
                            encrypted_chunk = recvall(conn, chunk_len)
                            # *** THE FIX: Check if recvall returned None ***
                            if encrypted_chunk is None:
                                logging.warning("Client disconnected during file transfer chunk reception.")
                                break

                            decrypted_chunk = crypto.decrypt_bytes(encrypted_chunk)
                            file.write(decrypted_chunk)
                            received_bytes += len(decrypted_chunk)
                    
                    if received_bytes == filesize:
                        logging.info(f"Successfully received '{filename}' ({received_bytes} bytes written).")
                    else:
                        logging.warning(f"File transfer for '{filename}' was incomplete. Got {received_bytes} of {filesize} bytes.")

                else:
                    logging.info(f"Echoing back to {addr}: '{decoded_line}'")
                    conn.sendall((decoded_line + '\n').encode('utf-8'))
    
    except InvalidToken:
         logging.error(f"DECRYPTION FAILED for {addr}. Invalid token received.")
    except ConnectionResetError:
        logging.warning(f"Client {addr} disconnected unexpectedly.")
    except Exception as e:
        logging.error(f"Error with client {addr}: {e}", exc_info=True)
    finally:
        logging.info(f"Closing connection for {addr}")
        conn.close()

# The rest of the server code (chatserver, main) remains the same.
def chatserver(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((ip, port))
        server.listen(100)
        logging.info(f"Server listening on {ip}:{port}")
        while True:
            client, address = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client, address))
            client_thread.start()

def main():
    svr = multiprocessing.Process(target=chatserver, args=[HOST, PORT], daemon=True, name="Server")
    while True:
        command = input("\nEnter a command (start, stop, exit): ")
        if command == "start":
            if not svr.is_alive():
                logging.info("\n----- Starting Server -----")
                svr = multiprocessing.Process(target=chatserver, args=[HOST, PORT], daemon=True, name="Server")
                svr.start()
            else:
                logging.info("Server is already running.")
        elif command == "stop":
            if svr.is_alive():
                logging.info("\n----- Ending Server -----")
                svr.terminate()
                svr.join()
                logging.info("\n----- Server Ended -----")
            else:
                logging.info("Server is not running.")
        elif command == "exit":
             if svr.is_alive():
                logging.info("\n----- Ending Server -----")
                svr.terminate()
                svr.join()
             break
    logging.info("\n----- Application Ended -----")

if __name__ == "__main__":
    main()

