import socket
import threading
import logging
import os
import sys
import json
import hashlib
import queue
import time
import random
import argparse
from cryptography.fernet import Fernet
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.logging import RichHandler

# --- Basic Configuration ---
# Sets up logging to show thread names, timestamps, and messages.
logging.basicConfig(
    format="%(levelname)s:%(threadName)s - %(asctime)s: %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
    handlers=[RichHandler(rich_tracebacks=True)]
)

log = logging.getLogger("rich")
console = Console()

class Crypto:
    """A simple wrapper for Fernet encryption."""
    def __init__(self):
        self.key = Fernet.generate_key()
        self.f = Fernet(self.key)

    def encrypt_bytes(self, data):
        return self.f.encrypt(data)

    def decrypt_bytes(self, encrypted_data):
        return self.f.decrypt(encrypted_data)

class Node:
   
    def __init__(self, host, port, is_bootstrap=False, bootstrap_address=None):
        self.host = host
        self.port = port
        self.is_bootstrap = is_bootstrap
        self.bootstrap_address = bootstrap_address
        self.crypto = Crypto()
        self.chunk_size = 4096 * 1024 # 4MB chunks

        # --- Kademlia DHT Specifics ---
        self.k = 20  # Max contacts per k-bucket
        self.alpha = 3 # Concurrency parameter for lookups
        self.id_length_bits = 160 # Using 160-bit SHA-1 hashes
        self.node_id = int.from_bytes(os.urandom(self.id_length_bits // 8), "big")
        self.k_buckets = [[] for _ in range(self.id_length_bits)]
        self.nodes_lock = threading.Lock() # Lock for thread-safe k-bucket access

        logging.info(f"Node starting with ID: {str(self.node_id)[:15]}...")

        # --- Start Background Threads ---
        server_thread = threading.Thread(target=self.start_listener, name="ListenerThread")
        server_thread.daemon = True
        server_thread.start()

        if not self.is_bootstrap:
            bootstrap_thread = threading.Thread(target=self.connect_to_bootstrap, name="BootstrapThread")
            bootstrap_thread.daemon = True
            bootstrap_thread.start()
            self._start_gossip_thread()

    # --- Kademlia Routing Table Methods ---
    @staticmethod
    def XOR_distance(id1, id2):
        """Calculates the XOR distance between two integer IDs."""
        return id1 ^ id2

    @staticmethod
    def hash_data(data):
        """Calculates the SHA-1 hash of data, used for Kademlia keys."""
        return hashlib.sha1(data).hexdigest()

    def _get_bucket_index(self, node_id):
        """Calculates the correct k-bucket index for a given node ID."""
        distance = self.XOR_distance(self.node_id, node_id)
        if distance == 0: return -1
        return distance.bit_length() - 1

    def add_node(self, node_id, host, port):
        """Adds a new node to the appropriate k-bucket."""
        new_node_contact = {'id': node_id, 'host': host, 'port': port}
        with self.nodes_lock:
            bucket_index = self._get_bucket_index(node_id)
            if bucket_index < 0: return # Don't add ourselves
            bucket = self.k_buckets[bucket_index]
            # If node is already present, move it to the end (most recently seen)
            for i, contact in enumerate(bucket):
                if contact['id'] == node_id:
                    bucket.pop(i)
                    bucket.append(new_node_contact)
                    return
            if len(bucket) < self.k:
                bucket.append(new_node_contact)
            else:
                # If bucket is full, ping the oldest contact to see if it's still alive
                ping_thread = threading.Thread(target=self._handle_full_bucket, 
                                               args=(bucket[0], new_node_contact, bucket_index))
                ping_thread.start()

    def _handle_full_bucket(self, oldest_node, new_node_contact, bucket_index):
        """Pings the oldest node in a full bucket and replaces it if unresponsive."""
        is_responsive = self.connect_and_ping(oldest_node['host'], oldest_node['port'])
        with self.nodes_lock:
            bucket = self.k_buckets[bucket_index]
            if not bucket: return
            if not is_responsive and bucket and bucket[0]['id'] == oldest_node['id']:
                bucket.pop(0)
                bucket.append(new_node_contact)
                logging.info(f"Replaced unresponsive node {str(oldest_node['id'])[:10]}...")
    
    def remove_node(self, node_addr_tuple):
        """Thread-safely removes a node from the k-buckets by its address."""
        with self.nodes_lock:
            for bucket in self.k_buckets:
                for i, contact in enumerate(bucket):
                    if (contact['host'], contact['port']) == node_addr_tuple:
                        bucket.pop(i)
                        logging.info(f"Removed unresponsive node: {node_addr_tuple}")
                        return

    # --- Listener and Connection Handling ---
    def start_listener(self):
        """Starts the main server loop to listen for incoming connections."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen()
            logging.info(f"Node listening on {self.host}:{self.port}")
            while True:
                client, address = server.accept()
                handler_thread = threading.Thread(target=self.handle_incoming_connection, args=(client, address), name=f"Handler-{address[1]}")
                handler_thread.daemon = True
                handler_thread.start()

    def handle_incoming_connection(self, conn, addr):
        """Acts as a router, calling the correct handler based on the node's role."""
        if self.is_bootstrap:
            self._handle_bootstrap_connection(conn, addr)
        else:
            self._handle_peer_connection(conn, addr)
    
    @staticmethod
    def recvall(conn, n):
        """Receives exactly n bytes from a socket, or returns None if connection is closed."""
        data = bytearray()
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet: return None
            data.extend(packet)
        return bytes(data)

    def _handle_bootstrap_connection(self, conn, addr):
        """Handles a short-lived registration connection when in bootstrap mode."""
        logging.info(f"Bootstrap: Handling registration from {addr}")
        try:
            buffer = b""
            # Keep reading until a newline character is found
            while b'\n' not in buffer:
                data = conn.recv(1024)
                if not data:
                    # Connection closed before message was complete
                    return
                buffer += data # CORRECT: Update buffer inside the loop

            # Process the first complete line from the buffer
            line, buffer = buffer.split(b'\n', 1)
            decoded_line = line.decode('utf-8').strip()
            parts = decoded_line.split("::")
            command = parts[0].upper()

            if command == "REGISTER" and len(parts) == 4:
                node_id, host, port = int(parts[1]), parts[2], int(parts[3])
                existing_contacts = []
                with self.nodes_lock:
                    for bucket in self.k_buckets:
                        for contact in bucket:
                            existing_contacts.append(f"{contact['id']}::{contact['host']}::{contact['port']}")
                
                peer_list_str = ",".join(existing_contacts)
                response = f"PEER_LIST::{peer_list_str}\n"
                conn.sendall(response.encode('utf-8'))
                logging.info(f"Bootstrap: Sent list of {len(existing_contacts)} peers to new node.")
                
                # Now, add the new node to this bootstrap node's own list
                self.add_node(node_id, host, port)
                
        except Exception as e:
            logging.error(f"Bootstrap error with {addr}: {e}")
        finally:
            conn.close()

    def _handle_peer_connection(self, conn, addr):
        """Handles a long-lived, secure connection from another peer."""
        session_crypto = None
        try:
            # We need to peek at the first command to see if it's a PING
            # before we wait for an encryption key.
            initial_data = conn.recv(1024, socket.MSG_PEEK)
            if initial_data.strip() == b'PING':
                conn.recv(1024) # Consume the PING from the socket buffer
                conn.sendall(b"PONG\n")
                return # End the connection, it was just a ping.

            # If it's not a PING, proceed with the encrypted session setup
            key = self.recvall(conn, 44)
            if not key: return
            session_crypto = Crypto()
            session_crypto.f = Fernet(key)
            buffer = b""
            while True:
                data = conn.recv(4096)
                if not data: break
                buffer += data
                while b'\n' in buffer:
                    header_line, buffer = buffer.split(b'\n', 1)
                    decoded_line = header_line.decode('utf-8').strip()
                    parts = decoded_line.split("::")
                    command = parts[0].upper()

                    if command == "STORE_CHUNK" and len(parts) == 3:
                        chunk_hash, chunk_size = parts[1], int(parts[2])
                        if len(buffer) >= chunk_size:
                            encrypted_chunk = buffer[:chunk_size]
                            buffer = buffer[chunk_size:]
                        else:
                            encrypted_chunk = buffer + self.recvall(conn, chunk_size - len(buffer))
                            buffer = b''
                        if encrypted_chunk and session_crypto:
                            decrypted_chunk = session_crypto.decrypt_bytes(encrypted_chunk)
                            os.makedirs("chunk_storage", exist_ok=True)
                            with open(os.path.join("chunk_storage", chunk_hash), "wb") as f: f.write(decrypted_chunk)
                            logging.info(f"Stored chunk {chunk_hash[:10]}... from {addr}")
                    elif command == "GET_CHUNK" and len(parts) == 2:
                        chunk_hash = parts[1]
                        chunk_path = os.path.join("chunk_storage", chunk_hash)
                        if os.path.exists(chunk_path) and session_crypto:
                            with open(chunk_path, "rb") as f: chunk_data = f.read()
                            encrypted_chunk = session_crypto.encrypt_bytes(chunk_data)
                            response_header = f"CHUNK_DATA::{chunk_hash}::{len(encrypted_chunk)}\n"
                            conn.sendall(response_header.encode('utf-8'))
                            conn.sendall(encrypted_chunk)
                        else:
                            conn.sendall(f"ERROR::CHUNK_NOT_FOUND::{chunk_hash}\n".encode('utf-8'))
                    elif command == "FIND_NODE" and len(parts) == 2:
                        target_id = int(parts[1])
                        with self.nodes_lock:
                            all_contacts = []
                            for bucket in self.k_buckets: all_contacts.extend(bucket)
                            all_contacts.sort(key=lambda c: self.XOR_distance(c['id'], target_id))
                            contact_list_str = ",".join([f"{c['id']}::{c['host']}::{c['port']}" for c in all_contacts[:self.k]])
                        conn.sendall(f"FOUND_NODES::{contact_list_str}\n".encode('utf-8'))
                    elif command == "PING":
                        conn.sendall(b"PONG\n")
        except Exception:
            pass # Keep logs clean from common disconnect errors
        finally:
            logging.info(f"Closing connection for {addr}")
            conn.close()

    # --- Client-Side Initiator Methods ---
    def connect_to_bootstrap(self):
        if not self.bootstrap_address or self.bootstrap_address == (self.host, self.port): return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect(self.bootstrap_address)
                s.sendall(f"REGISTER::{self.node_id}::{self.host}::{self.port}\n".encode('utf-8'))
                response = s.recv(8192).decode('utf-8').strip() # Increased buffer for larger peer lists
                parts = response.split("::", 1)
                if parts[0] == "PEER_LIST" and len(parts) > 1 and parts[1]:
                    contacts = parts[1].split(',')
                    for contact_str in contacts:
                        try:
                            c_parts = contact_str.split('::')
                            if len(c_parts) == 3:
                                node_id, host, port = int(c_parts[0]), c_parts[1], int(c_parts[2])
                                if node_id != self.node_id: self.add_node(node_id, host, port)
                        except (ValueError, IndexError): continue
                    logging.info(f"Processed {len(contacts)} peers from bootstrap.")
            except Exception as e:
                logging.error(f"Bootstrap connection failed: {e}")
    
    def connect_and_ping(self, host, port):
        """Pings a node to see if it's responsive."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((host, port))
                # PING is a simple, unencrypted command, so we don't send a key.
                s.sendall(b"PING\n")
                response = s.recv(1024)
                # A successful PONG proves the node is responsive.
                if response.strip() == b"PONG":
                    return True
                return False
        except Exception:
            # Any exception (timeout, connection refused) means it's not responsive.
            return False

    def find_closest_nodes(self, target_id):
        shortlist = []
        queried_nodes = {self.node_id}
        with self.nodes_lock:
            all_contacts = []
            for bucket in self.k_buckets: all_contacts.extend(bucket)
            if not all_contacts:
                logging.warning("Cannot perform lookup: No known nodes.")
                return []
            all_contacts.sort(key=lambda c: self.XOR_distance(c['id'], target_id))
            initial_contacts = all_contacts[:self.k]
        for contact in initial_contacts:
            distance = self.XOR_distance(contact['id'], target_id)
            shortlist.append((distance, contact))
        shortlist.sort(key=lambda x: x[0])
        while True:
            nodes_to_query = []
            for _, contact in shortlist:
                if contact['id'] not in queried_nodes: nodes_to_query.append(contact)
                if len(nodes_to_query) == self.alpha: break
            if not nodes_to_query: break
            response_queue = queue.Queue()
            threads = []
            for contact in nodes_to_query:
                queried_nodes.add(contact['id'])
                thread = threading.Thread(target=self.connect_and_find_nodes, args=(target_id, contact['host'], contact['port'], response_queue))
                threads.append(thread); thread.start()
            for t in threads: t.join()
            old_closest_distance = shortlist[0][0] if shortlist else None
            while not response_queue.empty():
                for contact in response_queue.get():
                    if contact['id'] not in queried_nodes:
                        distance = self.XOR_distance(contact['id'], target_id)
                        shortlist.append((distance, contact))
            shortlist.sort(key=lambda x: x[0])
            shortlist = shortlist[:self.k]
            new_closest_distance = shortlist[0][0] if shortlist else None
            if new_closest_distance is None or (old_closest_distance is not None and new_closest_distance >= old_closest_distance): break
        return [contact for _, contact in shortlist]

    def connect_and_find_nodes(self, target_id, host, port, response_queue):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((host, port))
                s.sendall(f"FIND_NODE::{target_id}\n".encode('utf-8'))
                response_data = s.recv(8192).decode('utf-8').strip()
                parts = response_data.split("::", 1)
                if parts[0] == "FOUND_NODES" and len(parts) > 1 and parts[1]:
                    new_contacts = []
                    for contact_str in parts[1].split(','):
                        try:
                            c_parts = contact_str.split('::')
                            if len(c_parts) == 3: new_contacts.append({'id': int(c_parts[0]), 'host': c_parts[1], 'port': int(c_parts[2])})
                        except (ValueError, IndexError): continue
                    response_queue.put(new_contacts)
        except Exception:
            pass

    # --- High-Level Application Logic ---
    def upload_file(self, filepath):
        if not os.path.exists(filepath):
            logging.error(f"File not found: {filepath}"); return
        file_map = {"filename": os.path.basename(filepath), "filesize": os.path.getsize(filepath), "chunks": []}
        logging.info(f"Starting DHT upload for {filepath}...")
        with open(filepath, "rb") as f:
            chunk_index = 0
            while True:
                chunk_data = f.read(self.chunk_size)
                if not chunk_data: break
                chunk_hash = self.hash_data(chunk_data)
                chunk_key = int(chunk_hash, 16)
                logging.info(f"Finding closest nodes for chunk {chunk_index} ({chunk_hash[:10]}...)")
                nodes_to_store_on = self.find_closest_nodes(chunk_key)
                if not nodes_to_store_on:
                    logging.error(f"Could not find nodes for chunk {chunk_index}. Aborting."); return
                chunk_locations = []
                for node in nodes_to_store_on:
                    self.connect_and_store_chunk(chunk_data, node['host'], node['port'])
                    chunk_locations.append([node['host'], node['port']])
                file_map["chunks"].append([chunk_hash, chunk_locations])
                chunk_index += 1
        os.makedirs("file_maps", exist_ok=True)
        map_filepath = os.path.join("file_maps", f"{file_map['filename']}.json")
        with open(map_filepath, "w") as map_file: json.dump(file_map, map_file, indent=4)
        logging.info(f"Upload complete. File map saved to {map_filepath}")

    def download_file(self, filename):
        map_filepath = os.path.join("file_maps", f"{filename}.json")
        if not os.path.exists(map_filepath):
            logging.error(f"File map not found for '{filename}'."); return
        with open(map_filepath, "r") as map_file: file_map = json.load(map_file)
        logging.info(f"Starting download for {file_map['filename']}...")
        download_threads = []
        for chunk_hash, locations in file_map["chunks"]:
            thread = threading.Thread(target=self._download_chunk, args=(chunk_hash, locations))
            download_threads.append(thread)
            thread.start()
        for t in download_threads: t.join()
        self._reassemble_file(file_map)

    def _download_chunk(self, chunk_hash, locations):
        for host, port in locations:
            if self.connect_and_get_chunk(chunk_hash, host, port):
                return
        logging.error(f"Failed to retrieve chunk {chunk_hash} from any known location.")

    def _reassemble_file(self, file_map):
        output_filename = f"downloaded_{file_map['filename']}"
        logging.info(f"Reassembling chunks into {output_filename}...")
        try:
            with open(output_filename, "wb") as output_file:
                for chunk_hash, _ in file_map["chunks"]:
                    chunk_path = os.path.join("retrieved_chunks", chunk_hash)
                    if os.path.exists(chunk_path):
                        with open(chunk_path, "rb") as chunk_file: output_file.write(chunk_file.read())
                        os.remove(chunk_path)
                    else:
                        logging.error(f"Missing chunk {chunk_hash}! Reassembly failed."); return
            logging.info(f"File {output_filename} reassembled successfully.")
        except Exception as e:
            logging.error(f"An error occurred during file reassembly: {e}")

    def connect_and_store_chunk(self, chunk_data, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                s.sendall(self.crypto.key)
                encrypted_chunk = self.crypto.encrypt_bytes(chunk_data)
                chunk_hash = self.hash_data(chunk_data)
                header = f"STORE_CHUNK::{chunk_hash}::{len(encrypted_chunk)}\n"
                s.sendall(header.encode("utf-8"))
                s.sendall(encrypted_chunk)
        except Exception as e:
            logging.error(f"Failed to store chunk at {host}:{port}: {e}")
            self.remove_node((host, port))

    def connect_and_get_chunk(self, chunk_hash, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                s.sendall(self.crypto.key)
                s.sendall(f"GET_CHUNK::{chunk_hash}\n".encode('utf-8'))
                buffer = b""
                while b'\n' not in buffer:
                    data = s.recv(1024)
                    if not data: return False
                    buffer += data
                header_line, buffer = buffer.split(b'\n', 1)
                parts = header_line.decode('utf-8').strip().split('::')
                if parts[0] == "CHUNK_DATA" and len(parts) == 3:
                    response_hash, chunk_size = parts[1], int(parts[2])
                    if len(buffer) >= chunk_size: encrypted_chunk = buffer[:chunk_size]
                    else: encrypted_chunk = buffer + self.recvall(s, chunk_size - len(buffer))
                    decrypted_chunk = self.crypto.decrypt_bytes(encrypted_chunk)
                    if self.hash_data(decrypted_chunk) == response_hash:
                        os.makedirs("retrieved_chunks", exist_ok=True)
                        with open(os.path.join("retrieved_chunks", response_hash), "wb") as f: f.write(decrypted_chunk)
                        logging.info(f"Successfully received and verified chunk {response_hash[:10]}...")
                        return True
                return False
        except Exception as e:
            logging.error(f"Failed to get chunk from {host}:{port}: {e}")
            self.remove_node((host, port))
            return False
            
    def _start_gossip_thread(self):
        def gossip_loop():
            while True:
                time.sleep(60) # Gossip less frequently
                all_known_nodes = []
                with self.nodes_lock:
                    for bucket in self.k_buckets: all_known_nodes.extend(bucket)
                if not all_known_nodes:
                    logging.info("Gossip: No known peers. Re-contacting bootstrap.")
                    self.connect_to_bootstrap()
                    continue
                random_node = random.choice(all_known_nodes)
                # Future enhancement: gossip with nodes in sparse buckets
                self.connect_and_find_nodes(self.node_id, random_node['host'], random_node['port'], queue.Queue())

    # --- User Interface ---
    def run_user_interface(self):
        print("\n----- Kademlia DHT Node UI -----")
        print("  peers              - Show the K-Bucket routing table.")
        print("  upload <filepath>  - Distribute a file onto the DHT.")
        print("  download <filename> - Reassemble a file from the DHT.")
        print("  list_files         - List files with available maps.")
        print("  exit               - Shut down the node.")
        print("---------------------------------")
        while True:
            try:
                message = input("> ")
                if not message: continue
                full_parts = message.split()
                command = full_parts[0].lower()
                if command == 'exit': break
                elif command == 'peers':
                    nodes_to_display = []
                    with self.nodes_lock:
                        for bucket in self.k_buckets: nodes_to_display.append(list(bucket))
                    print("\n----- K-Bucket Routing Table -----")
                    total_nodes = 0
                    for i, bucket in enumerate(nodes_to_display):
                        if bucket:
                            print(f"Bucket {i}:")
                            for node in bucket:
                                short_id = str(node['id'])[:10]
                                print(f"  - Node {short_id}... at {node['host']}:{node['port']}")
                            total_nodes += len(bucket)
                    print(f"Total known nodes: {total_nodes}")
                elif command == 'upload' and len(full_parts) == 2:
                    filepath = full_parts[1]
                    threading.Thread(target=self.upload_file, args=(filepath,)).start()
                elif command == 'download' and len(full_parts) == 2:
                    filename = full_parts[1]
                    threading.Thread(target=self.download_file, args=(filename,)).start()
                elif command == 'list_files':
                    maps_dir = "file_maps"
                    if not os.path.exists(maps_dir) or not os.listdir(maps_dir):
                        print("No file maps found.")
                    else:
                        print("\n----- Available File Maps -----")
                        for filename in os.listdir(maps_dir):
                            if filename.endswith(".json"): print(f"- {filename.replace('.json', '')}")
                else: print("Invalid command.")
            except KeyboardInterrupt: break
            except Exception as e: logging.error(f"UI Error: {e}", exc_info=True)
        print("\nShutting down.")

# --- Main Execution Block ---
"""
if __name__ == "__main__":
    BOOTSTRAP_HOST = 'localhost'
    BOOTSTRAP_PORT = 2067
    my_port = 0
    is_bootstrap = False
    if len(sys.argv) > 1:
        if sys.argv[1] == '--bootstrap':
            is_bootstrap = True
            my_port = BOOTSTRAP_PORT
        else:
            try: my_port = int(sys.argv[1])
            except ValueError: print(f"Error: Invalid port '{sys.argv[1]}'."); sys.exit(1)
    else:
        try: my_port = int(input("Enter the port for this node: "))
        except ValueError: print("Invalid port."); sys.exit(1)
    my_node = Node(host="localhost", port=my_port, is_bootstrap=is_bootstrap, bootstrap_address=(BOOTSTRAP_HOST, BOOTSTRAP_PORT))
    my_node.run_user_interface()
"""

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
                    prog ='Node.py',
                    description ='A decentralized and encrypted cloud storage system with the use of Kademlia DHT nodes',
                    epilog ='Text at the bottom of help')

    parser.add_argument('port',
                        type = int,
                        help = 'The port number for this node to listen on.')
    
    parser.add_argument('--is-bootstrap',
                        action='store_true', 
                        help='Run this node as the bootstrap server.')
    
    parser.add_argument("--host",
                        type = str,
                        default = "localhost",
                        description = "The host address this node will bind to, default host is localhost")
    
    parser.add_argument("--bootstrap",
                        type = str,
                        default = None,
                        help = "Whether or not this node will act as a bootstrap node.")
    

    args = parser.parse_args()

    bootstrap_addr = None
    if args.is_bootstrap:
        # A bootstrap node uses its own address as the bootstrap address
        bootstrap_addr = (args.host, args.port)
        print(f"----- Starting in BOOTSTRAP mode on {args.host}:{args.port} -----")
    elif args.bootstrap:
        try:
            host, port_str = args.bootstrap.split(':')
            bootstrap_addr = (host, int(port_str))
        except ValueError:
            print("Error: Invalid bootstrap address format. Use host:port.")
            sys.exit(1)
    
    my_node = Node(host=args.host,
                   port=args.port,
                   is_bootstrap=args.is_bootstrap,
                   bootstrap_address=bootstrap_addr)
    
    my_node.run_user_interface()