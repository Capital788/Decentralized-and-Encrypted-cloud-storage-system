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
import ipaddress
from cryptography.fernet import Fernet
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.logging import RichHandler

logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

log = logging.getLogger("rich")
console = Console()

class Crypto:
    
    def __init__(self):

        self.key = Fernet.generate_key()
        self.f = Fernet(self.key)

    def encrypt_bytes(self, data):

        return self.f.encrypt(data)

    def decrypt_bytes(self, encrypted_data):

        return self.f.decrypt(encrypted_data)


class Node:
   
    def __init__(self, host, port, node_id=None, is_bootstrap=False, bootstrap_address=None):

        self.host = host
        self.port = port
        self.public_host = None
        self.public_port = None
        self.is_bootstrap = is_bootstrap
        self.bootstrap_address = bootstrap_address
        self.crypto = Crypto()
        self.chunk_size = 4 * 1024 * 1024  # 4MB chunks

        self.k = 20
        self.alpha = 3
        self.id_length_bits = 160
        self.node_id = node_id if node_id is not None else int.from_bytes(os.urandom(self.id_length_bits // 8), "big")
        self.k_buckets = [[] for _ in range(self.id_length_bits)]
        self.nodes_lock = threading.Lock()

        log.info(f"Node starting with ID: {str(self.node_id)[:15]}...")

        server_thread = threading.Thread(target=self.start_listener, name = "ListenerThread")
        server_thread.daemon = True
        server_thread.start()

        if not self.is_bootstrap:
            
            self.stun_thread = threading.Thread(target=self.discover_public_ip, name="StunThread")
            self.stun_thread.daemon = True
            self.stun_thread.start()
            
            bootstrap_thread = threading.Thread(target=self.connect_to_bootstrap, name="BootstrapThread")
            bootstrap_thread.daemon = True
            bootstrap_thread.start()

            self._start_gossip_thread()


    @staticmethod
    def XOR_distance(id1, id2):

        return id1 ^ id2


    @staticmethod
    def hash_data(data):

        return hashlib.sha1(data).hexdigest()


    def _get_bucket_index(self, node_id):

        distance = self.XOR_distance(self.node_id, node_id)

        if distance == 0:
            return -1
        
        return distance.bit_length() - 1


    def add_node(self, node_id, host, port, public_host, public_port):

        new_node_contact = {'id': node_id, 'host': host, 'port': port, 'public_host': public_host, 'public_port': public_port}

        with self.nodes_lock:

            bucket_index = self._get_bucket_index(node_id)

            if bucket_index < 0:
                return
            
            bucket = self.k_buckets[bucket_index]

            for i, contact in enumerate(bucket):

                if contact['id'] == node_id:

                    bucket.pop(i)
                    bucket.append(new_node_contact)
                    return
                
            if len(bucket) < self.k:

                bucket.append(new_node_contact)
            
            else:

                ping_thread = threading.Thread(target = self._handle_full_bucket, 
                                               args = (bucket[0], new_node_contact, bucket_index))
                
                ping_thread.start()


    def _handle_full_bucket(self, oldest_node, new_node_contact, bucket_index):

        is_responsive = self.connect_and_ping(oldest_node['host'], oldest_node['port'])

        with self.nodes_lock:

            bucket = self.k_buckets[bucket_index]

            if not bucket:
                return
            
            if not is_responsive and bucket and bucket[0]['id'] == oldest_node['id']:

                bucket.pop(0)
                bucket.append(new_node_contact)
                log.info(f"Replaced unresponsive node {str(oldest_node['id'])[:10]}...")


    def remove_node(self, node_addr_tuple):

        with self.nodes_lock:

            for bucket in self.k_buckets:

                for i, contact in enumerate(bucket):

                    if (contact['host'], contact['port']) == node_addr_tuple:

                        bucket.pop(i)
                        log.info(f"Removed unresponsive node: {node_addr_tuple}")
                        return

   
    def start_listener(self):

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen()
            log.info(f"Node listening on {self.host}:{self.port}")
            
            while True:

                client, address = server.accept()
                handler_thread = threading.Thread(target=self.handle_incoming_connection, args=(client, address), name=f"Handler-{address[1]}")
                handler_thread.daemon = True
                handler_thread.start()


    def handle_incoming_connection(self, conn, addr):

        if self.is_bootstrap:

            self._handle_bootstrap_connection(conn, addr)

        else:

            self._handle_peer_connection(conn, addr)
    

    @staticmethod
    def recvall(conn, n):

        data = bytearray()

        while len(data) < n:

            packet = conn.recv(n - len(data))
            if not packet: return None
            data.extend(packet)

        return bytes(data)


    def _handle_bootstrap_connection(self, conn, addr):

        log.info(f"Bootstrap: Handling registration from {addr}")

        try:

            buffer = b""

            while b'\n' not in buffer:

                data = conn.recv(1024)
                if not data: return
                buffer += data

            line, _ = buffer.split(b'\n', 1)
            decoded_line = line.decode('utf-8').strip()
            parts = decoded_line.split("::")
            command = parts[0].upper()

            if command == "REGISTER" and len(parts) == 6:

                node_id, host, port, public_host, public_port = int(parts[1]), parts[2], int(parts[3]), parts[4], int(parts[5])
                existing_contacts = []

                with self.nodes_lock:

                    for bucket in self.k_buckets:

                        for contact in bucket:

                            existing_contacts.append(f"{contact['id']}::{contact['host']}::{contact['port']}::{contact['public_host']}::{contact['public_port']}")

                peer_list_str = ",".join(existing_contacts)
                response = f"PEER_LIST::{peer_list_str}\n"
                conn.sendall(response.encode('utf-8'))

                log.info(f"Bootstrap: Sent list of {len(existing_contacts)} peers to new node.")
                self.add_node(node_id, host, port, public_host, public_port)

            elif command == "PUNCH_INIT" and len(parts) == 3:

                try:
                    
                    requester_id = int(parts[1])
                    target_id = int(parts[2])

                    log.info(f"Bootstrap: Received PUNCH_INIT from {requester_id} for {target_id}")

                    requester_contact = self.find_contact_by_id(requester_id)
                    target_contact = self.find_contact_by_id(target_id)

    
                    if requester_contact and target_contact:

                        alice_message = f"PUNCH_INFO::{target_contact['public_host']}::{target_contact['public_port']}\n"
                        conn.sendall(alice_message.encode('utf-8'))

                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(3)
                            bob_address = (target_contact['host'], target_contact['port'])
                            s.connect(bob_address)
                            
                            bob_message = f"PUNCH_REQUEST::{requester_contact['public_host']}::{requester_contact['public_port']}\n"
                            s.sendall(bob_message.encode('utf-8'))
                        
                        log.info(f"Bootstrap: Successfully coordinated punch between {requester_id} and {target_id}")

                    else:

                        error_message = b"ERROR::NODE_NOT_FOUND\n"
                        conn.sendall(error_message)
                        log.warning("Bootstrap: PUNCH_INIT failed, one or more nodes not found.")

                except (ValueError, IndexError) as e:
                    log.error(f"Bootstrap: Invalid PUNCH_INIT command: {e}")

        except Exception as e:

            log.error(f"Bootstrap error with {addr}: {e}")
        finally:

            conn.close()


    def _handle_peer_connection(self, conn, addr):

        session_crypto = None
        buffer = b'' 

        try:

            key = self.recvall(conn, 44)

            if not key:

                return
            
            session_crypto = Crypto()
            session_crypto.f = Fernet(key)

            while True:

                data = conn.recv(4096)
                if not data:

                    break

                buffer += data
                while b'\n' in buffer:

                    header_line, buffer = buffer.split(b'\n', 1)
                    decoded_line = header_line.decode('utf-8').strip()
                    parts = decoded_line.split("::")
                    command = parts[0].upper()

                    if command == "STORE_CHUNK" and len(parts) == 3:

                        chunk_hash, chunk_size = parts[1], int(parts[2])

                        if len(buffer) >= chunk_size:

                            encrypted_chunk, buffer = buffer[:chunk_size], buffer[chunk_size:]
                        
                        else:

                            encrypted_chunk, buffer = buffer + self.recvall(conn, chunk_size - len(buffer)), b''
                        
                        if encrypted_chunk and session_crypto:

                            decrypted_chunk = session_crypto.decrypt_bytes(encrypted_chunk)
                            os.makedirs("chunk_storage", exist_ok=True)
                            with open(os.path.join("chunk_storage", chunk_hash), "wb") as f: f.write(decrypted_chunk)
                            log.info(f"Stored chunk {chunk_hash[:10]}... from {addr}")

                    elif command == "GET_CHUNK" and len(parts) == 2:

                        chunk_hash = parts[1]
                        chunk_path = os.path.join("chunk_storage", chunk_hash)

                        if os.path.exists(chunk_path) and session_crypto:

                            with open(chunk_path, "rb") as f:

                                chunk_data = f.read()

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
                            contact_list_str = ",".join([f"{c['id']}::{c['host']}::{c['port']}::{c['public_host']}::{c['public_port']}" for c in all_contacts[:self.k]])
                        
                        conn.sendall(f"FOUND_NODES::{contact_list_str}\n".encode('utf-8'))
                    
                    elif command == "PING":

                        conn.sendall(b"PONG\n")

        except (ConnectionResetError, BrokenPipeError):
             
             log.warning(f"Connection with {addr} was forcibly closed.")

        except Exception:

            pass

        finally:

            log.info(f"Closing connection for {addr}")
            conn.close()


    def connect_to_bootstrap(self):
        
        if self.stun_thread:
            self.stun_thread.join()

        if not self.bootstrap_address or self.bootstrap_address == (self.host, self.port): return
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            try:

                s.settimeout(5)
                s.connect(self.bootstrap_address)
                
                register_message = f"REGISTER::{self.node_id}::{self.host}::{self.port}::{self.public_host}::{self.public_port}\n"
                s.sendall(register_message.encode('utf-8'))
                
                response = s.recv(8192).decode('utf-8').strip()
                parts = response.split("::", 1)

                if parts[0] == "PEER_LIST" and len(parts) > 1 and parts[1]:

                    contacts = parts[1].split(',')

                    for contact_str in contacts:

                        try:

                            c_parts = contact_str.split('::')

                            if len(c_parts) == 5:

                                node_id, host, port, public_host, public_port = int(c_parts[0]), c_parts[1], int(c_parts[2]), c_parts[3], int(c_parts[4])
                                if node_id != self.node_id: self.add_node(node_id, host, port, public_host, public_port)
                        
                        except (ValueError, IndexError):
                            
                            continue

                    log.info(f"Processed {len(contacts)} peers from bootstrap.")

            except Exception as e:

                log.error(f"Bootstrap connection failed: {e}")
    

    def connect_and_ping(self, host, port):

        try:

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

                s.settimeout(2)
                s.connect((host, port))
                s.sendall(f"PING::{self.node_id}\n".encode('utf-8'))

                return s.recv(1024).strip() == b"PONG"
        
        except Exception:

            return False


    def find_closest_nodes(self, target_id):

        shortlist, queried_nodes = [], {self.node_id}

        with self.nodes_lock:

            all_contacts = []
            for bucket in self.k_buckets: all_contacts.extend(bucket)

            if not all_contacts:

                return []
            
            all_contacts.sort(key=lambda c: self.XOR_distance(c['id'], target_id))

            for contact in all_contacts[:self.k]:

                shortlist.append((self.XOR_distance(contact['id'], target_id), contact))
        
        while True:

            nodes_to_query = []

            for _, contact in shortlist:

                if contact['id'] not in queried_nodes:

                    nodes_to_query.append(contact)

                if len(nodes_to_query) == self.alpha:

                    break

            if not nodes_to_query:
                break

            response_queue, threads = queue.Queue(), []

            for contact in nodes_to_query:

                queried_nodes.add(contact['id'])
                thread = threading.Thread(target=self.connect_and_find_nodes, args=(target_id, contact['host'], contact['port'], response_queue))
                threads.append(thread); thread.start()

            for t in threads:

                t.join()

            old_closest_distance = shortlist[0][0] if shortlist else None

            while not response_queue.empty():

                for contact in response_queue.get():

                    if contact['id'] not in queried_nodes:

                        shortlist.append((self.XOR_distance(contact['id'], target_id), contact))

            shortlist.sort(key=lambda x: x[0]); shortlist = shortlist[:self.k]
            new_closest_distance = shortlist[0][0] if shortlist else None

            if new_closest_distance is None or (old_closest_distance is not None and new_closest_distance >= old_closest_distance):
                break

        return [contact for _, contact in shortlist]


    def connect_and_find_nodes(self, target_id, host, port, response_queue):

        try:

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

                s.settimeout(3)
                s.connect((host, port))
                s.sendall(self.crypto.key) 
                s.sendall(f"FIND_NODE::{target_id}\n".encode('utf-8'))

                response_data = s.recv(8192).decode('utf-8').strip()
                parts = response_data.split("::", 1)

                if parts[0] == "FOUND_NODES" and len(parts) > 1 and parts[1]:

                    new_contacts = []
                    for contact_str in parts[1].split(','):

                        try:

                            c_parts = contact_str.split('::')

                            if len(c_parts) == 5:

                                new_contacts.append({'id': int(c_parts[0]), 'host': c_parts[1], 'port': int(c_parts[2]), 'public_host': c_parts[3], 'public_port': int(c_parts[4])})
                        
                        except (ValueError, IndexError): continue
                    response_queue.put(new_contacts)

        except Exception:

            pass

   
    def upload_file(self, filepath):

        if not os.path.exists(filepath):
            
            log.error(f"File not found: {filepath}"); return
        
        file_map = {"filename": os.path.basename(filepath), "filesize": os.path.getsize(filepath), "chunks": []}
        log.info(f"Starting DHT upload for [bold cyan]{filepath}[/bold cyan]", extra={"markup": True})

        with open(filepath, "rb") as f:

            chunk_index = 0
            
            while True:

                chunk_data = f.read(self.chunk_size)

                if not chunk_data:
                    break

                chunk_hash = self.hash_data(chunk_data)
                chunk_key = int(chunk_hash, 16)
                log.info(f"Finding closest nodes for chunk {chunk_index} ([yellow]{chunk_hash[:10]}[/yellow]...)", extra={"markup": True})
                nodes_to_store_on = self.find_closest_nodes(chunk_key)

                if not nodes_to_store_on:

                    log.error(f"Could not find nodes for chunk {chunk_index}. Aborting."); return
                
                chunk_locations, threads = [], []

                for node in nodes_to_store_on:

                    thread = threading.Thread(target=self.connect_and_store_chunk, args=(chunk_data, node['host'], node['port']))
                    threads.append(thread); thread.start()
                    chunk_locations.append([node['host'], node['port']])

                for t in threads:
                    t.join()

                file_map["chunks"].append([chunk_hash, chunk_locations])
                chunk_index += 1

        os.makedirs("file_maps", exist_ok=True)
        map_filepath = os.path.join("file_maps", f"{file_map['filename']}.json")
        with open(map_filepath, "w") as map_file: json.dump(file_map, map_file, indent=4)

        log.info(f"Upload complete. File map saved to [green]{map_filepath}[/green]", extra={"markup": True})


    def download_file(self, filename):

        map_filepath = os.path.join("file_maps", f"{filename}.json")

        if not os.path.exists(map_filepath):

            log.error(f"File map not found for '{filename}'."); return
        
        with open(map_filepath, "r") as map_file: file_map = json.load(map_file)

        log.info(f"Starting download for [bold cyan]{file_map['filename']}[/bold cyan]", extra={"markup": True})
        download_threads = []

        for chunk_hash, locations in file_map["chunks"]:

            thread = threading.Thread(target=self._download_chunk, args=(chunk_hash, locations))
            download_threads.append(thread); thread.start()

        for t in download_threads:
            t.join()

        self._reassemble_file(file_map)


    def _download_chunk(self, chunk_hash, locations):

        for host, port in locations:

            if self.connect_and_get_chunk(chunk_hash, host, port):
                return
            
        log.error(f"Failed to retrieve chunk {chunk_hash} from any known location.")


    def _reassemble_file(self, file_map):

        output_filename = f"downloaded_{file_map['filename']}"
        log.info(f"Reassembling chunks into [green]{output_filename}[/green]", extra={"markup": True})

        try:

            with open(output_filename, "wb") as output_file:

                for chunk_hash, _ in file_map["chunks"]:

                    chunk_path = os.path.join("retrieved_chunks", chunk_hash)

                    if os.path.exists(chunk_path):

                        with open(chunk_path, "rb") as chunk_file: output_file.write(chunk_file.read())
                        os.remove(chunk_path)

                    else:

                        log.error(f"Missing chunk {chunk_hash}! Reassembly failed."); return
                    
            log.info(f"File {output_filename} reassembled successfully.", extra={"markup": True})
            
        except Exception as e:

            log.error(f"An error occurred during file reassembly: {e}")


    def connect_and_store_chunk(self, chunk_data, host, port):

        try:

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

                s.settimeout(10)
                s.connect((host, port))
                s.sendall(self.crypto.key)

                encrypted_chunk = self.crypto.encrypt_bytes(chunk_data)
                chunk_hash = self.hash_data(chunk_data)
                header = f"STORE_CHUNK::{chunk_hash}::{len(encrypted_chunk)}\n"

                s.sendall(header.encode("utf-8"))
                s.sendall(encrypted_chunk)

        except Exception as e:

            log.error(f"Failed to store chunk at {host}:{port}: {e}")
            self.remove_node((host, port))


    def connect_and_get_chunk(self, chunk_hash, host, port):

        try:

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

                s.settimeout(10)
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

                    if len(buffer) >= chunk_size:

                        encrypted_chunk = buffer[:chunk_size]

                    else:

                        encrypted_chunk = buffer + self.recvall(s, chunk_size - len(buffer))

                    decrypted_chunk = self.crypto.decrypt_bytes(encrypted_chunk)

                    if self.hash_data(decrypted_chunk) == response_hash:

                        os.makedirs("retrieved_chunks", exist_ok=True)
                        with open(os.path.join("retrieved_chunks", response_hash), "wb") as f: f.write(decrypted_chunk)
                        log.info(f"Received and verified chunk {response_hash[:10]}...")

                        return True
                    
                return False
            
        except Exception as e:

            log.error(f"Failed to get chunk from {host}:{port}: {e}")
            self.remove_node((host, port))

            return False


    def _start_gossip_thread(self):

        def gossip_loop():

            while True:

                time.sleep(30)

                with self.nodes_lock:

                    all_known_nodes = []
                    for bucket in self.k_buckets: all_known_nodes.extend(bucket)

                if not all_known_nodes:

                    self.connect_to_bootstrap()
                    continue

                random_node = random.choice(all_known_nodes)
                self.find_closest_nodes(self.node_id)

        threading.Thread(target=gossip_loop, name="GossipThread", daemon=True).start()

    
    def _print_welcome_banner(self):

        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right")
        grid.add_row(
            f"[bold magenta]Kademlia DHT Node[/bold magenta] | ID: [cyan]{str(self.node_id)[:15]}[/cyan]...",
            f"Listening on [bold]{self.host}:{self.port}[/bold]"
        )
        
        panel = Panel(
            grid,
            title="[bold green]Node Initialized[/bold green]",
            border_style="green",
            padding=(1, 2)
        )
        console.print(panel)
        console.print("[bold]Commands:[/bold] peers, upload <file>, download <file>, list_files, exit")


    def run_user_interface(self):

        self._print_welcome_banner()

        while True:

            try:

                message = console.input("[bold cyan]> [/bold cyan]")

                if not message:

                    continue
                
                full_parts = message.split()
                command = full_parts[0].lower()

                if command == 'exit':
                    break
                
                elif command == 'peers':

                    nodes_to_display = []
                    with self.nodes_lock:
                        for bucket in self.k_buckets: nodes_to_display.append(list(bucket))
                    
                    table = Table(title="[bold magenta]K-Bucket Routing Table[/bold magenta]")
                    table.add_column("Bucket", justify="right", style="cyan", no_wrap=True)
                    table.add_column("Node ID", style="magenta")
                    table.add_column("Address", justify="right", style="green")
                    table.add_column("Public UDP", style="yellow")

                    total_nodes = 0

                    for i, bucket in enumerate(nodes_to_display):

                        if bucket:

                            for node in bucket:

                                table.add_row(str(i), f"{str(node['id'])[:15]}...", f"{node['host']}:{node['port']}")

                            total_nodes += len(bucket)
                    
                    console.print(table)
                    console.print(f"[bold]Total known nodes:[/bold] {total_nodes}")

                elif command == 'upload' and len(full_parts) == 2:

                    filepath = full_parts[1]
                    threading.Thread(target=self.upload_file, args=(filepath,), name=f"Upload-{os.path.basename(filepath)}").start()
                
                elif command == 'connect' and len(full_parts) == 2:

                    if not full_parts[1].isdigit():

                        console.print("[bold red]Error: Please use the number from the 'peers' list.[/bold red]")
                        continue
                    
                    target_contact = self._get_contact_by_index(int(full_parts[1]))

                    if target_contact is None:

                        console.print(f"[bold red]Error: No peer with number {full_parts[1]}.[/bold red]")
                        continue

                    threading.Thread(target=self.connect_p2p, args=(target_contact['id'],)).start()

                elif command == 'download' and len(full_parts) == 2:

                    filename = full_parts[1]
                    threading.Thread(target=self.download_file, args=(filename,), name=f"Download-{filename}").start()
                
                elif command == 'list_files':

                    maps_dir = "file_maps"

                    if not os.path.exists(maps_dir) or not os.listdir(maps_dir):

                        console.print("[yellow]No file maps found.[/yellow]")

                    else:

                        table = Table(title="[bold magenta]Available File Maps[/bold magenta]")
                        table.add_column("Filename", style="cyan")

                        for filename in os.listdir(maps_dir):

                            if filename.endswith(".json"):

                                table.add_row(filename.replace('.json', ''))
                        console.print(table)

                else:

                    console.print("[bold red]Invalid command.[/bold red]")

            except KeyboardInterrupt:

                break

            except Exception as e:

                log.error(f"UI Error: {e}", exc_info=True)

        console.print("[bold yellow]Shutting down.[/bold yellow]")


    def _get_contact_by_index(self, user_index):
        
        index = user_index - 1
        
        with self.nodes_lock:
            
            flat_list = []

            for bucket in self.k_buckets:

                flat_list.extend(bucket)
            
            if 0 <= index < len(flat_list):
              
                return flat_list[index]
        
        return None


    def get_public_ip_info(self):

        try:
            stun_server_addr = ('stun.l.google.com', 19302)

            transaction_id_bytes = os.urandom(12)

            request_packet = (
                (0x0001).to_bytes(2, 'big') +        
                (0).to_bytes(2, 'big') +             
                (0x2112A442).to_bytes(4, 'big') +    
                transaction_id_bytes                 
            )

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:

                s.settimeout(3)
                s.sendto(request_packet, stun_server_addr)
                
                response_data, _ = s.recvfrom(2048)

            return self.parse_stun_response(response_data, transaction_id_bytes)

        except socket.timeout:
            log.error("STUN request timed out.")
            return None
        except Exception as e:
            log.error(f"An error occurred during STUN request: {e}")
            return None
    

    def parse_stun_response(self, response_data, transaction_id_bytes):
     
        msg_type = int.from_bytes(response_data[0:2], 'big')
        msg_len = int.from_bytes(response_data[2:4], 'big')
        magic_cookie = int.from_bytes(response_data[4:8], 'big')
        resp_tid = response_data[8:20]

        
        if msg_type != 0x0101 or resp_tid != transaction_id_bytes:
            log.error("Invalid STUN response or transaction ID mismatch.")
            return None

        current_position = 20 
        while current_position < len(response_data):
        
            attr_type = int.from_bytes(response_data[current_position : current_position + 2], 'big')
            attr_len = int.from_bytes(response_data[current_position + 2 : current_position + 4], 'big')
            
            if attr_type == 0x0020:
               
                value_start = current_position + 4
                
                xor_port_bytes = response_data[value_start + 2 : value_start + 4]
                xor_ip_bytes = response_data[value_start + 4 : value_start + 8]

                
                xor_port = int.from_bytes(xor_port_bytes, 'big')
                xor_ip = int.from_bytes(xor_ip_bytes, 'big')

                real_port = xor_port ^ (magic_cookie >> 16) 
                real_ip_int = xor_ip ^ magic_cookie
                real_ip = str(ipaddress.IPv4Address(real_ip_int))
                
                log.info(f"STUN Discovery: Public IP is {real_ip}:{real_port}")
                return real_ip, real_port
            
            else:
        
                current_position += (4 + attr_len)

        log.error("Could not find XOR-MAPPED-ADDRESS in STUN response.")
        return None


    def discover_public_ip(self):
       
        public_ip_info = self.get_public_ip_info() 
        
        if public_ip_info:
            
            self.public_host, self.public_port = public_ip_info
            log.info(f"Successfully discovered public endpoint: {self.public_host}:{self.public_port}")
        
        else:

            log.warning("Could not discover public IP via STUN. P2P connections may fail.")


    def find_contact_by_id(self, node_id):
        
        with self.nodes_lock:
            
            for bucket in self.k_buckets:
            
                for contact in bucket:
                    
                    if contact['id'] == node_id:
                        return contact 
        
        return None


    def initiate_udp_punch(self, target_host, target_port):

        log.info(f"Attempting UDP hole punch to {target_host}:{target_port}...")

        try:

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:

                s.bind((self.host, 0))
                s.settimeout(3)

                target_address = (target_host, target_port)

                logging.info("\nPunching a hole >:) .....")

                for _ in range(3):

                    s.sendto(b"blah blah blah", target_address)
                    time.sleep(0.1)
                
                data, addr = s.recvfrom(1024)
                if data == b"punch_back":

                    logging.info(f"Hole punch successful! Received acknowledgement from {addr}.")
                    return True

        except socket.timeout:

            log.warning("Hole punch failed: Did not receive a response.")

        except Exception as e:

            log.error(f"An error occurred during hole punch: {e}")
            
        return False


    def respond_to_udp_punch(self, udp_socket, target_address):
        
        udp_socket.sendto(b"punch_back", target_address)


    def connect_p2p(self, target_node_id):
        
        log.info(f"Attempting P2P connection with node {str(target_node_id)[:15]}...")
        
       
        target_contact = self._find_contact_by_id(target_node_id)

        if not target_contact:

            log.error(f"Cannot connect: Node {str(target_node_id)[:15]}... not found in routing table.")
            return

        if target_contact['host'] == self.host:

            log.info("Target is on the same local machine. Attempting direct TCP connection...")
            
            try:

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

                    s.settimeout(3)
                    s.connect((target_contact['host'], target_contact['port']))
                    log.info(f"[bold green]Success![/bold green] Direct local connection established with {target_contact['host']}:{target_contact['port']}", extra={"markup": True})
                
                return
            
            except Exception as e:

                log.error(f"Direct local connection failed: {e}. Falling back to NAT traversal.")

        target_public_host, target_public_port = None, None

        try:

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

                s.settimeout(5)
                s.connect(self.bootstrap_address)
                request_message = f"PUNCH_INIT::{self.node_id}::{target_node_id}\n"
                s.sendall(request_message.encode('utf-8'))

                response = s.recv(1024).decode('utf-8').strip()
                parts = response.split("::")
                if parts[0] == "PUNCH_INFO" and len(parts) == 3:

                    target_public_host, target_public_port = parts[1], int(parts[2])
                    log.info(f"Received rendezvous info: {target_public_host}:{target_public_port}")
                
                else:

                    log.error(f"Rendezvous failed. Response: {response}"); return
        
        except Exception as e:

            log.error(f"Failed to initiate rendezvous: {e}"); return

        if not target_public_host or not target_public_port:

            log.error("Aborting P2P connect: Could not get target public address."); return

        listener_socket = None

        try:

            listener_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            listener_socket.bind((self.host, 0))
            listener_socket.settimeout(5)
            punching_thread = threading.Thread(target=self.initiate_udp_punch, args=(target_public_host, target_public_port))
            punching_thread.daemon = True
            punching_thread.start()
            
            log.info("Listening for peer's punch packet...")
            data, addr = listener_socket.recvfrom(1024)
            log.info(f"[bold green]Success![/bold green] Direct UDP link established with {addr}", extra={"markup": True})
        
        except socket.timeout:

            log.error("[bold red]P2P connection failed.[/bold red] Did not receive a punch from the peer.", extra={"markup": True})
        
        except Exception as e:

            log.error(f"An error occurred during P2P connection: {e}")

        finally:

            if listener_socket: listener_socket.close()
            
        
if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Start a Kademlia DHT Node for a decentralized storage network.",
        epilog="Example: python Node.py 2068 --bootstrap localhost:2067"
    )
    
    parser.add_argument('port', type=int, help="The port number for this node to listen on.")
    parser.add_argument('--host', type=str, default='localhost', help="The host address for this node to bind to (default: localhost).")
    parser.add_argument('--bootstrap', type=str, default=None, help="The address of the bootstrap node in host:port format.")
    parser.add_argument('--is-bootstrap', action='store_true', help="Run this node as the bootstrap server.")

    args = parser.parse_args()

    bootstrap_addr = None

    if args.is_bootstrap:

        bootstrap_addr = (args.host, args.port)
        console.print(Panel(f"[bold green]Starting in BOOTSTRAP mode on {args.host}:{args.port}[/bold green]"))

    elif args.bootstrap:

        try:

            host, port_str = args.bootstrap.split(':')
            bootstrap_addr = (host, int(port_str))

        except ValueError:
            
            console.print("[bold red]Error: Invalid bootstrap address format. Use host:port.[/bold red]")
            sys.exit(1)

    my_node = Node(host=args.host,
                   port=args.port,
                   is_bootstrap=args.is_bootstrap,
                   bootstrap_address=bootstrap_addr)
    
    my_node.run_user_interface()

