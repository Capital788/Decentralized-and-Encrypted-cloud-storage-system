# Decentralised and Encrypted Cloud Storage System

A peer-to-peer distributed file storage system built on a **Kademlia DHT** (Distributed Hash Table). Files are split into chunks, encrypted with Fernet symmetric encryption, and distributed across nodes in the network. No central server stores your data.

## How It Works

1. A **bootstrap node** acts as the initial rendezvous point for peers to discover each other.
2. Regular **peer nodes** register with the bootstrap, receive a list of existing peers, and populate their Kademlia routing table (k-buckets).
3. When a file is uploaded, it is split into 4 MB chunks. Each chunk is hashed (SHA-1), and the DHT lookup finds the closest nodes to store it on. Chunks are encrypted before transmission.
4. A **file map** (JSON) is saved locally, recording each chunk's hash and which nodes hold it.
5. To download, the file map is read, chunks are fetched from their recorded nodes, decrypted, verified by hash, and reassembled into the original file.
6. A **gossip thread** runs in the background every 30 seconds to keep the routing table fresh.
7. **STUN** (Google's public STUN server) is used to discover each node's public IP/port for NAT traversal.

## Architecture

| File | Role |
|---|---|
| `Node.py` | Main application — Kademlia DHT node, P2P networking, UI |
| `Encrypter.py` | Fernet encryption/decryption wrapper |
| `FileChunker.py` | File splitting and reassembly utility (standalone) |
| `EchoServer.py` | Earlier prototype server (not part of the DHT system) |
| `originalNode.py` | Archived earlier version of Node.py (for reference only) |

## Requirements

- Python 3.10+
- `cryptography`
- `rich`

Install dependencies:

```bash
pip install cryptography rich
```

## Running the System

### 1. Start the Bootstrap Node

The bootstrap node must be started first. It acts as a rendezvous point and does not store files.

```bash
python Node.py 2067 --is-bootstrap
```

### 2. Start Peer Nodes

Start one or more peer nodes, pointing them at the bootstrap:

```bash
python Node.py 2068 --bootstrap localhost:2067
python Node.py 2069 --bootstrap localhost:2067
```

Each peer gets a random 160-bit Kademlia ID on startup.

## UI Commands

Once a peer node is running, you get an interactive prompt:

| Command | Description |
|---|---|
| `peers` | Display the Kademlia k-bucket routing table and all known nodes |
| `upload <filepath>` | Encrypt and distribute a file across the DHT |
| `download <filename>` | Retrieve and reassemble a file from the DHT |
| `list_files` | List all locally available file maps |
| `exit` | Shut down the node |

### Example Session

```
> upload TestFile.txt
> list_files
> download TestFile.txt
```

The downloaded file will be saved as `downloaded_TestFile.txt` in the current directory.

## Protocol Overview

All peer-to-peer messages are newline-delimited (`\n`) and `::` separated. Connections begin with the sender transmitting a 44-byte Fernet key, after which all chunk data is encrypted.

| Message | Direction | Description |
|---|---|---|
| `REGISTER::id::host::port::pub_host::pub_port` | Node → Bootstrap | Register on the network |
| `PEER_LIST::...` | Bootstrap → Node | List of known peers |
| `FIND_NODE::target_id` | Node → Node | Kademlia node lookup |
| `FOUND_NODES::...` | Node → Node | Closest nodes response |
| `STORE_CHUNK::hash::size` + data | Node → Node | Store an encrypted chunk |
| `GET_CHUNK::hash` | Node → Node | Request a chunk |
| `CHUNK_DATA::hash::size` + data | Node → Node | Deliver an encrypted chunk |
| `PING` / `PONG` | Node → Node | Liveness check |
| `PUNCH_INIT::requester_id::target_id` | Node → Bootstrap | Initiate UDP hole punch |
| `PUNCH_INFO::host::port` | Bootstrap → Node | Rendezvous info for NAT traversal |

## Known Issues

- The `connect` command in the UI raises `AttributeError` due to a typo (`_find_contact_by_id` instead of `find_contact_by_id`). Upload and download are unaffected.
- If a connection drops mid-chunk-transfer, `recvall` returns `None` and concatenation will raise `TypeError`. Rare in practice.
- The "Public UDP" column in the `peers` table is always blank (column defined but value not passed to `add_row`).

## File Storage Layout

```
chunk_storage/      # Chunks stored by this node for other peers
retrieved_chunks/   # Chunks temporarily downloaded during reassembly
file_maps/          # JSON maps recording chunk hashes and locations
```
