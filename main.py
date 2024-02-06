import bencodepy
import sys
import hashlib
import requests
import socket
import hashlib
import struct


def create_handshake(info_hash, peer_id):
    """
    Create a BitTorrent handshake message.
    """
    protocol_name = b"BitTorrent protocol"
    reserved_bytes = b"\x00" * 8
    handshake_msg = struct.pack("!B19s8x20s20s", len(protocol_name), protocol_name, reserved_bytes, info_hash, peer_id)
    return handshake_msg


def parse_handshake(handshake_msg):
    """
    Parse a BitTorrent handshake message.
    """
    protocol_len = struct.unpack("!B", handshake_msg[0:1])[0]
    protocol_name = handshake_msg[1 : protocol_len + 1]
    reserved_bytes = handshake_msg[protocol_len + 1 : protocol_len + 9]
    info_hash = handshake_msg[protocol_len + 9 : protocol_len + 29]
    peer_id = handshake_msg[protocol_len + 29 :]
    return protocol_name, reserved_bytes, info_hash, peer_id


def peer_handshake():
    info_hash = "d69f91e6b2ae4c542468d1073a71d4ea13879a7f"
    peer_id = "00112233445566778899"
    peer_ip = "178.62.82.89"
    peer_port = 51470

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, peer_port))

        # Create and send the handshake message
        handshake_msg = create_handshake(info_hash, peer_id)
        s.send(handshake_msg)

        # Receive and parse the handshake response
        response = s.recv(68)  # Assuming the handshake response is 68 bytes
        protocol, reserved, received_info_hash, received_peer_id = parse_handshake(response)

        # Verify the received info hash to ensure the connection is valid
        if received_info_hash == info_hash:
            print("Handshake successful. Connected to the peer.")
        else:
            print("Handshake failed. Invalid info hash.")


# Calculate sha1 info hash
def calculate_info_hash(info):
    encoded_info = bencodepy.encode(info)
    hash = hashlib.sha1(encoded_info).digest()
    return hash


# decoder
def decode_address(peers):
    length = 6
    for i in range(0, len(peers), length):
        ip = ".".join(str(b) for b in peers[i : i + 4])
        port = peers[i + 4] << 8 | peers[i + 5]
        yield ip, port


# Fetch peers from tracker server
def get_peers_from_tracker(tracker_url, info_hash, length):
    params = {
        "info_hash": info_hash,
        "peer_id": "00112233445566778899",
        "port": 6861,
        "uploaded": 0,
        "downloaded": 0,
        "compact": 1,
        "left": length,
    }
    response = requests.get(tracker_url, params=params)

    if response.status_code == 200:
        decoded_value = bencodepy.decode(response.content)
        return decode_address(decoded_value[b"peers"])
    else:
        print(f"Failed to get peers. Status code: {response.status_code}")
        return None

# Torrent file parser
def parse_torrent_file(file_path):
    with open(file_path, "rb") as torrent_file:
        # Load the torrent file using bencodepy
        torrent_data = bencodepy.decode(torrent_file.read())

        # Extract relevant information
        info = torrent_data[b"info"]

        # Display tracker information if available
        if b"announce" in torrent_data:
            tracker_url = torrent_data[b"announce"].decode("utf-8")
            print(f"\nTracker URL: {tracker_url}")
            info = torrent_data[b"info"]
            name = info[b"name"].decode("utf-8")
            length = info[b"piece length"]
            no_of_pieces = len(info[b"pieces"]) // 20

            # print the info hash
            info_hash = calculate_info_hash(info)
            info_hash_hex = info_hash.hex()
            print(f"\nInfo Hash (Hex): {info_hash_hex}")

            peers = get_peers_from_tracker(tracker_url, info_hash, length)
            # print peers
            print("\nIp addresses:")
            for ip, port in peers:
                print(f"{ip}:{port}")

            # Print piece hashes
            piece_hashes = [
                info[b"pieces"][i : i + 20].hex()
                for i in range(0, len(info[b"pieces"]), 20)
            ]
            print("\nPiece Hashes:")
            for i, piece_hash in enumerate(piece_hashes):
                print(f"  Piece {i+1}: {piece_hash}")

        # Display general information
        print("\nTorrent Info")
        print("Name: " + name)
        print("Piece Length: " + str(length))
        print("Number of Pieces: " + str(no_of_pieces))

        peer_handshake()


if __name__ == "__main__":
    # Check if a filename is provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python script.py <torrent_file>")
        sys.exit(1)

    # Take the filename from the command-line argument
    torrent_file_path = sys.argv[1]

    # Parse the .torrent
    parse_torrent_file(torrent_file_path)
