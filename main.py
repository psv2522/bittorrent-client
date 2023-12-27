import bencodepy
import sys 
import hashlib

def calculate_info_hash(info):
    encoded_info = bencodepy.encode(info)
    sha1_hash = hashlib.sha1(encoded_info).digest()
    return sha1_hash

def parse_torrent_file(file_path):
    with open(file_path, 'rb') as torrent_file:
        # Load the torrent file using bencodepy
        torrent_data = bencodepy.decode(torrent_file.read())

        # Extract relevant information
        info = torrent_data[b'info']

        # Display tracker information if available
        if b'announce' in torrent_data:
            tracker_url = torrent_data[b'announce'].decode('utf-8')
            print(f"\nTracker URL: {tracker_url}")

        # Display general information
        print("Torrent Information:")
        print(f"  Name: {info[b'name'].decode('utf-8')}")
        print(f"  Piece Length: {info[b'piece length']}")
        print(f"  Number of Pieces: {len(info[b'pieces']) // 20}")

        # Calculate and print the info hash
        info_hash = calculate_info_hash(info)
        info_hash_hex = info_hash.hex()
        print(f"\nInfo Hash (Hex): {info_hash_hex}")
        

if __name__ == "__main__":
    # Check if a filename is provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python script.py <torrent_file>")
        sys.exit(1)

    # Take the filename from the command-line argument
    torrent_file_path = sys.argv[1]

    # Parse the torrent file
    parse_torrent_file(torrent_file_path)