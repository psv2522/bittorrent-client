import bencodepy
import sys 
import hashlib
import requests

#Calculate sha1 info hash
def calculate_info_hash(info):
    encoded_info = bencodepy.encode(info)
    hash = hashlib.sha1(encoded_info).digest()
    return hash

def decode_address(peers):
  
    length = 6
    for i in range(0, len(peers), length):
        ip = ".".join(str(b) for b in peers[i : i + 4])
        port = peers[i + 4] << 8 | peers[i + 5]
        yield ip, port

def get_peers_from_tracker(tracker_url, info_hash,length):
    params = {
        "info_hash": info_hash,
        "peer_id": "00112233445566778899" ,
        "port": 6861,
        "uploaded": 0,
        "downloaded": 0,
        "compact": 1,
        "left":length, 
    }
    response = requests.get(tracker_url, params=params)

    if response.status_code == 200:
        decoded_value = bencodepy.decode(response.content)
        return decode_address(decoded_value[b"peers"])
    else:
        print(f"Failed to get peers. Status code: {response.status_code}")
        return None

def parse_torrent_file(file_path):
    with open(file_path, 'rb') as torrent_file:
        #Load the torrent file using bencodepy
        torrent_data = bencodepy.decode(torrent_file.read())

        #Extract relevant information
        info = torrent_data[b'info']

        #Display tracker information if available
        if b'announce' in torrent_data:
            tracker_url = torrent_data[b'announce'].decode('utf-8')
            print(f"\nTracker URL: {tracker_url}")
            info = torrent_data[b'info']
            name = info[b'name'].decode('utf-8')
            length = info[b'piece length']
            no_of_pieces = len(info[b'pieces']) // 20

            #print the info hash
            info_hash = calculate_info_hash(info)
            info_hash_hex = info_hash.hex()
            print(f"\nInfo Hash (Hex): {info_hash_hex}")

            peers = get_peers_from_tracker(tracker_url, info_hash,length)
            # print peers
            print("\nIp addresses:")
            for ip, port in peers:
                print(f"{ip}:{port}")

            #Print piece hashes
            piece_hashes = [info[b'pieces'][i:i+20].hex() for i in range(0, len(info[b'pieces']), 20)]
            #print("\nPiece Hashes:")
            #for i, piece_hash in enumerate(piece_hashes):
            #  print(f"  Piece {i+1}: {piece_hash}")

        # Display general information
        print("\nTorrent Info")
        print("Name: "+ name)
        print("Piece Length: "+ str(length))
        print("Number of Pieces: "+ str(no_of_pieces))
        

if __name__ == "__main__":
    #Check if a filename is provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python script.py <torrent_file>")
        sys.exit(1)

    #Take the filename from the command-line argument
    torrent_file_path = sys.argv[1]

    #Parse the .torrent
    parse_torrent_file(torrent_file_path)