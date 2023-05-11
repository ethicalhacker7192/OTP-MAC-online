import threading
import string
import random
import time
import sys
import socket
import pickle
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

keyboard = string.printable[:-5]
one_time_pad = list(keyboard)

help = """
   ___      _               ___              _         
  / __|_  _(_)_ _  ___ __ _/ __| ___ _ _  __| |___ _ _ 
 | (_ | || | | ' \/ -_) _` \__ \/ -_) ' \/ _` / -_) '_|
  \___|\_,_|_|_||_\___\__,_|___/\___|_||_\__,_\___|_|  
                                                       

help: GuineaSender r|s|t|q
s: send
r: receive
t: transcieve (recieve and send at same time)
q: quit """
def generate_mac(msg, key):
    mac = hmac.new(key, msg.encode('utf-8'), hashlib.sha512).hexdigest()

    # Repeat the MAC until it reaches the desired length
    while len(mac) < 1000:
        mac += hmac.new(key, mac.encode('utf-8'), hashlib.sha512).hexdigest()

    return mac[:1000]
    
def encrypt(msg, key):
    ciphertext = bytearray()
    for idx, char in enumerate(msg):
        charIdx = keyboard.index(char)
        keyIdx = one_time_pad.index(key[idx % len(key)])
        cipher = (keyIdx + charIdx) % len(one_time_pad)

        # Check if the generated cipher is a printable character
        while not keyboard[cipher].isprintable():
            keyIdx = one_time_pad.index(random.choice(one_time_pad))
            cipher = (keyIdx + charIdx) % len(one_time_pad)

        ciphertext.append(keyboard[cipher].encode('utf-8')[0])

    return bytes(ciphertext)



def decrypt(ciphertext, key):
    if not ciphertext or not key:
        return b''

    if isinstance(ciphertext, int):
        ciphertext = bytearray([ciphertext])

    if isinstance(ciphertext, str):
        ciphertext = bytearray(ciphertext, 'utf-8')

    if isinstance(key, str):
        key = bytearray(key, 'utf-8')

    decrypted_text = bytearray()
    for i in range(len(ciphertext)):
        charIdx = one_time_pad.index(chr(ciphertext[i]))
        keyIdx = one_time_pad.index(chr(key[i]))

        cipher = (charIdx - keyIdx) % len(one_time_pad)
        char = keyboard[cipher].encode('utf-8')
        decrypted_text.extend(char)

    return decrypted_text


    
def shared_key_to_string(shared_key, length):
    random.seed(shared_key)
    return ''.join([random.choice(one_time_pad) for _ in range(length)])



def generate_key_pair(parameters):
    # Generate the private key for the Diffie-Hellman key exchange
    private_key = parameters.generate_private_key()

    # Return the private key
    return private_key

def compute_shared_secret(private_key, other_public_key):
    shared_key = private_key.exchange(other_public_key)
    return shared_key

def generate_domain_parameters():
    # Define the domain parameters for the Diffie-Hellman key exchange
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

def send_message(ip, msg):
    pipe_chars = "|/-\\"
    # Generate a random private key for the key agreement protocol
    parameters = generate_domain_parameters()
    private_key = generate_key_pair(parameters)

    # Serialize and send the parameters for the key agreement protocol
    serialized_parameters = parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3)

    # Serialize the public key for the key agreement protocol
    serialized_public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        for i in range(100):
            sys.stdout.write('\r' + 'Connecting to client... ' + pipe_chars[i % len(pipe_chars)])
            sys.stdout.flush()
            time.sleep(0.1)

        BUFFER_LIMIT = 1024 * 10
        s.connect((ip, 5555))
        print("\nConnected to receiver")

        # Display a rotating progress indicator while creating the keys
        for i in range(100):
            sys.stdout.write('\r' + 'Creating keys... ' + pipe_chars[i % len(pipe_chars)])
            sys.stdout.flush()
            time.sleep(0.1)

        s.sendall(serialized_parameters + b'----END PARAMETERS----')
        print("\nSent domain parameters")
        s.sendall(serialized_public_key + b'----END PUBLIC KEY----')
        print("\nSent public key")

        # Receive the other party's public key and compute the shared secret key
        received_data = b''
        while not received_data.endswith(b'----END PUBLIC KEY----'):
            received_data += s.recv(1024)
            if len(received_data) >= BUFFER_LIMIT:
                print("\nBuffer limit reached in send_message (public key)")
                break
        serialized_other_public_key = received_data[:-20]  # Remove the delimiter

        other_public_key = serialization.load_pem_public_key(serialized_other_public_key, backend=default_backend())
        shared_secret_key = compute_shared_secret(private_key, other_public_key)
        shared_secret_key_str = shared_key_to_string(shared_secret_key, max(1000, len(msg)))

        # Encrypt the key using the shared secret key
        key = ''.join(random.choices(one_time_pad, k=max(1000, len(msg))))
        encrypted_key = encrypt(key, shared_secret_key_str)

        # Compute the MAC using the shared secret key and send it along with the encrypted message and key
        mac = hmac.new(shared_secret_key, encrypt(msg, key), digestmod=hashlib.sha256).digest()
        data = {'msg': encrypt(msg, key), 'encrypted_key': encrypted_key, 'mac': mac}
        print(f'\nEncrypted Message: {data["msg"]}')

        # Display a rotating progress indicator while sending the message
        for i in range(100):
            sys.stdout.write('\r' + 'Sending message... ' + pipe_chars[i % len(pipe_chars)])
            sys.stdout.flush()
            time.sleep(0.1)

        serialized_data = pickle.dumps(data)
        s.sendall(serialized_data)
        print("\nSent encrypted message, key and MAC")



def receive_message():
    BUFFER_LIMIT = 1024 * 10
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))
    server.listen(1)
    conn, addr = server.accept()
    print('Connected to', addr)

    # Receive the domain parameters for the key agreement protocol
    received_data = b''
    while not received_data.endswith(b'----END PARAMETERS----'):
        received_data += conn.recv(1024)
    print("\nReceived domain parameters\n")
    if len(received_data) >= BUFFER_LIMIT:
        print("\nBuffer limit reached while receiving (domain parameters)\n")
    serialized_parameters = received_data[:-20]  # Remove the delimiter

    parameters = serialization.load_pem_parameters(serialized_parameters, backend=default_backend())

    # Generate a random private key for the key agreement protocol
    private_key = generate_key_pair(parameters)

    # Serialize the public key for the key agreement protocol
    serialized_public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    conn.sendall(serialized_public_key + b'----END PUBLIC KEY----')

    # Receive the other party's public key and compute the shared secret key
    received_data = b''
    while not received_data.endswith(b'----END PUBLIC KEY----'):
        received_data += conn.recv(1024)
    print("\nReceived sender's public key\n")
    if len(received_data) >= BUFFER_LIMIT:
        print("\nBuffer limit reached while receiving (public key)\n")
    serialized_other_public_key = received_data[:-20]  # Remove the delimiter

    other_public_key = serialization.load_pem_public_key(serialized_other_public_key, backend=default_backend())
    shared_secret_key = compute_shared_secret(private_key, other_public_key)
    max_msg_len = 1000  # You can adjust this value according to your requirements

    # Receive the serialized encrypted message, the encrypted key, and the MAC
    serialized_data = b''
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        serialized_data += chunk
    print("\nReceived encrypted message, key, and MAC\n")

    # Deserialize the received data
    data = pickle.loads(serialized_data)
    encrypted_msg = data['msg']
    encrypted_key = data['encrypted_key']
    received_mac = data['mac']

    # Verify the MAC
    expected_mac = hmac.new(shared_secret_key, encrypted_msg, digestmod=hashlib.sha256).digest()
    if not hmac.compare_digest(received_mac, expected_mac):
        print("\nMAC verification failed\n")
        conn.close()
        server.close()
        return b''


    # Decrypt the key using the shared secret key
    shared_secret_key_str = shared_key_to_string(shared_secret_key, max_msg_len)
    key = decrypt(encrypted_key, shared_secret_key_str)

    # Decrypt the message using the key
    plaintext = decrypt(encrypted_msg, key)
    print("\nDecrypted message:", plaintext.decode('utf-8'), "\n")
    conn.close()
    server.close()

    return plaintext
    

def tranceive_message(ip, msg):
    # Start a new thread to handle the sending
    send_thread = threading.Thread(target=send_message, args=(ip, msg))
    send_thread.start()

    # Receive messages in the main thread
    receive_message()

    



if __name__ == '__main__':
    print(help)
    opt = input("do you want to receive (r), send (s), or transceive (t)? (press q to quit) ")
    if opt == "s":
        ip = input("Enter the IP address to send the message to: ")
        msg = input("Enter the message: ")
        send_message(ip, msg)
    elif opt == "r":
        receive_message()
    elif opt == "t":
        ip = input("Enter the IP address to send the message to: ")
        while True:
            msg = input("Enter the message (press 'q' to quit, and 'CHANGEIP' to change the listener IP): ")
            if msg == "q":
                print("exiting...")
                break
            elif msg == "CHANGEIP":
                ip = input("Enter the new IP address to send the message to: ")
            else:
                tranceive_message(ip, msg)
    elif opt == "q":
        print("exiting...")
        exit(0)
    else:
        print(help)
        opt = input("Do you want to receive (r), send (s), or transceive (t)? (Press q to quit) ")
