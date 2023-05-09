import binascii
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

help = """Synopsis: secretmessages r|s
s send
r receive """
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
    # Generate a random private key for the key agreement protocol
    parameters = generate_domain_parameters()
    private_key = generate_key_pair(parameters)

    # Serialize and send the parameters for the key agreement protocol
    serialized_parameters = parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3)

    # Serialize the public key for the key agreement protocol
    serialized_public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        BUFFER_LIMIT = 1024 * 10
        s.connect((ip, 5555))
        print("Connected to receiver")
        s.sendall(serialized_parameters + b'----END PARAMETERS----')
        print("Sent domain parameters")
        s.sendall(serialized_public_key + b'----END PUBLIC KEY----')
        print("Sent public key")

        # Receive the other party's public key and compute the shared secret key
        received_data = b''
        while not received_data.endswith(b'----END PUBLIC KEY----'):
            received_data += s.recv(1024)
            if len(received_data) >= BUFFER_LIMIT:
                print("Buffer limit reached in send_message")
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
        print(f'Encrypted Message: {data["msg"]}')
        serialized_data = pickle.dumps(data)
        s.sendall(serialized_data)
        print("Sent encrypted message, key and MAC")



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
    print("Received domain parameters")
    if len(received_data) >= BUFFER_LIMIT:
        print("Buffer limit reached in receive_message (domain parameters)")
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
    print("Received sender's public key")
    if len(received_data) >= BUFFER_LIMIT:
        print("Buffer limit reached in receive_message (public key)")
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
    print("Received encrypted message, key, and MAC")

    # Deserialize the received data
    data = pickle.loads(serialized_data)
    encrypted_msg = data['msg']
    encrypted_key = data['encrypted_key']
    received_mac = data['mac']

    # Verify the MAC
    expected_mac = hmac.new(shared_secret_key, encrypted_msg, digestmod=hashlib.sha256).digest()
    if not hmac.compare_digest(received_mac, expected_mac):
        print("MAC verification failed")
        conn.close()
        server.close()
        return b''


    # Decrypt the key using the shared secret key
    shared_secret_key_str = shared_key_to_string(shared_secret_key, max_msg_len)
    key = decrypt(encrypted_key, shared_secret_key_str)

    # Decrypt the message using the key
    plaintext = decrypt(encrypted_msg, key)
    print("Decrypted message:", plaintext.decode('utf-8'))
    conn.close()
    server.close()

    return plaintext



if __name__ == '__main__':
    print(help)
    opt = input("do you want to recieve or send: ")

    
    if opt == "s":
        ip = input("Enter the IP address to send the message to: ")
        msg = input("Enter the message: ")
        send_message(ip, msg)
    elif opt == "r":
        receive_message()
    else:
        print(help)
        exit(0)
