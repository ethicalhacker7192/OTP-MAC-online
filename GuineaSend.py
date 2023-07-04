import threading
import string
import random
import os
import time
import sys
import socket
import pickle
import hmac
import hashlib
import platform
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import print_formatted_text

rng = "False"
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
q: quit and self-destruct

"""

def selfdestruct():
    if platform == "Linux":
        os.system('clear')
    elif platform == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def get_ip_address():
    try:
        # The following line of code could fail if the computer is not connected to a network
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # The IP address isn't important here, we just need to specify a valid address
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except OSError:
        ip_address = '127.0.0.1'
    return ip_address

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
    print("To User: I am once again, currently eating my cyber lettuce, please note I will be back when the keys are being generated... -Bear the guinea pig")
    # Generate a random private key for the key agreement protocol
    parameters = generate_domain_parameters()
    private_key = generate_key_pair(parameters)
    for i in range(1000):
        sys.stdout.write('\r' + '*POPCORNING IN THE BACKGROUND OF YOUR COMPUTER* Creating Private key and Domain Parameters... ' + pipe_chars[i % len(pipe_chars)])
        sys.stdout.flush()
        time.sleep(0.01)
    print('\n WHEEK!! Sucess, Tom will receive the message in no time! Private key and Domain Parameters successfully generated!\n')
    # Serialize and send the parameters for the key agreement protocol
    serialized_parameters = parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3)

    # Serialize the public key for the key agreement protocol
    serialized_public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        for i in range(1000):
            sys.stdout.write('\r' + 'WHEEK!! Connecting to client... ' + pipe_chars[i % len(pipe_chars)])
            sys.stdout.flush()
            time.sleep(0.01)

        BUFFER_LIMIT = 1024 * 10
        s.connect((ip, 5555))
        print("\nConnected to receiver")

        # Display a rotating progress indicator while creating the keys
        for i in range(1000):
            sys.stdout.write('\r' + 'GIVE ME PEAFLAKES!! Creating keys... ' + pipe_chars[i % len(pipe_chars)])
            sys.stdout.flush()
            time.sleep(0.01)

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
        for i in range(1000):
            sys.stdout.write('\r' + 'GIVE ME LETTUCE HUUMAN!! Sending message... ' + pipe_chars[i % len(pipe_chars)])
            sys.stdout.flush()
            time.sleep(0.01)

        serialized_data = pickle.dumps(data)
        s.sendall(serialized_data)
        print("\nSent encrypted message, key and MAC")



def receive_message():
    global rng
    rng = "True"
    BUFFER_LIMIT = 1024 * 10
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))
    server.listen(1)
    print('To User: I will be back when bear connects, sorry about that. I am once again, currently eating a salad, who knew I could get fat off of these, anyway see you when bear connects! -Tom')
    conn, addr = server.accept()
    print('\nWHEEK!! I successfully connected to', addr)
    # Receive the domain parameters for the key agreement protocol
    received_data = b''
    while not received_data.endswith(b'----END PARAMETERS----'):
        received_data += conn.recv(1024)
    print("\n GIVE ME SWEET PEPPERS!! Received domain parameters from Bear!\n")
    if len(received_data) >= BUFFER_LIMIT:
        print("\n *CHATTERS TEETH ANGERLY* why bear!: Buffer limit reached while receiving (domain parameters)\n")
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
    print("\n *laying in the corner while yawning* whoops, almost fell asleep, also I received Bear's public key!\n")
    if len(received_data) >= BUFFER_LIMIT:
        print("\n *CHATTERS TEETH ANGERLY* Buffer limit reached while receiving (public key)\n")
    serialized_other_public_key = received_data[:-20]  # Remove the delimiter

    other_public_key = serialization.load_pem_public_key(serialized_other_public_key, backend=default_backend())
    shared_secret_key = compute_shared_secret(private_key, other_public_key)
    max_msg_len = 10000000  # You can adjust this value according to your requirements

    # Receive the serialized encrypted message, the encrypted key, and the MAC
    serialized_data = b''
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        serialized_data += chunk
    print("\n I received the encrypted message, key, and MAC! WHEEK!!\n")
    # Deserialize the received data
    data = pickle.loads(serialized_data)
    encrypted_msg = data['msg']
    encrypted_key = data['encrypted_key']
    received_mac = data['mac']

    # Verify the MAC
    expected_mac = hmac.new(shared_secret_key, encrypted_msg, digestmod=hashlib.sha256).digest()
    if not hmac.compare_digest(received_mac, expected_mac):
        print("\n *CHATTERS TEETH ANGERLY* The MAC verification failed!\n")
        conn.close()
        server.close()
        return b''


    # Decrypt the key using the shared secret key
    shared_secret_key_str = shared_key_to_string(shared_secret_key, max_msg_len)
    key = decrypt(encrypted_key, shared_secret_key_str)

    # Decrypt the message using the key
    plaintext = decrypt(encrypted_msg, key)
    print("\nGIVE ME LETTUCE! decrypted message:", plaintext.decode('utf-8'), "\n")
    conn.close()
    server.close()
    rng = "False"

    return plaintext

def check_receive():
    global rng
    while True:
        if rng == "False":
            receive_thread = threading.Thread(target=receive_message, daemon=True)
            receive_thread.start()
        time.sleep(1)  # Adjust the sleep duration based on your requirements


def transceive_message():
    receive_thread = threading.Thread(target=receive_message, daemon=True)
    receive_thread.start()
    check_receive_thread = threading.Thread(target=check_receive, daemon=True)
    check_receive_thread.start()

    with patch_stdout():
        # Prompt for the IP address
        session = PromptSession(history=InMemoryHistory(), auto_suggest=AutoSuggestFromHistory())
        ip = session.prompt("Enter the IP address to send the message to (press 'q' to quit): ")
        if ip == "q":
            print_formatted_text("Please don't go!")
            print("\n5")
            time.sleep(1)
            print("\n4")
            time.sleep(1)
            print("\n3")
            time.sleep(1)
            print("\n2")
            time.sleep(1)
            print("\n1")
            print("\n[-] Self destruct initiated!")
            time.sleep(1)
            selfdestruct()
            exit(0)
        
    with patch_stdout():
        # Send and receive messages
            # loop for sending messages
        while True:
            # Get the message to send
            msg = session.prompt("\nEnter the message (press 'q' to quit, 'CHANGEIP' to change the listener IP): ")

            # Handle the different types of input
            if msg == "q":
                print_formatted_text("I want more lettuce though!")
                print_formatted_text("\n5")
                time.sleep(1)
                print_formatted_text("\n4")
                time.sleep(1)
                print_formatted_text("\n3")
                time.sleep(1)
                print_formatted_text("\n2")
                time.sleep(1)
                print_formatted_text("\n1")
                print_formatted_text("\n[-] Self destruct initiated!")
                time.sleep(1)
                selfdestruct()
                exit(0)
            elif msg == "CHANGEIP":
                ip = session.prompt("Enter the new IP address to send the message to: ")
            else:
                # Start the send thread
                send_thread = threading.Thread(target=send_message, args=(ip, msg))
                send_thread.start()





if __name__ == '__main__':
    print(help)
    print(f'Your IP address is {get_ip_address()}')
    while True:
        opt = input("do you want to receive (r), send (s), or transceive (t)? (press q to quit) ")
        if opt == "s":
            ip = input("Enter the IP address to send the message to: ")
            msg = input("Enter the message: ")
            send_message(ip, msg)
        elif opt == "r":
            receive_message()
        elif opt == "t":
            transceive_message()
        elif opt == "q":
            print("exiting...")
            print("\n5")
            time.sleep(1)
            print("\n4")
            time.sleep(1)
            print("\n3")
            time.sleep(1)
            print("\n2")
            time.sleep(1)
            print("\n1")
            print("\n[-] Self destruct initiated!")
            time.sleep(1)
            selfdestruct()
            exit(0)
        else:
            print(help)

