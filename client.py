import socket
import sys
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from ecdsa import VerifyingKey, SigningKey, NIST256p, BadSignatureError
from ecdsa.util import sigencode_der, sigdecode_der

SERVER_RSA = None
PORT_FOR_BOB = 15_000


def create_my_name(sc):
    flagName = False
    name = ''
    global SERVER_RSA
    userKeys = RSA.generate(1024)

    privateECDSA = SigningKey.generate(curve=NIST256p)
    publicECDSA = privateECDSA.verifying_key
    print('Public ECDSA', publicECDSA)

    userKeysDER = userKeys.exportKey('DER')
    sc.send(userKeysDER)
    key = sc.recv(2048)
    serverPublicKey = RSA.importKey(key)
    userRSA = PKCS1_OAEP.new(userKeys)
    SERVER_RSA = PKCS1_OAEP.new(serverPublicKey)

    while not flagName:
        name = input(sc.recv(1024).decode())
        sc.send(name.encode())
        flagName = (sc.recv(1024).decode() == 'True')
    return name, userRSA, privateECDSA, publicECDSA


def print_operations():
    print("Options:")
    print("\t Enter 'q' to exit")
    print("\t Enter 'connect' or 'c' to be Alice")
    print("\t Enter 'wait connection' or 'w' to be Bob")


def print_user_list(client):
    UserName = client.recv(1024).decode('utf-8')
    print('Connected users:\n', UserName)


def string_padding(string):
    return string + (20 - len(string)) * '0'


# Alice  C option

def initiate_connection(client, UserName, publicECDSA):
    flagRecipient = False
    recipient_name = ''

    client.send(UserName.encode())
    while not flagRecipient:
        recipient_name = input(client.recv(1024).decode())
        client.send(recipient_name.encode())
        flagRecipient = (client.recv(1024).decode() == 'True')

    # step 1: A, B -->
    client.send((UserName + '/' + recipient_name).encode())

    # YAH  step 1 :  Alice  --{A, R_a}-->  Bob
    A = UserName
    R_a = get_random_bytes(8)
    print('Alice A', A)
    print('Alice R_a', R_a)

    bob_host = client.recv(1024).decode()
    client.send('ACK'.encode())
    connection_to_Bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection_to_Bob.connect((bob_host, PORT_FOR_BOB))

    mes = string_padding(A).encode() + R_a
    print('message Alice ', mes)
    connection_to_Bob.send(mes)
    if connection_to_Bob.recv(12).decode() != 'ACK':
        sys.exit()

    # YAH step 3: Alice <--{R_b, E_a(B,K,R_a), E_b(A,K,R_b)}-- Trent

    clientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    HOSTNAME = socket.gethostname()
    HOST_IP = socket.gethostbyname(HOSTNAME)
    PORT = 10_000
    try:
        clientSocket.bind((HOST_IP, PORT))
    except socket.error as e:
        print(str(e))
    clientSocket.listen(1)
    Server_to_Alice, address = clientSocket.accept()

    mes = Server_to_Alice.recv(1024)
    Server_to_Alice.send('ACK'.encode())
    R_b = mes[:8]
    E_a = mes[8:]
    print('Alice R_b', R_b)
    print('Alice E_a', E_a)
    E_a_decr = userRSA.decrypt(E_a)
    B = string_without_padding(E_a_decr[:20].decode())
    K = E_a_decr[20:36]
    R_a_check = E_a_decr[36:]
    if R_a_check != R_a:
        print('ERROR!!! Message spoofing!')
        sys.exit()
    print('Alice B', B)
    print('Alice K', K)
    print('Alice R_a', R_a)

    E_b = Server_to_Alice.recv(1024)
    Server_to_Alice.send('ACK'.encode())

    print('Alice E_b', E_b)

    # YAH step 4: Alice --{E_b(A, K, R_b), E_k(R_b)}--> Bob

    connection_to_Bob.send(E_b)
    if connection_to_Bob.recv(12).decode() != 'ACK':
        sys.exit()

    AEScipher = AES.new(K, AES.MODE_GCM)
    nonce_to_Bob = AEScipher.nonce
    ciphertext, tag_to_bob = AEScipher.encrypt_and_digest(R_b)
    message = nonce_to_Bob + tag_to_bob + ciphertext
    connection_to_Bob.send(message)
    if connection_to_Bob.recv(12).decode() != 'ACK':
        sys.exit()

    print('************************** COMMON KEY K = ', K, ' **************************')

    connection_to_Bob.send(publicECDSA.to_der())
    mes = connection_to_Bob.recv(1024)
    BobECDSA = VerifyingKey.from_der(mes)
    print('Bob ECDSA pub', BobECDSA)


    K_COMMON = K

    return K_COMMON, connection_to_Bob, BobECDSA


def string_without_padding(string):
    pos = string.find('0')
    return string[:pos]


#  Bob    W option

def connect_to_user(server_connect, userRSA, myUserName, publicECDSA):  # bob side
    clientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    HOSTNAME = socket.gethostname()
    HOST_IP = socket.gethostbyname(HOSTNAME)
    # PORT = 10_000
    try:
        clientSocket.bind((HOST_IP, PORT_FOR_BOB))
    except socket.error as e:
        print(str(e))
    clientSocket.listen(1)
    Client_to_Alice, address = clientSocket.accept()

    # YAH step 1: Bob <--{A, R_a}-- Alice
    mes = Client_to_Alice.recv(1024)
    Client_to_Alice.send('ACK'.encode())
    print('Bob message ', mes)
    A = string_without_padding(mes[:20].decode())
    R_a = mes[20:]
    print('Bob A', A)
    print('Bob R_a', R_a)

    # YAH step 2: Bob --{B, R_b, E_b(A, R_a)}--> Trent
    B = myUserName
    R_b = get_random_bytes(8)

    BobRSA = userRSA

    E_b = BobRSA.encrypt(mes)
    print('Bob B', B)
    print('Bob R_b', R_b)
    print('Bob E_b', E_b)
    message = string_padding(B).encode() + R_b + E_b
    server_connect.send(message)
    if server_connect.recv(12).decode() != 'ACK':
        sys.exit()

    E_b_Alice = Client_to_Alice.recv(1024)
    E_b_Alice_decr = userRSA.decrypt(E_b_Alice)
    A_check = string_without_padding(E_b_Alice_decr[:20].decode())
    R_b_check = E_b_Alice_decr[36:]
    if A_check != A or R_b_check != R_b:
        print('ERROR!!! Message spoofing on Alice side!')
        sys.exit()
    Client_to_Alice.send('ACK'.encode())
    K = E_b_Alice_decr[20:36]

    print('Bob A', A)
    print('Bob K', K)
    print('Bob R_b', R_b)

    E_k = Client_to_Alice.recv(1024)

    nonce = E_k[:16]
    AEScipher = AES.new(K, AES.MODE_GCM, nonce=nonce)
    tag = E_k[16:32]
    cipher = E_k[32:]
    R_b_check = AEScipher.decrypt(cipher)
    if R_b_check != R_b:
        print('ERROR!!! Message spoofing on Alice side!')
        sys.exit()
    Client_to_Alice.send('ACK'.encode())

    print('************************** COMMON KEY K = ', K, ' **************************')

    mes = Client_to_Alice.recv(1024)
    Client_to_Alice.send(publicECDSA.to_der())
    AliceECDSA = VerifyingKey.from_der(mes)
    print('Alice ECDSA pub', AliceECDSA)


    K_COMMON = K

    return K_COMMON, Client_to_Alice, AliceECDSA


def messenger_for_alice(K_sym, Bob_socket, userName, privateECDSA, publicBobECDSA):
    flagExit = False
    while not flagExit:
        message = input('ENTER YOUR MESSAGE: ')
        if message == 'quit':
            flagExit = True

        message = userName + ': ' + message
        print('WAITING FOR THEIR RESPONSE....')
        AEScipher = AES.new(K_sym, AES.MODE_GCM)
        nonce_alice = AEScipher.nonce
        cipher, tag_alice = AEScipher.encrypt_and_digest(bytes(message, 'ascii'))
        message_enc = nonce_alice + tag_alice + cipher
        Bob_socket.send(message_enc)
        if Bob_socket.recv(12).decode() != 'ACK':
            sys.exit()

        sig = privateECDSA.sign_deterministic(
            message_enc,
            hashfunc=sha256,
            sigencode=sigencode_der
        )
        print('Alice signed ECDSA', sig)
        Bob_socket.send(sig)


        # __________________________
        if not flagExit:
            ciphertext_from_Bob = Bob_socket.recv(2048)

            Bob_socket.send('ACK'.encode())

            signature = Bob_socket.recv(1024)
            print('Bob ECDSA signature', signature)

            try:
                ret = publicBobECDSA.verify(signature, ciphertext_from_Bob, sha256, sigdecode=sigdecode_der)
                assert ret
                print("Valid signature")
            except BadSignatureError:
                print("Incorrect signature")
                sys.exit()



            nonce_bob = ciphertext_from_Bob[:16]
            tag_bob = ciphertext_from_Bob[16:32]
            cipher_mb = ciphertext_from_Bob[32:]
            AEScipher = AES.new(K_sym, AES.MODE_GCM, nonce=nonce_bob)
            message_from_bob = AEScipher.decrypt(cipher_mb).decode()
            try:
                AEScipher.verify(tag_bob)
            except ValueError:
                print("Key incorrect or message corrupted (Bob side)")

            print(message_from_bob)
            if message_from_bob.find('quit') != -1:
                flagExit = True


def messenger_for_bob(K_sym, Alice_socket, userName, privateECDSA, publicAliceECDSA):
    flagExit = False
    print('Waiting for ', userName, ' to start conversation....')
    while not flagExit:
        cipher_text_from_Alice = Alice_socket.recv(2048)

        Alice_socket.send('ACK'.encode())

        signature = Alice_socket.recv(1024)
        print('Alice ECDSA signature', signature)

        print('Alice pub ECDSA', publicAliceECDSA)
        try:
            ret = publicAliceECDSA.verify(signature, cipher_text_from_Alice, sha256, sigdecode=sigdecode_der)
            assert ret
            print("Valid signature")
        except BadSignatureError:
            print("Incorrect signature")
            sys.exit()


        nonce_alice = cipher_text_from_Alice[:16]
        tag_alice = cipher_text_from_Alice[16:32]
        cipher_ma = cipher_text_from_Alice[32:]
        AEScipher = AES.new(K_sym, AES.MODE_GCM, nonce=nonce_alice)
        message_from_alice = AEScipher.decrypt(cipher_ma).decode()
        try:
            AEScipher.verify(tag_alice)
        except ValueError:
            print("Key incorrect or message corrupted (alice side)")
        if message_from_alice.find('quit') != -1:
            break
        print(message_from_alice)



        # _________________________
        message = input('ENTER YOUR MESSAGE: ')
        if message == 'quit':
            flagExit = True
        message = userName + ': ' + message
        print('WAITING FOR THEIR RESPONSE....')
        AEScipher = AES.new(K_sym, AES.MODE_GCM)
        nonce_bob = AEScipher.nonce
        cipher, tag_bob = AEScipher.encrypt_and_digest(bytes(message, 'ascii'))
        cipher_text_from_Bob = nonce_bob + tag_bob + cipher
        Alice_socket.send(cipher_text_from_Bob)

        if Alice_socket.recv(12).decode() != 'ACK':
            sys.exit()

        sig = privateECDSA.sign_deterministic(
            cipher_text_from_Bob,
            hashfunc=sha256,
            sigencode=sigencode_der
        )
        print('Bob signed ECDSA', sig)
        Alice_socket.send(sig)




if __name__ == '__main__':
    SERVER_NAME = 'VladosPC'
    SERVER_IP = socket.gethostbyname(SERVER_NAME)
    PORT = 18082

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client.connect((SERVER_IP, PORT))

    client_name, userRSA, privateECDSA, publicECDSA = create_my_name(client)
    print('Welcome, ', client_name, '\n')
    #########

    operation = ''
    while 1:
        print_operations()
        operation = input()
        if operation.lower() == 'quit' or operation.lower() == 'q':
            break
        elif operation.lower() == 'list' or operation.lower() == 'l':
            client.send(operation.lower()[0].encode())
            print_user_list(client)
        ###
        elif operation.lower() == 'connect' or operation.lower() == 'c':
            client.send(operation.lower()[0].encode())
            K_sym, connect_to_bob, BobECDSA = initiate_connection(client, client_name, publicECDSA)
            messenger_for_alice(K_sym, connect_to_bob, client_name, privateECDSA, BobECDSA)
            operation = 'quit'
            break
        ###
        elif operation.lower() == 'wait connection' or operation.lower() == 'w':
            client.send(operation.lower()[0].encode())
            print(client.recv(1024).decode())
            K_sym, connect_to_alice, AliceECDSA = connect_to_user(client, userRSA, client_name, publicECDSA)
            messenger_for_bob(K_sym, connect_to_alice, client_name, privateECDSA, AliceECDSA)
            operation = 'quit'
            break

        ###
        else:
            print('ERROR! NO SUCH OPERATION! TRY ONE MORE TIME...\n')

    client.send(operation.lower()[0].encode())
    client.close()
