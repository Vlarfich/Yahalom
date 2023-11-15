import socket
import sys
import threading
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Create Socket (TCP) Connection
ServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
HOSTNAME = socket.gethostname()
HOST_IP = socket.gethostbyname(HOSTNAME)
PORT = 18082
ThreadCount = 0
MAX_CONNECTIONS = 5

UserName = []
RSAKeys = []
ServerRSA = []
ClientRSA = []
HostandPort = []

try:
    ServerSocket.bind((HOST_IP, PORT))
except socket.error as e:
    print(str(e))

print('Waiting for a Connection..')
ServerSocket.listen(MAX_CONNECTIONS)


def create_user_profile(connection):
    flagName = False
    name = ''

    serverKeys = RSA.generate(2048)

    serverKeysDER = serverKeys.exportKey('DER')
    clientKeyDER = connection.recv(2048)
    clientKey = RSA.importKey(clientKeyDER)
    connection.send(serverKeysDER)

    serverRSA = PKCS1_OAEP.new(serverKeys)
    clientRSA = PKCS1_OAEP.new(clientKey)

    while not flagName:
        connection.send('(FROM SERVER) Enter your name/nickname: '.encode())
        name = connection.recv(1024).decode()
        if name not in UserName:
            flagName = True
            UserName.append(name)
            ServerRSA.append(serverRSA)
            ClientRSA.append(clientRSA)
            HostandPort.append(connection.getpeername())
            print('Host&Port:\n', connection.getpeername())
            with open(name + 'key.txt', 'wb') as f:
                f.write(clientKeyDER)
        connection.send(str(flagName).encode())

    return name


def string_padding(string):
    return string + (20-len(string))*'0'

def string_without_padding(string):
    pos = string.find('0')
    return string[:pos]



# C option    Alice

def choose_recipient(connection):
    flagRecipient = False

    A = connection.recv(1024).decode()  # Alice
    while not flagRecipient:
        connection.send('(FROM SERVER) Enter the name you want to communicate with: '.encode())
        B = connection.recv(1024).decode()  # Bob
        flagRecipient = B in UserName
        connection.send(str(flagRecipient).encode())


    userBIndex = UserName.index(B)


    # YAH step 1:
    message = str(HostandPort[userBIndex][0])
    connection.send(message.encode())
    connection.recv(12)

    return B



def threaded_client(connection):
    first_client_name = create_user_profile(connection)
    operation = connection.recv(512).decode()
    while operation != 'q':
        if operation == 'l':
            connection.send((" ".join(UserName)).encode())
        elif operation == 'c':
            choose_recipient(connection)
        elif operation == 'w':

            # Bob

            connection.send('(FROM SERVER) Please, wait...\n'.encode())


            # YAH step 2: Trent <--{B, R_b, E_b(A, R_a)}-- Bob

            mes = connection.recv(1024)
            connection.send('ACK'.encode())
            B = string_without_padding(mes[:20].decode())
            R_b = mes[20:28]
            E_b = mes[28:]
            print('Server B', B)
            print('Server R_b', R_b)
            print('Server E_b', E_b)

            userBIndex = UserName.index(B)
            BobRSA = ClientRSA[userBIndex]
            E_bdecr = BobRSA.decrypt(E_b)
            A = string_without_padding(E_bdecr[:20].decode())
            R_a = E_bdecr[20:]
            print('Server A', A)
            print('Server R_a', R_a)


            #   YAH step 3: Trent --{R_b, E_a(B, K, R_a), E_b(A, K, R_b)}--> Alice

            PORT = 10_000
            alice_host = str(HostandPort[userBIndex][0])
            connection_to_Alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection_to_Alice.connect((alice_host, PORT))

            K = get_random_bytes(16)

            userAIndex = UserName.index(A)
            AliceRSA = ClientRSA[userAIndex]
            E_a = AliceRSA.encrypt(string_padding(B).encode() + K + R_a)
            message = R_b + E_a
            connection_to_Alice.send(message)
            if connection_to_Alice.recv(12).decode() != 'ACK':
                sys.exit()
            print('Server R_b', R_b)
            print('Server E_a', E_a)
            print('Server B', B)
            print('Server K', K)
            print('Server R_a', R_a)

            message = string_padding(A).encode() + K + R_b
            E_b = BobRSA.encrypt(message)
            connection_to_Alice.send(E_b)
            if connection_to_Alice.recv(12).decode() != 'ACK':
                sys.exit()

            print('Server E_b', E_b)
            print('Server A', A)
            print('Server K', K)
            print('Server R_b', R_b)

            print('************************** COMMON KEY K = ', K, ' **************************')


while True:
    Client, address = ServerSocket.accept()
    client_handler = threading.Thread(
        target=threaded_client,
        args=(Client,)
    )
    client_handler.start()
    ThreadCount += 1
    print('Connection Request: ' + str(ThreadCount))
    if ThreadCount == 0:
        break
ServerSocket.close()