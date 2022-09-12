from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import json
import socket
import os, glob, datetime
import sys

def server():
    # server port
    serverPort = 13000

    # dictionary of user_name and password
    f = open("user_pass.json", "r")
    content = f.read()
    data = json.loads(content)
    user_dict = {}
    f.close()
    for user in data:
        user_dict[user] = data[user]

    # create server socket that uses IPv4 and tcp protocols
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:', e)
        sys.exit(1)

    # Associate 13000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:', e)
        sys.exit(1)

    print('Server is ready to accept connections')

    # the server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)

    # ***number represent stages of interaction between server and client

    while 1:
        try:
            # server accept client connection
            connectionSocket, addr = serverSocket.accept()
            pid = os.fork()

            # if it is a client process
            if pid == 0:
                serverSocket.close()

                s_key_file = open(os.getcwd() + "/server_private.pem", "rb")
                s_pri_key = s_key_file.read()
                pri_key = RSA.import_key(s_pri_key)
                # create cipher
                s_pri_cipher = PKCS1_OAEP.new(pri_key)

                # 2. wait for client to send username and password
                encode_message = revcMessage(connectionSocket)
                decrypted_message = s_pri_cipher.decrypt(encode_message).decode('ascii')
                user = decrypted_message.split("+")
                validation_bool = True
                user_name = user[0]
                user_pass = user[1]
                sym_key = ""
                # 3. validating username and password, send sym_key or invalid message
                if user_name in user_dict:
                    if user_dict[user_name] == user_pass:
                        # create sym_key if username and password check out
                        sym_key = key_gen()
                        validation_bool = False
                if validation_bool:
                    message_to_send = "Invalid username or password"
                    connectionSocket.send(message_to_send.encode('ascii'))
                    print("The received client information: ", user_name, " is invalid (Connection Terminated).")
                    connectionSocket.close()
                    serverSocket.close()

                c_key_file = open(os.getcwd() + "/" + user_name + "/" + user_name + "_public.pem", "r")
                c_pub_key = c_key_file.read()
                pub_key = RSA.import_key(c_pub_key)
                c_pub_cipher = PKCS1_OAEP.new(pub_key)

                # enhance
				message = Crypto.Random.get_random_bytes(64)
                connectionSocket.send(message.encode('ascii'))
                nonce_message = revcMessage(connectionSocket)
                decrypted_message = c_pub_cipher.decrypt(nonce_message).decode('ascii')

                if decrypted_message != message:
                    print("incorrect nonce, terminating connection with " + user_name)
                    serverSocket.close()
                    sys.exit(0)
                else:
                    print("Validation accepted with " + user_name)

                connectionSocket.send(c_pub_cipher.encrypt(sym_key))
                print("Connection Accepted and Symmetric Key Generated for client: " + user_name)

                # 6. server wait for client respond with "ok"
                sym_cipher = AES.new(sym_key, AES.MODE_ECB)
                encode_message = revcMessage(connectionSocket)
                decrypted_message = decrypt(encode_message, sym_cipher)
                client_respond = decrypted_message

                if client_respond == "ok":
                    bool_condition = True
                    # 7. loop for menu
                    menu_message = "Select the operation:" \
                        "\n\t1) Create and send an email" \
                                   "\n\t2) Display the inbox list" \
                                   "\n\t3) Display the email contents" \
                                   "\n\t4) Terminate the connection" \
                                   "\n\tchoice: "
                    while bool_condition:
                        connectionSocket.send(encrypt(menu_message, sym_cipher))
                        client_respond = decrypt(revcMessage(connectionSocket), sym_cipher)

                        if client_respond == "1":
                            # sending email protocol
                            # print("1. ", client_respond)  # are these test prints (1 - 3) ?

                            # 1. encrypt and send client message
                            message = "Send the email"
                            connectionSocket.send(encrypt(message, sym_cipher))

                            # 3. receive encrypted email and decrypt
                            # get time and date first
                            now = datetime.datetime.now()
                            date_time = now.strftime("%d/%m/%Y %H:%M:%S")

                            email = decrypt(revcMessage(connectionSocket), sym_cipher)
                            # client has rejected email, continue back to menu
                            if (email == "REJECTED"):
                                continue

                            # split email into its sections
                            section = email.split("\n")
                            # could use username saved in server, but going to take it from email
                            username = section[0][6:]
                            destinations = section[1][4:]
                            title = section[2][7:]
                            length = section[3][16:]
                            content = section[5]

                            # check if fields follow message specifications (server side)
                            if (len(title) > 100) or (len(content) > 1000000):
                                # reject message and continue back to menu
                                continue

                            # print message to server
                            print("An email from " + username + " is sent to " + destinations +
                                  " has a content length of " + str(length) + ".")

                            # reconstruct email with new section containing date and time
                            email = ("From: " + username + "\nTo: " + destinations + "\nDate and Time: " +
                                     date_time + "\nTitle: " + title + "\nContent Length: " + str(length) +
                                    "\nContent: \n" + content)

                            # store email into destination client's directory
                            # get all destination clients
                            destination = destinations.split(";")
                            cwd = os.getcwd()
                            for i in range(len(destination)):
                                client_dir = (cwd + "/" + destination[i] + "/")
                                filename = (username + "_" + title + ".txt")
                                location = client_dir + filename
                                f = open(location, "w")
                                f.write(email)
                                f.close()

                        elif client_respond == "2":
                            # viewing inbox protocol
                            # print("2. ", client_respond)
                            # 1. send encrypted message with list of emails in inbox to client
                            message = ("Index\t\tFrom\t\tDateTime\t\tTitle\n")
                            index = 1
                            cwd = os.getcwd()
                            path = (cwd + "/" + user_name)
                            # open every .txt file in client's "mailbox"
                            for filename in glob.glob(os.path.join(path, "*.txt")):
                                with open(os.path.join(os.getcwd(), filename), "r") as f:
                                    contents = f.read()
                                    section = contents.split("\n")
                                    username = section[0][6:]
                                    date_time = section[2][15:]
                                    title = section[3][7:]
                                    message += (str(index) + "\t\t" + username + "\t\t" + date_time +
                                               "\t" + title + "\n")
                                index += 1

                            # encrypt and send mailbox list to client
                            connectionSocket.send(encrypt(message, sym_cipher))

                            # receive "OK" message from client
                            response = decrypt(revcMessage(connectionSocket), sym_cipher)

                        elif client_respond == "3":
                            # viewing email protocol
                            #print("3. ", client_respond)

                            # Open client email folder
                            path = (cwd + "/" + user_name)
                            entries = os.listdir(path)
                            email_count = len(entries) - 1

                            # prompt user for email 
                            message = "Enter the email index you wish to view: "
                            connectionSocket.send(encrypt(message, sym_cipher))

                            # Get index from user
                            choice = decrypt(revcMessage(connectionSocket), sym_cipher)
                            choice = int(choice)

                            # continue if valid index
                            if email_count >= 1 and choice >= 1 and choice <= email_count:
                                email_file = entries[int(choice)]
                                # open email file
                                try:
                                    email = open(cwd + "/" + user_name + '/' + str(email_file))

                                    # read email file contents
                                    contents = email.read()

                                    # send email to client
                                    connectionSocket.send(encrypt(contents, sym_cipher))

                                except: 
                                    print("Error - Cannot open email_file", email_file)

                            # invalid index
                            else:                            
                                email = "Invalid Email Index"
                                connectionSocket.send(encrypt(email, sym_cipher))

                            # receive "OK" message from client
                            response = decrypt(revcMessage(connectionSocket), sym_cipher)

                        elif client_respond == "4":
                            # terminating protocol
                            print("Terminate connection with", user_name)
                            connectionSocket.close()
                            return

                connectionSocket.close()

        except socket.error as e:
            print('An error occurred:', e)
            serverSocket.close()
            sys.exit(1)
        except:
            serverSocket.close()
            sys.exit(0)

    serverSocket.close()
    sys.exit(0)


def key_gen():
    return get_random_bytes(32)


def revcMessage(connectionSocket):
    encode_message = 0
    while 1:
        if encode_message != 0:
            break
        encode_message = connectionSocket.recv(2048)
    return encode_message

def encrypt(message, cipher):
    ct_bits = cipher.encrypt(pad(message.encode('ascii'), 16))
    return ct_bits


def decrypt(message, cipher):
    padded_message = cipher.decrypt(message)
    ec_message = unpad(padded_message, 16)
    return ec_message.decode('ascii')


server()
