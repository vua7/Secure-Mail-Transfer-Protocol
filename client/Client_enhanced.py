from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import json
import socket
import os, glob, datetime
import sys


def client():
    # serverName = input('Enter the server host name or IP:')
    serverPort = 13000

    # serverName = "cc5-212-05.macewan.ca"
    serverName = "localhost"

    # getting server public key from file
    s_pub_key = open(os.getcwd()+"/server_public.pem", "rb").read()
    public_key = RSA.import_key(s_pub_key)
    # create cipher
    s_pub_cipher = PKCS1_OAEP.new(public_key)

    # create client socket
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:', e)
        sys.exit(1)

    try:
        # condition for loop

        #  client connect with the server
        clientSocket.connect((serverName, serverPort))

        # 1. after connect client program ask user for id and pass word
        # client then send id and pass to server for validation
        user_name = input("Enter your username:")
        user_pass = input("Enter your password:")
        message = user_name + "+" + user_pass
        clientSocket.send(s_pub_cipher.encrypt(message.encode('ascii')))

        # else decrypt message with public key to get sym_key
        c_pri_key = open(os.getcwd() + "/" + user_name + "/" + user_name + "_private.pem", "r").read()
        pri_key = RSA.import_key(c_pri_key)
        c_pri_cipher = PKCS1_OAEP.new(pri_key)

        # enhance
        respond_from_server = revcMessage(clientSocket).decode('ascii')
        clientSocket.send(c_pri_cipher.encrypt(respond_from_server.encode('ascii')))

        # 4. respond from server: key or invalid
        respond_from_server = revcMessage(clientSocket)
        # if server respond with invalidation exit program
        if respond_from_server == "Invalid username or password".encode('ascii'):
            print("Invalid username or password.\nTerminating.")
            clientSocket.close()
            sys.exit(0)
        sym_key = c_pri_cipher.decrypt(respond_from_server)
        # creating new cipher with sym_key
        sym_cipher = AES.new(sym_key, AES.MODE_ECB)

        # 5. send ok to server        
        clientSocket.send(encrypt("ok", sym_cipher))

        # 7. menu loop
        condition_loop = True
        while condition_loop:
            respond_from_server = decrypt(revcMessage(clientSocket), sym_cipher)
            user_choice = input(respond_from_server)
            clientSocket.send(encrypt(user_choice, sym_cipher))
            
            if user_choice == "1":
                # 2. receive and decrypt message
                response = decrypt(revcMessage(clientSocket), sym_cipher)
                
                # prompt user for email elements
                destinations = input("Enter destinations (separated by ;): ")
                title = input("Enter title: ")
                title_length = len(title)
                while True:
                    source = input("Would you like to load contents from a file? (Y/N) ").lower()
                    if (source == "y"):
                        filename = input("Enter filename: ")
                        cwd = os.getcwd()
                        path = (cwd + "/" + user_name + "/" + filename)
                        f = open(path, "r")
                        contents = f.read()
                        f.close()
                        break
                    elif (source == "n"):
                        contents = input("Enter message contents: ")
                        break
                contents_length = len(contents)
                
                # construct email
                email = ("From: " + user_name + "\nTo: " + destinations + "\nTitle: " + title + 
                        "\nContent Length: " + str(contents_length) + "\nContent: \n" + contents)
                
                # check if fields follow message specifications (client side)
                if (title_length > 100) or (contents_length > 1000000):
                    # reject message
                    clientSocket.send(encrypt("REJECTED", sym_cipher))
                    # go back to menu
                    continue

                # encrypt and send email to server
                clientSocket.send(encrypt(email, sym_cipher))
                print("The message is sent to the server.")

            elif user_choice == "2":    
                # 2. receive list of emails in inbox from server
                message = decrypt(revcMessage(clientSocket), sym_cipher)
                print(message)

                # send server "OK" message
                response = "OK"
                clientSocket.send(encrypt(response, sym_cipher))

            elif user_choice == "3":

                # get prompt
                message = decrypt(revcMessage(clientSocket), sym_cipher)
                 
                # get email index from user
                index = input(message)
                 
                # check user input
                while(index.isdigit() == False):
                    index = input(message)
                print()

                # send index to server
                clientSocket.send(encrypt(index, sym_cipher))

                # recieve email and display its contents
                email = decrypt(revcMessage(clientSocket), sym_cipher)
                print(email)                
                print()
 
                # send server "OK" message
                response = "OK"
                clientSocket.send(encrypt(response, sym_cipher))


            elif user_choice == "4":
                clientSocket.send(encrypt(user_choice, sym_cipher))
                clientSocket.close()
                print("The connection is terminated with the server.")
                sys.exit(0)
    
    except socket.error as e:
        print('An error occurred:', e)
        clientSocket.close()
        sys.exit(1)


def encrypt(message, cipher):
    ct_bits = cipher.encrypt(pad(message.encode('ascii'), 16))
    return ct_bits


def decrypt(message, cipher):
    padded_message = cipher.decrypt(message)
    ec_message = unpad(padded_message, 16)
    return ec_message.decode('ascii')


def revcMessage(clientSocket):
    encode_message = 0
    # loop to make sure that client receive message from server
    while 1:
        if encode_message != 0:
            break
        encode_message = clientSocket.recv(2048)
    return encode_message


client()
