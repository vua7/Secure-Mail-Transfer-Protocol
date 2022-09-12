from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

import json
import socket
import os, glob, datetime
import sys


def main():
    # key_generator.py to generate public/private keys for the server
    # and the trusted clients and store these keys in files with the names provided
    # generate key and file in request client folder
    # [username]_private.pem
    # [username]_public.pem
    # server public key called server_public.pem

    f = open("user_pass.json", "r")
    content = f.read()
    data = json.loads(content)

    cwd = os.getcwd()
    client_directory = cwd + "/client/"
    server_directory = cwd + "/server/"

    # generates public and private keys of the server
    s_key = key_gen()
    s_pub_key = s_key.publickey().export_key()
    s_pri_key = s_key.export_key()

    # create server public and private key in server folder
    write_file(server_directory + "server_public.pem", s_pub_key)
    write_file(server_directory + "server_private.pem", s_pri_key)
    write_file(client_directory + "server_public.pem", s_pub_key)

    for user in data:
        # making user folder
        current_user_directory = client_directory + user
        try:
            # create new directories
            os.mkdir(current_user_directory)
            os.mkdir(server_directory + user)  # make directory for each user in server folder
            os.mkdir(server_directory + user + "/inbox")
            os.chmod(current_user_directory, 0o777)
            os.chmod(server_directory + user, 0o777)
            os.chmod(server_directory + user + "/inbox", 0o777)
        except OSError as e:
            print("Error occur: ", e)
            exit(1)
        # generate client's keys
        c_key = key_gen()
        c_pub_key = c_key.publickey().export_key()
        c_pri_key = c_key.export_key()

        write_file(current_user_directory + "/" + user + "_public.pem", c_pub_key)
        write_file(current_user_directory + "/" + user + "_private.pem", c_pri_key)
        write_file(server_directory + user + "/" + user + "_public.pem", c_pub_key)


def write_file(location, key):
    file = open(location, "wb")
    file.write(key)
    file.close()
    os.chmod(location, 0o777)


def key_gen():
    return RSA.generate(2048)


main()
