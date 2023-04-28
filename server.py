# ====================================================================------ IMPORTS ------===============================================================================
import socket
import threading
import select
from typing import Any

import socketserver
import os
import re
import sys

#? ====================================================================------ MAIN ------===============================================================================
def main():
    # !constants
    #? Server constants ----------------------------------------------------- 
    PORT = 3999
    HOST = socket.gethostbyname(socket.gethostname())
    ADDRESS = (HOST, PORT)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDRESS)
    server.listen(20)    #* listen only to max 20 clients

    FORMAT = "utf-8"
    SUFFIX = b'\x07\x08'

    # timeouts (s)
    TIMEOUT = 1.0
    RECHARGING_TIMEOUT = 5.0
    #? Server constants ----------------------------------------------------- 

    #* Key ID pairs; FORMAT =  KEY_ID : (SERVER_KEY, CLIENT_KEY)
    SERVER_CLIENT_KEYS = {
        0: (23019, 32037),
        1: (32037, 29295),
        2: (18789, 13603),
        3: (16443, 29533),
        4: (18189, 21952)
    }
    # Map for server messages and associated commands
    SERVER_MESSAGES = {
        # SERVER_COFIRMATION                IMPLEMENT ELSEWHERE IN THE CODE
        "SERVER_KEY_REQUEST":               b"107 KEY REQUEST" + SUFFIX,
        "SERVER_OK":                        b"200 OK" + SUFFIX,
        "SERVER_MOVE":                      b"102 MOVE" + SUFFIX,
        "SERVER_TURN_LEFT":                 b"103 TURN LEFT" + SUFFIX,
        "SERVER_TURN_RIGHT	":              b"104 TURN RIGHT" + SUFFIX,
        "SERVER_PICK_UP":                   b"105 GET MESSAGE" + SUFFIX,
        "SERVER_LOGOUT":                    b"106 LOGOUT" + SUFFIX,
        "SERVER_LOGIN_FAILED":              b"300 LOGIN FAILED" + SUFFIX,
        "SERVER_SYNTAX_ERROR":              b"301 SYNTAX ERROR" + SUFFIX,
        "SERVER_LOGIC_ERROR":               b"302 LOGIC ERROR" + SUFFIX,
        "SERVER_KEY_OUT_OF_RANGE_ERROR":    b"303 KEY OUT OF RANGE" + SUFFIX
    }
    CLIENT_MESSAGES_MAX_LEN = {
    "CLIENT_USERNAME":      20,
    "CLIENT_KEY_ID":        5,
    "CLIENT_CONFIRMATION":  7,
    "CLIENT_OK":            12,
    "CLIENT_RECHARGING":    12,
    "CLIENT_FULL_POWER":    12,
    "CLIENT_MESSAGE":       100
    }

    #|=================================================================================================================================================================

    #! Custom exceptions
    class SERVER_SYNTAX_ERROR(Exception):
        def __init__(self, message):
            self.message = message

    class SERVER_KEY_OUT_OF_RANGE_ERROR(Exception):
        def __init__(self, message):
            self.message = message

    class SERVER_LOGIN_FAILED(Exception):
        def __init__(self, message):
            self.message = message

    #? cann happen only while clients robot is recharging  
    class LOGIC_ERROR(Exception):
        def __init__(self, message):
            self.message = message

    #|================================================================================================================================================================
    
    #! Classes and structures
    # todo ROBOT
    class client_robot:
        def __init__(self):
            self.username: str = ""
            self.keyID: int = -1
            self.recharging: bool = False
            self.position: tuple[int, int] = (0, 0)   # (x, y) coordinates

    #|=================================================================================================================================================================
    
    #! Functions

        #==========================================---- ↓ GENERAL FUNCTIONS ↓ ----=============================================================


    # TODO - OPTIMIZE                     <<<=======================
    def get_message(conn):
        msg = conn.recv(1024)   
        return msg
    
        #========================================---- ↓ AUTHENTICATION FUNCTIONS ↓ ----=========================================================
    def check_suffix(message: bytes):
        if message[-2:] != SUFFIX:
            sfx = message[-2:]
            print(f"Wrong message suffix! Your message suffix was: {sfx}")              #~ debug print
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])

    def check_message_length(message: bytes, message_type: str):
        max_len = CLIENT_MESSAGES_MAX_LEN[message_type]
        if len(message) > max_len:
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
        
    def validate_client_message(message: bytes, message_type: str):
        check_message_length(message, message_type)
        print(f"[Client message lenght is OK]")                                         #~ debug print
        check_suffix(message)
        print(f"[Client message suffix is OK]")                                         #~ debug print

    def check_client_confirmation_key(message: bytes, client_key: int, hash_value: int):
        validate_client_message(message, "CLIENT_CONFIRMATION")
        client_confirmation_key = message[:-2].decode(FORMAT)
        if not client_confirmation_key.isnumeric():
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
        
        correct_client_key_value = (hash_value + client_key) % 65536

        if int(client_confirmation_key) != correct_client_key_value:
            raise SERVER_LOGIN_FAILED(SERVER_MESSAGES["SERVER_LOGIN_FAILED"])
        
        return True


    def calculate_confirmation_key(username: bytes, server_key: int):
        # both of the messages suffix was already checked
        username = username[:-2].decode(FORMAT)
        print(f"[CLIENTS USERNAME]: {username}")                #~ debug print

        ascii_sum = 0
        for char in username:
            ascii_sum += ord(char)

        hash_value = (ascii_sum * 1000) % 65536
        print(f"[hash_value]: {hash_value}")                    #~ debug print

        calculated_key = (hash_value + server_key) % 65536 

        print(f"calculated_key = {calculated_key}")             #~ debug print
        return calculated_key, hash_value                       

    #* check if the key is ok
    def check_key_ID(message: bytes):
        validate_client_message(message, "CLIENT_KEY_ID")                   #! ?? WHAT IF I RAISE MORE THAN ONE ERROR ?? WILL THE CODE AUTOMATICALLY END ??
        key_ID = message[:-2].decode(FORMAT)
        if not key_ID.isnumeric():
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
        key_ID = int(key_ID)
        if key_ID < 0 or key_ID > 4:
            raise SERVER_KEY_OUT_OF_RANGE_ERROR(SERVER_MESSAGES["SERVER_KEY_OUT_OF_RANGE_ERROR"])    

    def authenticate_client(conn, client_username: bytes):
        print(f"Starting username validation...")                        #~ debug print
        validate_client_message(client_username, "CLIENT_USERNAME")

        # if the clients username is valid, send him a key request
        conn.send(SERVER_MESSAGES["SERVER_KEY_REQUEST"])

        client_KEY_ID = get_message(conn)

        check_key_ID(client_KEY_ID)

        server_key, client_key = SERVER_CLIENT_KEYS[int(client_KEY_ID[:-2].decode(FORMAT))]
        server_confirmation_key, hash_value = calculate_confirmation_key(client_username, server_key)        

        #? send SERVER_CONFIRMATION (= server_confirmation_key ) to the client
        conn.send( str(server_confirmation_key).encode(FORMAT) + SUFFIX)

        client_confirmation_key = get_message(conn)                                                         

        try:
            check_client_confirmation_key(client_confirmation_key, client_key, hash_value)
            #? if the client_confirmation_key is correct, send SERVER_OK to the client
            conn.send(SERVER_MESSAGES["SERVER_OK"])
        except SERVER_LOGIN_FAILED:
            conn.send(SERVER_MESSAGES["SERVER_LOGIN_FAILED"])
            return False
        except SERVER_SYNTAX_ERROR:
            conn.send(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
            return False

        return True     #? return true if the whole authentication runs correctly
    
        #========================================---- ↓ ROBOT NAVIGATION FUNCTIONS ↓ ----=====================================================
    
    def robot_navigation():                                                                         #! CONTINUE HERE <================
        pass

    #|=================================================================================================================================================================
    
    #! Start of the actual code

    def close_client(conn):
        conn.close()

    # handle individual clients separately
    # running for each client individually
    def handle_client(conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")        #~ debug print

        connected = True
        authenticated = False
        while connected:                            # while client is connected receive messages from him
            msg = get_message(conn)                 # wait for the client until he sends a message through the socket (load it into a buffer which is 1024 bytes big)
            msg_len = len(msg.decode(FORMAT))
            if msg_len:                          # check if we actually got a valid message
                if msg[:-2].decode(FORMAT) == "!bye":            #~ DELETE
                    connected = False                       #~ DELETE

                if not authenticated:
                    try:
                        authenticated = authenticate_client(conn, msg)
                    except SERVER_KEY_OUT_OF_RANGE_ERROR as err:    #? clients key ID is out of range
                        print(err)
                        conn.send(SERVER_MESSAGES["SERVER_KEY_OUT_OF_RANGE_ERROR"])
                        close_client(conn)
                    except SERVER_SYNTAX_ERROR as err:              #? clients key ID or confirmation key is not a num
                        print(err)
                        conn.send(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
                        close_client(conn)
                    else:
                        if not authenticated:
                            close_client(conn)
                    finally:
                        pass
                

                # TODO - WRITE THE CODE FOR CLIENTS ROBOT NAVIGATION (+ HELPER FUNTINOS)


                print(f"[{addr}] sent: {msg}")                  #~ debug print

        print(f"{addr} diconnected.")                           #~ debug print
        
        # when client writes "!bye" close the connection with the client
        close_client(conn) 
    
    #? handle new connections and distribute them between clients 
    def start():
        server.listen()
        print(f"[LISTENING] Server is listening on {HOST}")
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target = handle_client, args=(conn, addr))   #? create an individual thread for each client
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")    # ~debug print


    #! ########################---- START THE SERVER ----################################
    print(f"[STARTING] server is starting...")                              # ~debug print
    start()
    
#|=================================================================================================================================================================

if __name__ == '__main__':
    main()