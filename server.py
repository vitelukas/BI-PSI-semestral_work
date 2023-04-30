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
        "SERVER_TURN_RIGHT":                b"104 TURN RIGHT" + SUFFIX,
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
    CLIENT_RECHARGING_MESSAGES = {
        "CLIENT_RECHARGING": b"RECHARGING" + SUFFIX,
        "CLIENT_FULL_POWER": b"FULL POWER" + SUFFIX
    }
    DIRECTIONS_TURN_RIGHT = {
        "LEFT":     "UP",
        "RIGHT":    "DOWN",
        "UP":       "RIGHT",
        "DOWN":     "LEFT",
        "NONE":     "NONE"
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
        def __init__(self, conn):
            self.conn = conn
            self.connected: bool = True
            self.authenticated: bool = False
            self.username: str = ""
            self.buffer: bytes = b''
            self.recharging: bool = False
            self.direction: str = "NONE"
            self.position: tuple[int, int] = (0, 0)         # (x, y) coordinates
            self.old_position: tuple[int, int] = (0, 0)     # (x, y) coordinates

    #|=================================================================================================================================================================
    
    #! Functions
        #*==========================================---- ↓ GENERAL FUNCTIONS ↓ ----=============================================================

    # TODO - OPTIMIZE - add timeout                     <<<=======================
    def get_message(robot: client_robot):
        # We are receiving data from the client until we receive a message
        while True:
            # If there is at least one message in the buffer we return it
            if SUFFIX in robot.buffer:
                index = robot.buffer.index(SUFFIX) + 2  # Index of the end of the message
                msg = robot.buffer[:index]
                robot.buffer = robot.buffer[index:]
                if msg != CLIENT_RECHARGING_MESSAGES["CLIENT_RECHARGING"]:      
                    return msg
                else:
                    robot.recharging = True                                     #TODO implement robot recharging situation
                    robot_recharging(robot)
                
            # If there is no message in the buffer, we wait for a message
            #TODO - implement timeout
            try:
                robot.conn.settimeout(TIMEOUT)
                data = robot.conn.recv(1024)
                robot.conn.settimeout(None)
            except socket.timeout:
                close_client(robot.conn)
                print(f"[CONNECTION TIMEOUT] closing connection...")                    #~ debug print

            if not data:                                                                #~ ? DELETE ?
                # If there is no data in the buffer, we return None because the connection has been closed
                print(f"[Connection closed]...")                                        #~ debug print
                close_client(robot.conn)
                return None
            robot.buffer += data


        #*==========================================---- ↓ ROBOT  RECHARGING ↓ ----=============================================================

    # TODO - IMPLEMENT RECHARGING
    def robot_recharging(robot: client_robot):
        pass


        #*========================================---- ↓ AUTHENTICATION FUNCTIONS ↓ ----=========================================================
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
        # print(f"[Client message lenght is OK]")                                         #~ debug print
        check_suffix(message)
        # print(f"[Client message suffix is OK]")                                         #~ debug print


    def check_client_confirmation_key(message: bytes, client_key: int, hash_value: int):
        validate_client_message(message, "CLIENT_CONFIRMATION")
        client_confirmation_key = message[:-2].decode(FORMAT)
        if not client_confirmation_key.isnumeric():
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
        
        correct_client_key_value = (hash_value + client_key) % 65536

        if int(client_confirmation_key) != correct_client_key_value:
            raise SERVER_LOGIN_FAILED(SERVER_MESSAGES["SERVER_LOGIN_FAILED"])
        
        return True


    def calculate_confirmation_key(username: str, server_key: int):
        # both of the messages suffix was already checked
        print(f"[CLIENTS USERNAME]: {username}")                #~ debug print

        ascii_sum = 0
        for char in username:
            ascii_sum += ord(char)

        hash_value = (ascii_sum * 1000) % 65536
        print(f"[hash_value]: {hash_value}")                    #~ debug print

        calculated_key = (hash_value + server_key) % 65536 

        print(f"calculated_key = {calculated_key}")                         #~ debug print
        return calculated_key, hash_value                       


    #? check if the key is ok
    def check_key_ID(message: bytes):
        validate_client_message(message, "CLIENT_KEY_ID")                   #! ?? WHAT IF I RAISE MORE THAN ONE ERROR ?? WILL THE CODE AUTOMATICALLY END ??
        key_ID = message[:-2].decode(FORMAT)
        if not key_ID.isnumeric():
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
        key_ID = int(key_ID)
        if key_ID < 0 or key_ID > 4:
            raise SERVER_KEY_OUT_OF_RANGE_ERROR(SERVER_MESSAGES["SERVER_KEY_OUT_OF_RANGE_ERROR"])    

        # ###################################---- MAIN AUTHENTICATION FUNCTION ----###################################
    def authenticate_client(robot: client_robot, client_username: bytes):
        print(f"Starting username validation...")                           #~ debug print
        validate_client_message(client_username, "CLIENT_USERNAME")
        robot.username = client_username[:-2].decode(FORMAT)                #? if the client_username is valid, set it to the robot's username
        robot.username = robot.username.strip()

        # if the clients username is valid, send him a key request
        robot.conn.send(SERVER_MESSAGES["SERVER_KEY_REQUEST"])

        client_KEY_ID = get_message(robot)                                  #! ??? WHAT IF THERE IS A DIFFERENT MESSAGE IN THE BUFFER THAN client_KEY_ID ???                                               

        check_key_ID(client_KEY_ID)

        server_key, client_key = SERVER_CLIENT_KEYS[int(client_KEY_ID[:-2].decode(FORMAT))]
        server_confirmation_key, hash_value = calculate_confirmation_key(robot.username, server_key)        

        #? send SERVER_CONFIRMATION (= server_confirmation_key ) to the client
        robot.conn.send( str(server_confirmation_key).encode(FORMAT) + SUFFIX)

        client_confirmation_key = get_message(robot)                        #! WHAT IF THERE ARE ALREADY MORE MESSAGES IN THE BUFFER                                                 
                                                                            #! AND I GET A MESSAGE THAT IS NOT THE client_confirmation_key FROM THE BUFFER ???
        try:
            check_client_confirmation_key(client_confirmation_key, client_key, hash_value)
            #? if the client_confirmation_key is correct, send SERVER_OK to the client
            robot.conn.send(SERVER_MESSAGES["SERVER_OK"])
        except SERVER_LOGIN_FAILED:
            robot.conn.send(SERVER_MESSAGES["SERVER_LOGIN_FAILED"])
            return False
        except SERVER_SYNTAX_ERROR:
            robot.conn.send(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
            return False

        return True     #? return true if the whole authentication runs correctly
    

        #*========================================---- ↓ ROBOT NAVIGATION FUNCTIONS ↓ ----=====================================================
    
    # TODO - vyresit zacykleni TURN RIGHT - when the coords are the same he is trying to dodge
    def navigate_robot(robot: client_robot):                                                 #! CONTINUE HERE <================
        print(f"STARTING TO NAVIGATE ROBOT!")      #~ debug print
        get_start_position(robot)

        #? firstly we get the robot to the position y = 0 
        # we align robot so that he is facing towards the y axis        
        align_robot(robot, 1)
        while robot.position[1] != 0:
            robot.conn.send(SERVER_MESSAGES["SERVER_MOVE"])
            get_coords_from_message(robot)

        #? now the robot is on position y = 0 so we need him to get to the position x = 0 
        # we align robot so that he is facing towards the x axis
        align_robot(robot, 0)
        while robot.position[0] != 0:
            robot.conn.send(SERVER_MESSAGES["SERVER_MOVE"])
            get_coords_from_message(robot)            

        # robot is now in the final position -> we pick up the message
        robot.conn.send(SERVER_MESSAGES["SERVER_PICK_UP"])
        msg = get_message(robot)
        validate_client_message(msg, "CLIENT_MESSAGE")


    def align_robot(robot: client_robot, axis: int):   #? axis = 1 means Y ...
        if axis == 1:
            if robot.position[1] < 0:
                while robot.direction != "UP":
                    align_turn_robot(robot)
            elif robot.position[1] > 0:
                while robot.direction != "DOWN":
                    align_turn_robot(robot)
        elif axis == 0:
            if robot.position[0] < 0:
                while robot.direction != "RIGHT":
                    align_turn_robot(robot)            
            elif robot.position[0] > 0:
                while robot.direction != "LEFT":
                    align_turn_robot(robot)
                    

    def align_turn_robot(robot: client_robot):
        robot.conn.send(SERVER_MESSAGES["SERVER_TURN_RIGHT"])
        msg = get_message(robot)
        validate_client_message(msg, "CLIENT_OK")
        robot.direction = DIRECTIONS_TURN_RIGHT[robot.direction] 


    def get_start_position(robot: client_robot):
        print(f"GETTING STARTING POSITION...")                  #~ debug print
        # first we need to get the coordinates of the robot
        robot.conn.send(SERVER_MESSAGES["SERVER_TURN_RIGHT"])
        get_coords_from_message(robot, 1)

        # if the robot has spawned already in the final position we dont't need to continue
        if robot.position == (0, 0):
            return None

        # then we have to get the direction the robot is facing
        robot.conn.send(SERVER_MESSAGES["SERVER_MOVE"])
        get_coords_from_message(robot)


    #? get the new robot coordinates and direction from the message, set the robot's position and and old_position
    def get_coords_from_message(robot: client_robot, turn: int = 0):
        robot.old_position = robot.position

        coords = get_message(robot)
        validate_client_message(coords, "CLIENT_OK")

        coords = coords[:-2].decode(FORMAT)

        #TODO - simplify
        if ( len(coords.split()) != 3 ) or ( len(coords) != len(coords.rstrip()) ):
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])

        # Split the message into x and y coordinates
        x, y = coords.split()[1:]
        
        if "." in x or "." in y:
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])

        # Convert the coordinates to integers and update the robot's position
        robot.position = (int(x), int(y))
        get_robot_direction(robot)                              #~ PRESUNOUT JENOM DO get_start_position ???
        print(f"NEW POSITION: {robot.position}")                #~ debug print
        print(f"NEW DIRECTION: {robot.direction}")              #~ debug print

        if (robot.position == robot.old_position) and (turn == 0):
            #? robot hit an obstacle
            robot_dodge(robot)


    def get_robot_direction(robot: client_robot):
        dx = robot.position[0] - robot.old_position[0]
        dy = robot.position[1] - robot.old_position[1]

        if dx > 0:
            robot.direction = "RIGHT"
        elif dx < 0:
            robot.direction = "LEFT"
        elif dy > 0:
            robot.direction = "UP"
        elif dy < 0:
            robot.direction = "DOWN"         
        # else:
        #     robot.direction = robot_turn(robot)


    def robot_dodge(robot: client_robot):
        robot.conn.send(SERVER_MESSAGES["SERVER_TURN_RIGHT"])
        get_coords_from_message(robot, 1)
        #
        robot.conn.send(SERVER_MESSAGES["SERVER_MOVE"])
        get_coords_from_message(robot)
        #
        robot.conn.send(SERVER_MESSAGES["SERVER_TURN_LEFT"])
        get_coords_from_message(robot, 1)
        #
        robot.conn.send(SERVER_MESSAGES["SERVER_MOVE"])
        get_coords_from_message(robot)
        if robot.position[0] == 0 or robot.position[1] == 0:
            return None
        #
        robot.conn.send(SERVER_MESSAGES["SERVER_MOVE"])
        get_coords_from_message(robot)
        #
        robot.conn.send(SERVER_MESSAGES["SERVER_TURN_LEFT"])
        get_coords_from_message(robot, 1)
        #
        robot.conn.send(SERVER_MESSAGES["SERVER_MOVE"])
        get_coords_from_message(robot)
        #
        robot.conn.send(SERVER_MESSAGES["SERVER_TURN_RIGHT"])
        get_coords_from_message(robot, 1)


    #|=================================================================================================================================================================
    
    #! CLIENTS HANDLING FUNCTIONS

    def close_client(conn):
        conn.close()


    # handle individual clients separately
    # running for each client individually
    def handle_client(conn, addr):                              #TODO - delete addr from arguments
        print(f"[NEW CONNECTION] {addr} connected.")            #~ debug print

        robot = client_robot(conn)
        while robot.connected:                                  # while client is connected receive messages from him
            msg = get_message(robot)                            # wait for the client until he sends a message through the socket (load it into a buffer which is 1024 bytes big)
            if len(msg) > 2:                                    # check if we actually got a valid message
                if msg[:-2].decode(FORMAT) == "!bye":           #~ DELETE
                    robot.connected = False                     #~ DELETE

                if not robot.authenticated:
                    try:
                        robot.authenticated = authenticate_client(robot, msg)
                    except SERVER_KEY_OUT_OF_RANGE_ERROR as err:    #? clients key ID is out of range
                        print(err)
                        conn.send(SERVER_MESSAGES["SERVER_KEY_OUT_OF_RANGE_ERROR"])
                        close_client(robot.conn)
                    except SERVER_SYNTAX_ERROR as err:              #? clients key ID or confirmation key is not a num
                        print(err)
                        conn.send(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
                        close_client(robot.conn)
                    else:
                        pass
                    finally:
                        if not robot.authenticated:
                            close_client(robot.conn)
                try:
                    print(f"[{addr}] AUTHENTICATION IS OKEY!")      #~ debug print
                    navigate_robot(robot)
                except SERVER_SYNTAX_ERROR as err:              #? clients key ID or confirmation key is not a num
                    print(err)
                    conn.send(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
                    close_client(robot.conn)

                #? if the navigation was successful, send SERVER_LOGOUT to the client
                conn.send(SERVER_MESSAGES["SERVER_LOGOUT"])
                robot.connected = False

        print(f"{addr} diconnected.")                           #~ debug print
        
        # when client writes "!bye" close the connection with the client
        close_client(robot.conn) 
    

    #? handle new connections and distribute them between clients 
    def start():
        server.listen()
        print(f"[LISTENING] Server is listening on {HOST}")
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target = handle_client, args=(conn, addr))   #? create an individual thread for each client
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")    # ~debug print


    #? ########################---- START THE SERVER ----################################
    print(f"[STARTING] server is starting...")                              # ~debug print
    start()
    
#|=================================================================================================================================================================

if __name__ == '__main__':
    main()