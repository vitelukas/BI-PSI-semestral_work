import socket
import threading

#? ====================================================================------ MAIN ------===============================================================================
def main():
    # !Constants

    #? Server constants ----------------------------------------------------- 
    PORT = 3999
    HOST = socket.gethostbyname(socket.gethostname())
    ADDRESS = (HOST, PORT)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDRESS)
    server.listen(20)    #* listen to max 20 clients

    FORMAT = "utf-8"
    SUFFIX = b'\x07\x08'

    # timeouts (s)
    TIMEOUT = 1
    TIMEOUT_RECHARGING = 5
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
    DIRECTIONS_TURN_LEFT = {
        "UP":       "LEFT",
        "LEFT":     "DOWN",
        "DOWN":     "RIGHT",
        "RIGHT":    "UP",
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
    class SERVER_LOGIC_ERROR(Exception):
        def __init__(self, message):
            self.message = message

    #|================================================================================================================================================================
    
    #! Classes and structures
    
    class client_robot:
        def __init__(self, conn):
            self.conn = conn
            self.connected: bool = True
            self.username: str = ""
            self.buffer: bytes = b''
            self.recharging: bool = False
            self.direction: str = "NONE"
            self.position: tuple[int, int] = (0, 0)         # (x, y) coordinates
            self.old_position: tuple[int, int] = (0, 0)     # (x, y) coordinates

    #|=================================================================================================================================================================
    
    #! Functions
        #*==========================================---- ↓ GENERAL FUNCTIONS ↓ ----=============================================================
    
    def get_message(robot: client_robot, msg_max_len: str, TIMEOUT: int = TIMEOUT):
        msg = b''
        max_message_len = max(CLIENT_MESSAGES_MAX_LEN[msg_max_len], CLIENT_MESSAGES_MAX_LEN["CLIENT_RECHARGING"])
        # We are receiving data from the client until we receive a full message
        while True:
            # If there is nothing in the buffer, we wait for a message
            if len(robot.buffer) == 0:
                try:
                    robot.conn.settimeout(TIMEOUT)
                    robot.buffer += robot.conn.recv(1024)
                except socket.timeout:
                    close_client(robot.conn)
                else:
                    robot.conn.settimeout(None)                    
            # If there is at least one byte in the buffer we gradually put it together into a message
            # if we put together a whole message or if we reach max_message_len then we break the loop
            else:
                msg += robot.buffer[:1]
                robot.buffer = robot.buffer[1:]
                if len(msg) == max_message_len:
                    print(msg)
                    check_suffix(msg)
                    break
                if msg[-2:] == SUFFIX:
                    break
        
        if msg != CLIENT_RECHARGING_MESSAGES["CLIENT_RECHARGING"]:
            if msg == CLIENT_RECHARGING_MESSAGES["CLIENT_FULL_POWER"] and robot.recharging == False:
                raise SERVER_LOGIC_ERROR(SERVER_MESSAGES["SERVER_LOGIC_ERROR"])       
            else:
                return msg
        else:
            robot_recharging(robot)
            return get_message(robot, msg_max_len)


        #*========================================---- ↓ AUTHENTICATE CLIENT ↓ ----=====================================================

    
    def authenticate_client(robot: client_robot):
        
        #~ --- GET CLIENT'S USERNAME ---
        print("[GETTING USERNAME]")                                 #~ debug print
        print(f"Starting username validation...")                   #~ debug print
        client_username = get_message(robot, "CLIENT_USERNAME")

        #? if the client_username is valid, set it to the robot's username
        robot.username = client_username[:-2].decode(FORMAT)
        robot.username = robot.username.strip()

        #? check if the robot sent a recharge request 
        check_recharge(robot)

        #~ --- GET CLIENT'S KEY ID ---
        #? if the client_username is valid, send him a key request
        robot.conn.send(SERVER_MESSAGES["SERVER_KEY_REQUEST"])
        client_KEY_ID = get_message(robot, "CLIENT_KEY_ID")                                             

        check_key_ID(client_KEY_ID)

        server_key, client_key = SERVER_CLIENT_KEYS[int(client_KEY_ID[:-2].decode(FORMAT))]
        server_confirmation_key, hash_value = calculate_confirmation_key(robot.username, server_key)        

        #? send SERVER_CONFIRMATION (= calculated server_confirmation_key ) to the client
        robot.conn.send( str(server_confirmation_key).encode(FORMAT) + SUFFIX)

        #~ --- GET CLIENT'S CONFIRMATION KEY ---
        client_confirmation_key = get_message(robot, "CLIENT_CONFIRMATION")
        
        check_client_confirmation_key(client_confirmation_key, client_key, hash_value)

        #? if the client_confirmation_key is correct, send SERVER_OK to the client
        robot.conn.send(SERVER_MESSAGES["SERVER_OK"])
            
    
    def check_suffix(message: bytes):
        if message[-2:] != SUFFIX:
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])


    def check_client_confirmation_key(message: bytes, client_key: int, hash_value: int):
        client_confirmation_key = message[:-2].decode(FORMAT)
        if not client_confirmation_key.isnumeric() or len(message) > CLIENT_MESSAGES_MAX_LEN["CLIENT_CONFIRMATION"]:
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
        
        correct_client_key_value = (hash_value + client_key) % 65536

        if int(client_confirmation_key) != correct_client_key_value:
            raise SERVER_LOGIN_FAILED(SERVER_MESSAGES["SERVER_LOGIN_FAILED"])


    def calculate_confirmation_key(username: str, server_key: int):
        # both of the messages suffix was already checked
        print(f"[CLIENTS USERNAME]: {username}")                #~ debug print

        ascii_sum = 0
        for char in username:
            ascii_sum += ord(char)

        hash_value = (ascii_sum * 1000) % 65536
        print(f"[hash_value]: {hash_value}")                    #~ debug print

        calculated_key = (hash_value + server_key) % 65536 

        print(f"calculated_key = {calculated_key}")             #~ debug print
        return calculated_key, hash_value                       


    #? check if the key is ok
    def check_key_ID(message: bytes):
        key_ID = message[:-2].decode(FORMAT)
        if not key_ID.isnumeric():
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])
        key_ID = int(key_ID)
        if key_ID < 0 or key_ID > 4:
            raise SERVER_KEY_OUT_OF_RANGE_ERROR(SERVER_MESSAGES["SERVER_KEY_OUT_OF_RANGE_ERROR"])    
    

        #*========================================---- ↓ ROBOT NAVIGATION FUNCTIONS ↓ ----=====================================================
    
    def navigate_robot(robot: client_robot):                                                 
        print(f"STARTING TO NAVIGATE ROBOT!")      #~ debug print
        get_start_position(robot)

        while robot.position != (0,0):
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
        msg = get_message(robot, "CLIENT_MESSAGE")


    def align_robot(robot: client_robot, axis: int):   #? axis = 0 means X ...
        if axis == 0:
            if robot.position[0] < 0:
                while robot.direction != "RIGHT":
                    align_turn_robot(robot)            
            elif robot.position[0] > 0:
                while robot.direction != "LEFT":
                    align_turn_robot(robot)
        elif axis == 1:
            if robot.position[1] < 0:
                while robot.direction != "UP":
                    align_turn_robot(robot)
            elif robot.position[1] > 0:
                while robot.direction != "DOWN":
                    align_turn_robot(robot)
        
                    

    def align_turn_robot(robot: client_robot):
        robot.conn.send(SERVER_MESSAGES["SERVER_TURN_RIGHT"])
        get_coords_from_message(robot, 2)


    def get_start_position(robot: client_robot):
        print(f"GETTING STARTING POSITION...")                  #~ debug print
        #? first we need to get the coordinates of the robot
        robot.conn.send(SERVER_MESSAGES["SERVER_TURN_RIGHT"])
        get_coords_from_message(robot, 1)

        #? if the robot has spawned in the final position [0, 0] we dont't need to continue
        if robot.position == (0, 0):
            return None

        #? otherwise we have to get the direction the robot is facing
        robot.conn.send(SERVER_MESSAGES["SERVER_MOVE"])
        get_coords_from_message(robot)

        #? if the robot is stuck right after he spawn, 
        #? we try to move the robot until we have his position and direction
        while robot.direction == "NONE":
            robot.conn.send(SERVER_MESSAGES["SERVER_TURN_RIGHT"])
            get_coords_from_message(robot, 2)
            robot.conn.send(SERVER_MESSAGES["SERVER_MOVE"])
            get_coords_from_message(robot)
        

    #? Get the new robot coordinates and direction from the message, set the robot's position and and old_position
    def get_coords_from_message(robot: client_robot, turn: int = 0):    #? turn = 0 = robot moved 
        robot.old_position = robot.position                             #? turn = 1 = robot turned left
                                                                        #? turn = 2 = robot turned right
        coords = get_message(robot, "CLIENT_OK")

        coords = coords[:-2].decode(FORMAT)

        if ( len(coords.split()) != 3 ) or ( len(coords) != len(coords.rstrip()) ):
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])

        # Split the message into x and y coordinates
        x, y = coords.split()[1:]
        
        if "." in x or "." in y:
            raise SERVER_SYNTAX_ERROR(SERVER_MESSAGES["SERVER_SYNTAX_ERROR"])

        # Convert the coordinates to integers and update the robot's position
        robot.position = (int(x), int(y))

        #? Do NOT try to dodge an obstacle if:
        #?  1) we are only getting the starting position
        #?  2) the robot hits an obstacle right after he spawns
        #?  3) the robot only turned right/left but didn't actually move
        if (robot.position == robot.old_position) and (turn == 0) and (robot.direction != "NONE"):
            #? robot hit an obstacle
            robot_dodge(robot)

        if turn == 0:
            get_robot_direction(robot)
        elif turn == 1:
            robot.direction = DIRECTIONS_TURN_LEFT[robot.direction]
        elif turn == 2:
            robot.direction = DIRECTIONS_TURN_RIGHT[robot.direction]
        
        print(f"NEW POSITION: {robot.position}")                #~ debug print
        print(f"NEW DIRECTION: {robot.direction}")              #~ debug print
        

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


    def robot_dodge(robot: client_robot):
        robot.conn.send(SERVER_MESSAGES["SERVER_TURN_RIGHT"])
        get_coords_from_message(robot, 2)
        #
        robot.conn.send(SERVER_MESSAGES["SERVER_MOVE"])
        get_coords_from_message(robot)
        #
        robot.conn.send(SERVER_MESSAGES["SERVER_TURN_LEFT"])
        get_coords_from_message(robot, 1)
        #
        robot.conn.send(SERVER_MESSAGES["SERVER_MOVE"])
        get_coords_from_message(robot)
        if robot.position[0] == 0 or robot.position[1] == 0:    #? if the robot crosses an axis while dodging an obstacle we can stop dodging
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
        get_coords_from_message(robot, 2)


         #*==========================================---- ↓ ROBOT  RECHARGING ↓ ----=============================================================

    def robot_recharging(robot: client_robot):
        robot.conn.settimeout(TIMEOUT_RECHARGING)
        robot.recharging = True
        message = get_message(robot, "CLIENT_FULL_POWER", TIMEOUT_RECHARGING)
        if message != CLIENT_RECHARGING_MESSAGES["CLIENT_FULL_POWER"]:
            raise SERVER_LOGIC_ERROR(SERVER_MESSAGES["SERVER_LOGIC_ERROR"])
        robot.recharging = False
        robot.conn.settimeout(None)

    
    def check_recharge(robot: client_robot):                    
        print("ROBOT BUFFER IS CURRENTLY THIS:")                #~ debug print
        print(robot.buffer)                                     #~ debug print
        if SUFFIX in robot.buffer:
            index = robot.buffer.index(SUFFIX) + 2
            msg = robot.buffer[:index]
            if msg != CLIENT_RECHARGING_MESSAGES["CLIENT_RECHARGING"]:
                if msg == CLIENT_RECHARGING_MESSAGES["CLIENT_FULL_POWER"] and robot.recharging == False:
                    raise SERVER_LOGIC_ERROR(SERVER_MESSAGES["SERVER_LOGIC_ERROR"])       
            else:
                print("[STARTING ROBOT RECHARGING]")
                robot.buffer = robot.buffer[index:]
                robot_recharging(robot)
                

    #|=================================================================================================================================================================
    
    #! CLIENTS HANDLING FUNCTIONS

    def close_client(conn):
        conn.close()


    def comm_failure(robot, error_type: str):
        print(error_type)
        robot.conn.send(SERVER_MESSAGES[error_type])
        close_client(robot.conn)


    # Handle individual clients separately
    # Running for each client individually
    def handle_client(conn, addr):                              #TODO - delete addr from arguments
        print(f"[NEW CONNECTION] {addr} connected.")            #~ debug print
        robot = client_robot(conn)
        
        #~ --- CLIENT AUTHENTICATION ---
        try:
            authenticate_client(robot)
        except SERVER_SYNTAX_ERROR:                             #? client's key ID or confirmation key is invalid
            comm_failure(robot, "SERVER_SYNTAX_ERROR")
        except SERVER_KEY_OUT_OF_RANGE_ERROR:
            comm_failure(robot, "SERVER_KEY_OUT_OF_RANGE_ERROR")
        except SERVER_LOGIN_FAILED:
            comm_failure(robot, "SERVER_LOGIN_FAILED")

        print(f"[{addr}] AUTHENTICATION IS OKEY!")              #~ debug print
        
        #~ --- CLIENT NAVIGATION ---
        try:
            navigate_robot(robot)
        except SERVER_SYNTAX_ERROR:                             #? client's key ID or confirmation key is not a num
            comm_failure(robot, "SERVER_SYNTAX_ERROR")
        except SERVER_LOGIC_ERROR:
            comm_failure(robot, "SERVER_LOGIC_ERROR")

        #~ --- LOGOUT THE CLIENT ---
        #? if the navigation was successful, send SERVER_LOGOUT to the client
        conn.send(SERVER_MESSAGES["SERVER_LOGOUT"])

        #? if the robot picked up the message successfully, we close the connection
        print(f"{addr} diconnected.")                           #~ debug print
        close_client(robot.conn)


    #? Handle new connections and distribute them between clients 
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