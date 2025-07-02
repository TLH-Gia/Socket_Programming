# High-Level Architecture

The program is a command-line FTP (File Transfer Protocol) client. It operates based on a standard *command-response* model. The user types a command, the client sends it to the FTP server, reads the server's reply, and then takes the appropriate action.

The client is built in distinct layers:
1.  *User Interface*: The main() function loop that reads user input.
2.  *Command Logic*: Functions that implement specific FTP commands.
3.  *Connection Management*: Handling the two-channel nature of FTP (Control and Data) in both Active and Passive modes.
4.  *Core Networking*: Low-level functions for sending and receiving data over TCP/IP sockets.
5.  *Logging*:Self-contained logging system that records every action to a file.

## Section 0: The Logger Class

This class handles all program output (instead of printing all to console).

*   *Purpose*: To create a persistent, timestamped log file (ftp_client.log) of every action the client takes. 
  
*   **Singleton Pattern (getInstance)**: Ensures there is only *one* instance of the logger in the entire program. `static Logger instance;` creates the object the first time it's called and reuses it every time after (globally accessible).
  
*   **Initialization (start and stop)**: main() calls start() to open the log file. The logger automatically closes the file when the program exits.
  
*   *Cross-Platform Safety*: `#ifdef _MSC_VER` to use the safer localtime_s on Windows (MSVC compiler) while using the standard localtime on other systems, avoiding compiler warnings and maintaining portability.
  
*   **Log Levels (INFO, WARN, LOGERROR)**: Allows classifying messages by severity. LOGERROR messages are sent to `std::cerr`, while others go to `std::cout`. All messages are written to the log file.

## Section 1: Core Network Utilities

*   **get_local_ip()**: This function is crucial for *Active Mode FTP*. It queries the operating system's network adapters to find the client's local IP address.

*   **connect_to(ip, port)**: A simple helper function that creates a TCP socket and connects it to a specific server IP address and port. This is used for both the control and data connections.
  
*   **read_response(socket)**: Listens on a given socket for a reply from the server. It reads the data and  **`trims trailing newline characters (\r\n)`** to make log files cleaner.
  
*   **send_command(socket, cmd)**: Takes a command string, logs it, appends the `\r\n` required by the FTP protocol, and sends it to the server.

## Section 2: Data Connection Management 

1.  *Control Channel*: The connection made to port 21. All commands and server responses travel on this channel. It stays open for the entire session.

2.  *Data Channel*: A temporary, second connection that is opened only when data needs to be transferred (e.g., for a file listing or a file download/upload). It is closed immediately after the transfer is complete.

There are two ways to establish this Data Channel:

### Passive Mode (PASV)

1.  The client sends the PASV command to the server on the Control Channel.
2.  The server responds with an IP address and a port number (e.g., 227 Entering Passive Mode (192,168,1,5,10,20)).
3.  The client then *initiates* a new connection to that IP and port. This becomes the Data Channel.

*   **parse_pasv(resp)**: This function uses a regular expression to extract the IP and port from the server's PASV response.
*   **open_connect_passive(control_sock)**: This function orchestrates the process: sends PASV, parses the response, and calls connect_to to establish the data connection.

### Active Mode (PORT)

1.  The client opens a socket on its own machine and starts listening for an incoming connection.
2.  The client figures out its own IP (get_local_ip) and the port it's listening on. It sends this information to the server using the PORT command (e.g., PORT 10,0,1,2,15,30).
3.  The server then *initiates* a connection back to the client's specified IP and port.

*   **open_connect_active(...)**: This function creates the listening socket, sends the PORT command, and waits for the server to connect.
*   **complete_active_connection(listen_sock)**: After the data transfer command (LIST, RETR, etc.) is sent, this function calls accept() on the listening socket to finalize the connection when the server connects back.

### The Dispatcher

*   **get_data_socket(...)**: The main dispatcher, based on the global passiveMode boolean. It decides whether to call open_connect_passive or open_connect_active to get the initial data socket.

## Section 3: Core FTP Command Implementations

These functions combine the network utilities and data connection logic to execute user commands. They follow a strict pattern:

1.  Establish a data connection using get_data_socket().
2.  Send the primary FTP command (e.g., RETR filename).
3.  Read the server's initial response (e.g., 150 Opening data channel).
4.  Perform the data transfer (read or write) over the *data socket*.
5.  Close the *data socket*.
6.  Read the final confirmation response from the *control socket* (e.g., 226 Transfer complete).

*   **ftp_get(...)**: Downloads a file.
*   **ftp_put(...)**: Uploads a file.
*   **ftp_list(...)**: Gets a directory listing and uses parse_list_line to interpret each line as either a file or a directory.

## Section 4: ClamAV Scanner Integration

*   **scan_file_with_agent(local_path)**: A security feature. Before uploading a file, this function connects to a locally running ClamAV antivirus agent (on port 3310), sends it the file path, and waits for an "OK" or "VIRUS DETECTED" response. The upload only proceeds if the file is clean.

## Section 5: Recursive Operation Logic

These functions build on the core commands to handle entire directories.

*   **ftp_put_recursive(...)**: To upload a directory:
    1.  It creates the corresponding directory on the server (MKD).
    2.  It iterates through the local directory.
    3.  If it finds a file, it scans it and calls ftp_put.
    4.  If it finds another directory, it calls *itself* (recursion) to handle that subdirectory.
*   **ftp_get_recursive(...)**: To download a directory:
    1.  It changes the server's working directory to the target directory (CWD).
    2.  It creates the corresponding local directory.
    3.  It gets a LIST of all items in the remote directory.
    4.  It iterates through the list, calling ftp_get for files and calling *itself* (recursion) for directories.
    5.  It sends CWD .. to go back up to the parent directory before returning, so the next recursive call starts from the correct place.

## Section 6: The Main Application Loop

This is where everything is tied together.

1.  **Initialization**:
    *   Logger::getInstance().start(...) starts the logger.
    *   WSAStartup() initializes the Winsock library for networking on Windows.
    *   get_local_ip() gets the client's IP for later use.
    *   print_help() displays the available commands (using the logger).

2.  **The while(true) Loop**:
    *   std::cout  "; prints the interactive prompt for the user. This is the *only* std::cout call left, so the prompt doesn't get written to the log file.
    *   std::getline(std::cin, line) reads the user's entire command.
    *   The input is logged.
    *   std::istringstream is used to easily parse the line into a command (e.g., "GET") and its arguments (e.g., "file.txt").

3.  **Command Dispatcher (the big if-else if block)**:
    *   This block checks the command the user entered.
    *   Based on the command, it calls the appropriate function (ftp_get, ftp_put_recursive, etc.), passing along the arguments.
    *   It handles simple commands like PASSIVE (toggles the mode) and special cases like OPEN and QUIT.

4.  **Shutdown**:
    *   When the user types QUIT or BYE, the client sends the QUIT command to the server, closes the connection, and breaks the loop.
    *   WSACleanup() releases the resources used by the Winsock library.
    *   The Logger's destructor is automatically called, ensuring the log file is properly closed.