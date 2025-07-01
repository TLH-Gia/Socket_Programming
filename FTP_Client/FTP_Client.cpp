// =================================================================================
//  Combined and Refactored C++ FTP Client (CORRECTED VERSION)
//  - Logger is fully integrated and replaces all console output.
//  - Critical FTP protocol logic errors have been fixed.
//  - Handles both Active and Passive modes, with recursive transfers.
// =================================================================================

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include <vector>
#include <sstream>
#include <filesystem>
#include <cstdlib>
#include "Logger.h" // For log file 
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace fs = std::filesystem;

/// @brief Global flag to toggle interactive confirmation for MGET/MPUT. True by default.
bool interactiveMode = true;

/// @brief Global flag to toggle between FTP Passive (true) and Active (false) modes. False (Active) by default.
bool passiveMode = false;

/// @brief Global string for the current file transfer mode. "I" for Binary (default), "A" for ASCII.
std::string transferMode = "I";


// =================================================================================
//  SECTION 1: Core Network Utilities
// =================================================================================

/**
 * @brief Finds the primary active IPv4 address of the local machine.
 * @details This function queries the system's network adapters to find the first
 *          active non-loopback IPv4 address. It is essential for Active Mode FTP,
 *          where the client must tell the server its IP address via the PORT command.
 * @return A std::string containing the first active IPv4 address found.
 * @return "127.0.0.1" as a fallback if no suitable address is found.
 */
std::string get_local_ip() {
    ULONG bufferSize = 15000;
    std::vector<char> buffer(bufferSize);
    IP_ADAPTER_ADDRESSES* adapter_addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &bufferSize) == NO_ERROR) {
        // Data as Linked List
        for (IP_ADAPTER_ADDRESSES* adapter = adapter_addresses; adapter != NULL; adapter = adapter->Next)
        {
            if (adapter->OperStatus != IfOperStatusUp)
                continue;
            if (adapter->IfType != IF_TYPE_IEEE80211)
                continue;

            for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast != NULL; unicast = unicast->Next)
            {
                if (unicast->Address.lpSockaddr->sa_family == AF_INET)
                {
                    sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);// Cast to the specific IPv4 address structure.
                    char ipStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ipStr, sizeof(ipStr));
                    return std::string(ipStr);
                }
            }
        }
    }
    return "127.0.0.1";  // fallback
}

/**
 * @brief Establishes a standard TCP connection to a given host and port.
 * @param ip The IP address of the server to connect to.
 * @param port The port number on the server.
 * @return A valid SOCKET handle if the connection is successful.
 * @return INVALID_SOCKET if the connection fails at any stage.
 */
SOCKET connect_to(const std::string& ip, int port)
{
    //create a socket for TCP connection
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));  // Convert port to network byte order.
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr); // Convert IP string to binary format.

    if (connect(s, (sockaddr*)&addr, sizeof(addr)) < 0)
    {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

/**
 * @brief Reads a single chunk of data from a socket.
 * @warning This function is NOT suitable for general-purpose TCP communication. It performs
 *          only one read operation with a fixed-size buffer. If the server's response
 *          is larger than the buffer or arrives in multiple segments, this function will
 *          return an incomplete result.
 * @param s The connected socket to read data from.
 * @return A std::string containing the result:
 *         - On successful read: The data from the socket, with trailing '\r\n' removed.
 *         - If connection closed: The string "Connection closed by server.".
 *         - On socket error: The string "recv() failed.".
 */
std::string read_response(SOCKET s) {
    char buffer[4096];
    int received = recv(s, buffer, sizeof(buffer) - 1, 0);
    if (received > 0) {
        buffer[received] = '\0';
        std::string response(buffer);
        // FIX: Trim trailing newlines for cleaner logging and output
        if (!response.empty()) {
            response.erase(response.find_last_not_of("\r\n") + 1);
        }
        return response;
    }
    if (received == 0) return "Connection closed by server.";
    return "recv() failed.";
}

/**
 * @brief Sends an FTP command to the server over the control connection.
 * @details This function takes a command string, appends the required "\r\n"
 *          terminator as specified by the FTP protocol, and sends it to the server.
 * @param s The control socket connected to the FTP server.
 * @param cmd The FTP command string (e.g., "USER anonymous").
 */
void send_command(SOCKET s, const std::string& cmd) {
    // Log the command being sent
    Logger::getInstance().log(LogLevel::INFO, "Client: " + cmd);
    std::string full = cmd + "\r\n";
    send(s, full.c_str(), static_cast<int>(full.size()), 0);
}

// =================================================================================
//  SECTION 2: Data Connection Management (Passive vs. Active)
// =================================================================================

/**
 * @brief Parses the IP address and port from a server's PASV response.
 * @details The PASV response format is "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)".
 *          This function extracts these six numbers to compute the data connection endpoint.
 * @param resp The full response string from the server after a PASV command.
 * @return A std::pair containing the IP address string and the integer port number.
 * @return Returns an empty string and -1 on parsing failure.
 */
std::pair<std::string, int> parse_pasv(const std::string& resp) {
    std::smatch match;
    std::regex regex(R"(\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\))");
    if (std::regex_search(resp, match, regex) && match.size() == 7) {
        std::string ip = match[1].str() + "." + match[2].str() + "." + match[3].str() + "." + match[4].str();
        int port = std::stoi(match[5]) * 256 + std::stoi(match[6]);
        return { ip, port };
    }
    return { "", -1 };
}

/**
 * @brief Initiates a passive mode data connection with the FTP server.
 * @details It sends the "PASV" command, parses the server's response to get the
 *          IP and port for the data connection, and then connects to it.
 * @param control_sock The main FTP control socket.
 * @return A new SOCKET handle for the established data connection.
 * @return INVALID_SOCKET if any step fails.
 */
SOCKET open_connect_passive(SOCKET control_sock) {
    send_command(control_sock, "PASV");
    std::string resp = read_response(control_sock);
    Logger::getInstance().log(LogLevel::INFO, "Server: " + resp);

    auto [ip, port] = parse_pasv(resp);
    if (port == -1 || ip.empty()) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Failed to parse PASV response.");
        return INVALID_SOCKET;
    }

    SOCKET data_sock = connect_to(ip, port);
    if (data_sock == INVALID_SOCKET) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Data connection failed to " + ip + ":" + std::to_string(port));
    }
    return data_sock;
}

/**
 * @brief Initiates an active mode data connection.
 * @details It creates a local listening socket on an ephemeral port, tells the
 *          server this endpoint using the "PORT" command, and waits for the server to connect.
 * @param client_ip The local IP address of the client machine.
 * @param control_sock The main FTP control socket.
 * @return A listening SOCKET handle that is ready to accept the server's connection.
 * @return INVALID_SOCKET if any step fails.
 */
SOCKET open_connect_active(const std::string& client_ip, SOCKET control_sock) {
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in data_addr = {};
    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    data_addr.sin_port = 0;

    if (bind(listen_sock, (sockaddr*)&data_addr, sizeof(data_addr)) == SOCKET_ERROR) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Bind failed.");
        closesocket(listen_sock);
        return INVALID_SOCKET;
    }

    socklen_t len = sizeof(data_addr);
    getsockname(listen_sock, (sockaddr*)&data_addr, &len);
    int port = ntohs(data_addr.sin_port);

    std::string port_cmd_str = "PORT " + std::regex_replace(client_ip, std::regex("\\."), ",") + "," + std::to_string(port / 256) + "," + std::to_string(port % 256);
    send_command(control_sock, port_cmd_str);

    std::string resp = read_response(control_sock);
    Logger::getInstance().log(LogLevel::INFO, "Server: " + resp);

    if (resp.find("200") == std::string::npos) {
        closesocket(listen_sock);
        return INVALID_SOCKET;
    }

    if (listen(listen_sock, 1) == SOCKET_ERROR) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Listen failed.");
        closesocket(listen_sock);
        return INVALID_SOCKET;
    }

    return listen_sock;
}


/**
 * @brief Gets a data socket using either passive or active mode.
 * @details This acts as a factory function, calling the appropriate connection
 *          setup function based on the global `passiveMode` flag.
 * @param control_sock The main FTP control socket.
 * @param client_ip The client's IP address, required for active mode.
 * @return For passive mode, a connected data socket.
 * @return For active mode, a listening socket.
 * @return INVALID_SOCKET on failure.
 */
SOCKET get_data_socket(SOCKET control_sock, const std::string& client_ip) {
    if (passiveMode) {
        return open_connect_passive(control_sock);
    }
    else {
        return open_connect_active(client_ip, control_sock);
    }
}

/**
 * @brief Completes the active mode connection by accepting the server's connection.
 * @details This function is called after `open_connect_active`. It blocks until the
 *          server connects to the listening socket.
 * @param listen_sock The listening socket created by `open_connect_active`.
 * @return The established data transfer SOCKET on success.
 * @return INVALID_SOCKET on failure.
 */
SOCKET complete_active_connection(SOCKET listen_sock) {
    Logger::getInstance().log(LogLevel::INFO, "Waiting for server to connect for data transfer...");

    SOCKET data_sock = accept(listen_sock, nullptr, nullptr);
    closesocket(listen_sock);

    if (data_sock == INVALID_SOCKET) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Active mode accept() failed. Check your firewall configuration.");
        return INVALID_SOCKET;
    }
    return data_sock;
}

// =================================================================================
//  SECTION 3: Core FTP Command Implementations
// =================================================================================

/// @brief Enumerates the type of an item in an FTP directory listing.
enum class FtpItemType { FILE, DIRECTORY, UNKNOWN };

/// @brief Represents a single parsed item from an FTP directory listing.
struct FtpListItem {
    std::string name;
    FtpItemType type = FtpItemType::UNKNOWN;
};

// Forward declaration
FtpListItem parse_list_line(const std::string& line);


/**
 * @brief Downloads a single file from the FTP server.
 * @param control_sock The main FTP control socket.
 * @param filename The name of the file to retrieve from the server.
 * @param local_path The full local path where the file will be saved.
 * @param client_ip The client's IP address, needed for active mode.
 * @return True if the file was downloaded successfully, false otherwise.
 */
bool ftp_get(SOCKET control_sock, const std::string& filename, const std::string& local_path, const std::string& client_ip) {
    SOCKET initial_sock = get_data_socket(control_sock, client_ip);
    if (initial_sock == INVALID_SOCKET) return false;

    send_command(control_sock, "RETR " + filename);
    std::string resp = read_response(control_sock);
    Logger::getInstance().log(LogLevel::INFO, "Server: " + resp);
    if (resp.find("150") == std::string::npos)
    {
        // 150 File status okay; about to open data connection.
        closesocket(initial_sock);
        return false;
    }

    SOCKET data_sock = passiveMode ? initial_sock : complete_active_connection(initial_sock);
    if (data_sock == INVALID_SOCKET) return false;

    std::ofstream outfile(local_path, std::ios::binary);
    if (!outfile.is_open())
    {
        Logger::getInstance().log(LogLevel::LOGERROR, "Failed to open local file for writing: " + local_path);
        closesocket(data_sock);
        return false;
    }

    char buffer[4096];
    int received;
    while ((received = recv(data_sock, buffer, sizeof(buffer), 0)) > 0)
    {
        outfile.write(buffer, received);
    }
    outfile.close();
    closesocket(data_sock);

    resp = read_response(control_sock); // Read the 226 Transfer complete response.
    Logger::getInstance().log(LogLevel::INFO, "Server: " + resp);
    return resp.find("226") != std::string::npos;
}

/**
 * @brief Uploads a single file to the FTP server.
 * @param control_sock The main FTP control socket.
 * @param local_path The path of the local file to upload.
 * @param remote_filename The name the file will have on the server.
 * @param client_ip The client's IP address, needed for active mode.
 * @return True if the file was uploaded successfully, false otherwise.
 */
bool ftp_put(SOCKET control_sock, const std::string& local_path, const std::string& remote_filename, const std::string& client_ip) {
    SOCKET initial_sock = get_data_socket(control_sock, client_ip);
    if (initial_sock == INVALID_SOCKET) return false;

    send_command(control_sock, "STOR " + remote_filename);
    std::string resp = read_response(control_sock);
    Logger::getInstance().log(LogLevel::INFO, "Server: " + resp);
    if (resp.find("150") == std::string::npos) {
        closesocket(initial_sock);
        return false;
    }

    SOCKET data_sock = passiveMode ? initial_sock : complete_active_connection(initial_sock);
    if (data_sock == INVALID_SOCKET) return false;

    std::ifstream infile(local_path, std::ios::binary);
    if (!infile.is_open()) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Local file does not exist: " + local_path);
        closesocket(data_sock);
        return false;
    }

    char buffer[4096];
    while (infile.read(buffer, sizeof(buffer)) || infile.gcount() > 0) {
        if (send(data_sock, buffer, static_cast<int>(infile.gcount()), 0) == SOCKET_ERROR) {
            Logger::getInstance().log(LogLevel::LOGERROR, "Send failed during file upload.");
            infile.close();
            closesocket(data_sock);
            return false;
        }
    }
    infile.close();
    closesocket(data_sock);

    resp = read_response(control_sock);
    Logger::getInstance().log(LogLevel::INFO, "Server: " + resp);
    return resp.find("226") != std::string::npos;
}

/**
 * @brief Retrieves and parses a directory listing from the FTP server.
 * @details Sends the "LIST" command, receives the full directory listing over the
 *          data connection, and then parses it into a vector of items.
 * @param control_sock The main FTP control socket.
 * @param client_ip The client's IP address, needed for active mode.
 * @return A std::vector<FtpListItem> containing the parsed directory contents.
 *         The vector will be empty on failure.
 */
std::vector<FtpListItem> ftp_list(SOCKET control_sock, const std::string& client_ip) {
    SOCKET initial_sock = get_data_socket(control_sock, client_ip);
    std::vector<FtpListItem> items;
    if (initial_sock == INVALID_SOCKET) return items;

    send_command(control_sock, "LIST");
    std::string resp = read_response(control_sock);
    Logger::getInstance().log(LogLevel::INFO, "Server: " + resp);

    if (resp.find("150") == std::string::npos) {
        closesocket(initial_sock);
        return items;
    }

    SOCKET data_sock = passiveMode ? initial_sock : complete_active_connection(initial_sock);
    if (data_sock == INVALID_SOCKET) return items;

    std::string full_listing;
    char buffer[4096];
    int received;
    while ((received = recv(data_sock, buffer, sizeof(buffer), 0)) > 0) {
        full_listing.append(buffer, received);
    }
    closesocket(data_sock);

    resp = read_response(control_sock);
    Logger::getInstance().log(LogLevel::INFO, "Server: " + resp);

    std::istringstream iss(full_listing);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back(); // Clean up lines
        FtpListItem item = parse_list_line(line);
        if (item.type != FtpItemType::UNKNOWN && !item.name.empty() && item.name != "." && item.name != "..") {
            items.push_back(item);
        }
    }
    return items;
}


// =================================================================================
//  SECTION 4: ClamAV Scanner Integration
// =================================================================================

/**
 * @brief Scans a local file for viruses by contacting a ClamAV agent.
 * @details This function connects to a local ClamAV agent (assumed to be running on
 *          127.0.0.1:3310), sends the file path to be scanned, and interprets the response.
 * @param local_file_path The full path to the local file to be scanned.
 * @return True if the file is confirmed clean ("OK").
 * @return False if a virus is detected, the file doesn't exist, or any communication error occurs.
 */
bool scan_file_with_agent(const std::string& local_file_path) {
    if (!fs::exists(local_file_path)) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Local file does not exist: " + local_file_path);
        return false;
    }

    Logger::getInstance().log(LogLevel::INFO, "Contacting ClamAV Agent to scan '" + local_file_path + "'...");
    SOCKET agent_socket = connect_to("127.0.0.1", 3310);
    if (agent_socket == INVALID_SOCKET) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Could not connect to ClamAV Agent on port 3310. Is it running?");
        return false;
    }

    send(agent_socket, local_file_path.c_str(), static_cast<int>(local_file_path.size()), 0);

    char buffer[1024];
    int received = recv(agent_socket, buffer, sizeof(buffer) - 1, 0);
    closesocket(agent_socket);

    if (received <= 0) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Failed to receive response from ClamAV Agent.");
        return false;
    }

    buffer[received] = '\0';
    std::string response(buffer);
    Logger::getInstance().log(LogLevel::INFO, "Agent response: " + response);

    if (response == "OK") {
        Logger::getInstance().log(LogLevel::INFO, "Scan result: File is clean.");
        return true;
    }
    else {
        Logger::getInstance().log(LogLevel::WARN, "Scan result: VIRUS DETECTED or scan error! Upload aborted.");
        return false;
    }
}


// =================================================================================
//  SECTION 5: Recursive Operation Logic
// =================================================================================

/**
 * @brief Creates a directory on the FTP server.
 * @param control_sock The main FTP control socket.
 * @param dir_name The name of the directory to create on the server.
 * @return True if the server responds with success (257) or if the directory already exists (550).
 *         Returns false for other errors.
 */
bool ftp_mkdir(SOCKET control_sock, const std::string& dir_name) {
    send_command(control_sock, "MKD " + dir_name);
    std::string resp = read_response(control_sock);
    Logger::getInstance().log(LogLevel::INFO, "Server: " + resp);
    return resp.find("257") != std::string::npos || resp.find("550") != std::string::npos;
}

/**
 * @brief Parses a single line from an FTP LIST response to extract file/dir info.
 * @details This function is designed to handle typical UNIX-style LIST formats where
 *          the first character indicates the item type ('d' for directory, '-' for file).
 *          It then extracts the filename, which appears after the 8th column of metadata.
 * @param line A single line of text from the LIST command's data output.
 * @return An FtpListItem struct. The `type` will be `UNKNOWN` on parsing failure.
 */
FtpListItem parse_list_line(const std::string& line) {
    if (line.empty()) return {};
    FtpListItem item;
    if (line[0] == 'd') item.type = FtpItemType::DIRECTORY;
    else if (line[0] == '-') item.type = FtpItemType::FILE;
    else return {};

    std::string::size_type pos = -1;
    int space_count = 0;
    for (size_t i = 0; i < line.length() && space_count < 8; ++i) {
        if (isspace(line[i]) && (i == 0 || !isspace(line[i - 1]))) {
            space_count++;
        }
        if (space_count == 8) {
            pos = i;
            break;
        }
    }
    if (pos == std::string::npos) return {};

    item.name = line.substr(line.find_first_not_of(" \t", pos));
    return item;
}

/**
 * @brief Recursively uploads a local directory to the FTP server.
 * @details It iterates through the local directory. For each subdirectory, it calls
 *          itself. For each file, it first scans it with the ClamAV agent and then
 *          uploads it if clean.
 * @param control_sock The main FTP control socket.
 * @param local_path The local directory path to upload.
 * @param remote_path The destination directory path on the server.
 * @param client_ip The client's IP address, needed for active mode.
 */
void ftp_put_recursive(SOCKET control_sock, const fs::path& local_path, const std::string& remote_path, const std::string& client_ip) {
    if (!fs::exists(local_path) || !fs::is_directory(local_path)) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Local path is not a valid directory: " + local_path.string());
        return;
    }
    ftp_mkdir(control_sock, remote_path);

    for (const auto& entry : fs::directory_iterator(local_path)) {
        const auto& current_local_path = entry.path();
        std::string current_remote_path = remote_path + "/" + current_local_path.filename().string();

        if (fs::is_directory(current_local_path)) {
            ftp_put_recursive(control_sock, current_local_path, current_remote_path, client_ip);
        }
        else if (fs::is_regular_file(current_local_path)) {
            if (scan_file_with_agent(current_local_path.string())) {
                ftp_put(control_sock, current_local_path.string(), current_remote_path, client_ip);
            }
            else {
                Logger::getInstance().log(LogLevel::WARN, "Skipping infected file: " + current_local_path.string());
            }
        }
    }
}


/**
 * @brief Recursively downloads a remote directory from the FTP server.
 * @details Changes into the target remote directory, gets a listing, and then calls
 *          `ftp_get` for files and calls itself for subdirectories. Navigates back
 *          to the parent directory upon completion.
 * @param control_sock The main FTP control socket.
 * @param remote_path The remote directory path to download.
 * @param local_path The local destination directory path.
 * @param client_ip The client's IP address, needed for active mode.
 */
void ftp_get_recursive(SOCKET control_sock, const std::string& remote_path, const fs::path& local_path, const std::string& client_ip) {
    send_command(control_sock, "CWD " + remote_path);
    std::string cwd_resp = read_response(control_sock);
    Logger::getInstance().log(LogLevel::INFO, "Server: " + cwd_resp);
    if (cwd_resp.find("250") == std::string::npos) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Cannot enter remote directory: " + remote_path);
        return;
    }

    fs::create_directories(local_path);
    std::vector<FtpListItem> items = ftp_list(control_sock, client_ip);

    for (const auto& item : items) {
        fs::path current_local_path = local_path / item.name;
        if (item.type == FtpItemType::DIRECTORY) {
            ftp_get_recursive(control_sock, item.name, current_local_path, client_ip);
        }
        else if (item.type == FtpItemType::FILE) {
            ftp_get(control_sock, item.name, current_local_path.string(), client_ip);
        }
    }

    // FIX: Correctly read and log the response after changing directory up.
    send_command(control_sock, "CWD ..");
    std::string resp_up = read_response(control_sock);
    Logger::getInstance().log(LogLevel::INFO, "Server: " + resp_up);
}


// =================================================================================
//  SECTION 6: Main Application Loop
// =================================================================================


/**
 * @brief Prints the command help menu to the application's logger.
 */
void print_help() {
    Logger::getInstance().log(LogLevel::INFO, "\n--- FTP Client Commands ---\n"
        "  OPEN <host>                         - Connect to remote ftp server\n"
        "  CLOSE                               - Disconnect to ftp server\n"
        "  USER <username>                     - Send user name\n"
        "  PASS <password>                     - Send password\n"
        "  LIST                                - List files and folders in current remote directory\n"
        "  CWD <dir>                           - Change remote working directory\n"
        "  PWD                                 - Print remote working directory\n"
        "  MKD <dir-name>                      - Create directory on the remote machine\n"
        "  GET <remote-dir> [local-dir]        - Download a single file\n"
        "  PUT <local-dir> [remote-dir]        - Upload a single file (scans before upload)\n"
        "  MGET <remote_pattern>               - Download multiple files (e.g., MGET *.txt)\n"
        "  MPUT <local_pattern>                - Upload multiple files (e.g., MPUT *.log)\n"
        "  RGET <remote-dir> <local-dir>       - Recursively download a directory\n"
        "  RPUT <local-dir> <remote-dir>       - Recursively upload a directory (scans all files)\n"
        "  ASCII                               - File transfer mode to ascii\n"
        "  BINARY                              - File transfer mode to binar\n"
        "  PASSIVE                             - Toggle passive/active mode (default: active)\n"
        "  PROMPT                              - Toggle interactive confirmation for MGET/MPUT\n"
        "  HELP or ?                           - Show this help message\n"
        "  STATUS                              - Show current session status\n"
        "  QUIT or BYE                         - Terminate ftp session and exit\n");
}

/**
 * @brief The main entry point and command processing loop for the FTP client.
 * @details Initializes Winsock and the logger, then enters an infinite loop to
 *          read user commands from stdin, parse them, and dispatch them to the
 *          appropriate FTP handling functions.
 * @return 0 on normal exit, 1 on fatal initialization error.
 */
int main() {
    Logger::getInstance().start("ftp_client.log");

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        Logger::getInstance().log(LogLevel::LOGERROR, "Fatal Error: WSAStartup failed.");
        return 1;
    }

    SOCKET control = INVALID_SOCKET;
    std::string client_ip = get_local_ip();

    Logger::getInstance().log(LogLevel::INFO, "Welcome to the C++ FTP Client. Local IP: " + client_ip);
    print_help();

    std::string line;
    while (true) {
        // FIX: Keep std::cout ONLY for the interactive prompt.
        std::cout << "ftp> ";
        if (!std::getline(std::cin, line)) { // Handle Ctrl+C or end-of-file
            if (control != INVALID_SOCKET) send_command(control, "QUIT");
            break;
        }

        Logger::getInstance().log(LogLevel::INFO, "User Input: " + line);

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        for (auto& c : cmd) c = static_cast<char>(toupper(c));

        if (cmd == "QUIT" || cmd == "BYE") {
            if (control != INVALID_SOCKET) {
                send_command(control, "QUIT");
                Logger::getInstance().log(LogLevel::INFO, "Server: " + read_response(control));
                closesocket(control);
            }
            break;
        }
        if (cmd.empty()) continue;
        if (cmd == "HELP" || cmd == "?") {
            print_help();
            continue;
        }
        if (cmd == "OPEN") {
            if (control != INVALID_SOCKET) {
                Logger::getInstance().log(LogLevel::WARN, "Already connected. Use QUIT to disconnect first.");
                continue;
            }

            std::string server_ip;
            iss >> server_ip;
            if (server_ip.empty()) {
                Logger::getInstance().log(LogLevel::WARN, "Usage: OPEN <hostname>");
            }
            else {
                control = connect_to(server_ip, 21);
                if (control == INVALID_SOCKET) {
                    Logger::getInstance().log(LogLevel::LOGERROR, "Connection to " + server_ip + " failed.");
                }
                else {
                    Logger::getInstance().log(LogLevel::INFO, "Server: " + read_response(control));
                    Logger::getInstance().log(LogLevel::INFO, "Connected. Please provide USER and PASS.");
                }
            }
            continue;
        }
        else if (cmd == "STATUS") {
            Logger::getInstance().log(LogLevel::INFO, "\n--- Session Status ---");
            Logger::getInstance().log(LogLevel::INFO, "Connected: " + std::string(control != INVALID_SOCKET ? "YES" : "NO"));
            Logger::getInstance().log(LogLevel::INFO, "Transfer mode: " + std::string(transferMode == "I" ? "BINARY" : "ASCII"));
            Logger::getInstance().log(LogLevel::INFO, "Data mode: " + std::string(passiveMode ? "PASSIVE" : "ACTIVE"));
            Logger::getInstance().log(LogLevel::INFO, "Prompt (MGET/MPUT confirmation): " + std::string(interactiveMode ? "ON" : "OFF"));
            Logger::getInstance().log(LogLevel::INFO, "------------------------");
            continue;
        }

        if (control == INVALID_SOCKET) {
            Logger::getInstance().log(LogLevel::WARN, "Not connected. Use OPEN <host> first.");
            continue;
        }

        if (cmd == "RPUT") {
            std::string local_dir, remote_dir;
            iss >> local_dir >> remote_dir;
            if (local_dir.empty() || remote_dir.empty()) {
                Logger::getInstance().log(LogLevel::WARN, "Usage: RPUT <local_directory> <remote_directory>");
            }
            else {
                ftp_put_recursive(control, local_dir, remote_dir, client_ip);
                Logger::getInstance().log(LogLevel::INFO, "Recursive upload finished.");
            }
        }
        else if (cmd == "RGET") {
            std::string remote_dir, local_dir;
            iss >> remote_dir >> local_dir;
            if (remote_dir.empty() || local_dir.empty()) {
                Logger::getInstance().log(LogLevel::WARN, "Usage: RGET <remote_directory> <local_directory>");
            }
            else {
                ftp_get_recursive(control, remote_dir, local_dir, client_ip);
                Logger::getInstance().log(LogLevel::INFO, "Recursive download finished.");
            }
        }
        else if (cmd == "MPUT") {
            std::string pattern;
            iss >> pattern;
            if (pattern.empty()) {
                Logger::getInstance().log(LogLevel::WARN, "Usage: MPUT <pattern>");
            }
            else {
                std::filesystem::path pathPattern(pattern);
                std::filesystem::path baseDir = pathPattern.parent_path();
                if (baseDir.empty()) baseDir = fs::current_path();

                std::string rawPattern = pathPattern.filename().string();
                std::regex regexPattern(std::regex_replace(rawPattern, std::regex(R"(\*)"), ".*"));

                for (const auto& entry : fs::directory_iterator(baseDir)) {
                    if (fs::is_regular_file(entry)) {
                        std::string name = entry.path().filename().string();
                        if (std::regex_match(name, regexPattern)) {
                            if (interactiveMode) {
                                std::cout << "Upload " << entry.path().string() << "? (y/n): ";
                                std::string answer;
                                std::getline(std::cin, answer);
                                if (answer != "y" && answer != "Y") continue;
                            }
                            if (scan_file_with_agent(entry.path().string())) {
                                Logger::getInstance().log(LogLevel::INFO, "Uploading file: " + entry.path().string());
                                ftp_put(control, entry.path().string(), name, client_ip);
                            }
                            else {
                                Logger::getInstance().log(LogLevel::WARN, "Skipping infected file: " + name);
                            }
                        }
                    }
                }
            }
        }
        else if (cmd == "MGET") {
            std::string pattern;
            iss >> pattern;
            if (pattern.empty()) {
                Logger::getInstance().log(LogLevel::WARN, "Usage: MGET <pattern>");
            }
            else {
                std::vector<FtpListItem> items = ftp_list(control, client_ip);
                std::regex regexPattern(std::regex_replace(pattern, std::regex(R"(\*)"), ".*"));

                for (const auto& item : items) {
                    if (item.type == FtpItemType::FILE && std::regex_match(item.name, regexPattern)) {
                        if (interactiveMode) {
                            std::cout << "Download " << item.name << "? (y/n): ";
                            std::string answer;
                            std::getline(std::cin, answer);
                            if (answer != "y" && answer != "Y") continue;
                        }
                        Logger::getInstance().log(LogLevel::INFO, "Downloading file: " + item.name);
                        ftp_get(control, item.name, item.name, client_ip);
                    }
                }
            }
        }
        else if (cmd == "GET") {
            std::string remote_file, local_file;
            iss >> remote_file >> local_file;
            if (remote_file.empty()) {
                Logger::getInstance().log(LogLevel::WARN, "Usage: GET <remote-file> [local-file]");
            }
            else {
                if (local_file.empty()) local_file = fs::path(remote_file).filename().string();
                ftp_get(control, remote_file, local_file, client_ip);
            }
        }
        else if (cmd == "PUT") {
            std::string local_file, remote_file;
            iss >> local_file >> remote_file;
            if (local_file.empty()) {
                Logger::getInstance().log(LogLevel::WARN, "Usage: PUT <local-file> [remote-file]");
            }
            else {
                if (remote_file.empty()) remote_file = fs::path(local_file).filename().string();
                if (scan_file_with_agent(local_file)) {
                    ftp_put(control, local_file, remote_file, client_ip);
                }
            }
        }
        else if (cmd == "ASCII") {
            send_command(control, "TYPE A");
            std::string resp = read_response(control);
            Logger::getInstance().log(LogLevel::INFO, "Server: " + resp);
            if (resp.find("200") != std::string::npos) {
                transferMode = "A";
                Logger::getInstance().log(LogLevel::INFO, "Transfer mode set to ASCII.");
            }
            else {
                Logger::getInstance().log(LogLevel::LOGERROR, "Failed to set ASCII mode.");
            }
        }
        else if (cmd == "BINARY") {
            send_command(control, "TYPE I");
            std::string resp = read_response(control);
            Logger::getInstance().log(LogLevel::INFO, "Server: " + resp);
            if (resp.find("200") != std::string::npos) {
                transferMode = "I";
                Logger::getInstance().log(LogLevel::INFO, "Transfer mode set to Binary.");
            }
            else {
                Logger::getInstance().log(LogLevel::LOGERROR, "Failed to set Binary mode.");
            }
        }
        else if (cmd == "PASSIVE") {
            passiveMode = !passiveMode;
            Logger::getInstance().log(LogLevel::INFO, "Passive mode is now " + std::string(passiveMode ? "ON" : "OFF") + ".");
        }
        else if (cmd == "PROMPT") {
            interactiveMode = !interactiveMode;
            Logger::getInstance().log(LogLevel::INFO, "Interactive mode is now " + std::string(interactiveMode ? "ON" : "OFF") + ".");
        }
        else if (cmd == "LIST" || cmd == "LS") {
            std::vector<FtpListItem> items = ftp_list(control, client_ip);
            Logger::getInstance().log(LogLevel::INFO, "--- Directory Listing ---");
            for (const auto& item : items) {
                Logger::getInstance().log(LogLevel::INFO, (item.type == FtpItemType::DIRECTORY ? "[DIR]  " : "[FILE] ") + item.name);
            }
            Logger::getInstance().log(LogLevel::INFO, "-------------------------");
        }
        else if (cmd == "CLOSE")
        {
            if (control != INVALID_SOCKET) {
                Logger::getInstance().log(LogLevel::WARN, "No connected.");
                continue;
            }
            else
            {
                closesocket(control);
            }
        }
        else {
            send_command(control, line);
            Logger::getInstance().log(LogLevel::INFO, "Server: " + read_response(control));
        }
    }

    WSACleanup();
    Logger::getInstance().log(LogLevel::INFO, "FTP client exited.");
    return 0;
}
