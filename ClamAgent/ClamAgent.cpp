#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <cstdio> // For _popen, _pclose, fgets

#pragma comment(lib, "ws2_32.lib")

// A helper function to remove newline characters from the received path.
void trim_newlines(std::string& str) {
    str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());
    str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
}

/**
 * @brief Handles a single client's entire session, allowing for multiple scan requests
 *        over the same socket until the client sends "QUIT".
 * @param client_socket The socket for the connected client.
 */
void handle_persistent_scan_request(SOCKET client_socket) {
    // This inner loop handles multiple scan requests on the SAME connection.
    while (true) {
        char buffer[1024];
        int recv_len = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

        if (recv_len <= 0) {
            // This happens if the client closes the connection abruptly.
            std::cout << "Client closed the persistent connection." << std::endl;
            break; // Exit the loop to close the socket.
        }

        buffer[recv_len] = '\0';
        std::string command = buffer;
        trim_newlines(command);

        // Check for the special command to end the session.
        if (command == "QUIT") {
            std::cout << "Client sent QUIT command. Closing this connection." << std::endl;
            break;
        }

        // Otherwise, treat the command as a file path to scan.
        std::string& filepath = command;
        std::cout << "Received scan request for: \"" << filepath << "\"" << std::endl;

        // --- ClamAV Scan Logic ---
        // Use the full, quoted path to clamscan.exe for reliability.
        std::string clamscan_exe_path = "\"D:\\ClamAV\\clamav-1.4.3.win.x64\\clamscan.exe\"";
        std::string cmd_to_run = clamscan_exe_path + " --no-summary \"" + filepath + "\"";

        FILE* pipe = _popen(cmd_to_run.c_str(), "r");
        std::string output;
        if (!pipe) {
            output = "ERROR";
        }
        else {
            char result_buf[256];
            while (fgets(result_buf, sizeof(result_buf), pipe)) {
                output += result_buf;
            }
            _pclose(pipe);
        }

        // --- Response Logic ---
        std::string response;
        if (output.find("FOUND") != std::string::npos)       response = "INFECTED";
        else if (output.find("OK") != std::string::npos)      response = "OK";
        else if (output.find("Empty file") != std::string::npos) response = "OK"; // Treat empty as OK
        else                                                  response = "UNKNOWN_ERROR";

        std::cout << "Scan complete. Sending result: " << response << std::endl;
        send(client_socket, response.c_str(), static_cast<int>(response.size()), 0);
    }

    // After the loop ends, clean up this client's connection.
    closesocket(client_socket);
    std::cout << "--------------------------------------\n";
}



int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) return 1;

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(3310);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(server_socket);
        return 1;
    }

    // Use SOMAXCONN for the standard maximum number of pending connections.
    listen(server_socket, SOMAXCONN);
    std::cout << "ClamAV Agent (Persistent Connection Mode) listening on port 3310..." << std::endl;

    // --- The Main Server Loop ---
    // This outer loop allows the agent to handle clients indefinitely.
    while (true) {
        std::cout << "Waiting for a new client connection..." << std::endl;
        SOCKET client_socket = accept(server_socket, nullptr, nullptr);

        if (client_socket == INVALID_SOCKET) {
            std::cerr << "Accept failed. Continuing to wait for next connection." << std::endl;
            continue;
        }

        std::cout << "Accepted new connection. Handing off to request handler..." << std::endl;
        handle_persistent_scan_request(client_socket);
    }

    closesocket(server_socket);
    WSACleanup();
    return 0;
}
