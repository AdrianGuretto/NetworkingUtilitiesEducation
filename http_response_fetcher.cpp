#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#endif


#if defined(_WIN32)
#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) closesocket(s)
#define GETSOCKETERRNO() (WSAGetLastError())

#else
#define ISVALIDSOCKET(s) ((s) >= 0)
#define CLOSESOCKET(s) close(s)
#define SOCKET int
#define GETSOCKETERRNO() (errno)
#endif


#include <string>
#include <iostream>


#define TIMEOUT 5.0
#define MAX_RESPONSE_SIZE 8192

using namespace std::string_literals;

struct ParsedURL{
    std::string protocol;
    std::string hostname;
    std::string port = "80";
    std::string path;
};

ParsedURL ParseURL(const std::string& raw_url){
    ParsedURL ret_struct;

    // Parsing URL's protocol
    size_t curr_pos = raw_url.find("://", 0);
    size_t last_pos = 0;
    if (curr_pos == raw_url.npos){
        ret_struct.protocol = "http"s;
    } else{
        ret_struct.protocol = raw_url.substr(0, curr_pos);
        curr_pos += 3;
        last_pos = curr_pos;
    }


    // If there is a port with the hostname address
    curr_pos = raw_url.find_first_of(":/#", curr_pos);
    if (curr_pos != raw_url.npos){
        if (raw_url[curr_pos] == ':'){
            size_t port_end = raw_url.find_first_of("/#", curr_pos + 1);
            ret_struct.port = raw_url.substr(curr_pos + 1, port_end - curr_pos - 1);
            ret_struct.hostname = raw_url.substr(last_pos, curr_pos - last_pos);
            curr_pos = port_end;
        } else{
            ret_struct.hostname = raw_url.substr(last_pos, curr_pos - last_pos);
        }
    } 
    else {
        ret_struct.hostname = raw_url.substr(last_pos);
        ret_struct.path = "/"s;
        return ret_struct;
    }

    last_pos = curr_pos;
    curr_pos += 1;

    curr_pos = raw_url.find_first_of("/#");
    if (curr_pos != raw_url.npos){
        if (raw_url[curr_pos] == '/'){
            curr_pos = raw_url.find('#', curr_pos + 1);
            ret_struct.path = raw_url.substr(last_pos, curr_pos - last_pos + 1);
        }
    } else {
        std::string path(raw_url.substr(last_pos, curr_pos - last_pos + 1));
        ret_struct.path = (path.empty() ? "/page1.htm" : path);
    }

    if (ret_struct.protocol == "http") ret_struct.port = "80";

    std::cout << "URL: " << raw_url << '\n';
    std::cout << "URL's protocol: " << ret_struct.protocol << '\n';
    std::cout << "URL's hostname: " << ret_struct.hostname << '\n';
    std::cout << "URL's port: " << ret_struct.port << '\n';
    std::cout << "URL's path: " << ret_struct.path << '\n';
    return ret_struct;
}
 
int SendRequest(SOCKET socketfd, const ParsedURL& parsed_url){
    std::string request;
    request.append("GET "s + parsed_url.path + " HTTP/1.1\r\n"s);
    request.append("Host: "s + parsed_url.hostname + ":"s + parsed_url.port + "\r\n"s);
    request.append("Connection: close\r\n"s);
    request.append("User-Agent: honpwc web_get 1.0\r\n");
    request.append("\r\n");

    if (send(socketfd, request.data(), request.size(), 0) == -1){
        std::cerr << "SendRequest() failed: send(): " << std::system_category().message(GETSOCKETERRNO());
        return -1;
    }

    std::cout << "Sent headers: \n"s << request;
    return 0;
}

SOCKET ConnectToHost(const std::string& hostname, const std::string& port){
    const std::string interpreted_port = (port == "Default"s ? "80"s : port);

    std::cerr << "[i] Configuring remote address ("s << hostname << ", "s << interpreted_port << ")\n"s;
    addrinfo hints, *conn_addr;
    memset(&hints, 0x00, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.data(), interpreted_port.data(), &hints, &conn_addr) != 0){
        std::cerr << "ConnectToHost() failed: getaddrinfo(): "s << std::system_category().message(GETSOCKETERRNO()) << std::endl;
        return -1;
    }

    char ip_addr[INET6_ADDRSTRLEN];
    char port_str[100];
    getnameinfo(conn_addr->ai_addr, conn_addr->ai_addrlen, ip_addr, sizeof(ip_addr), port_str, sizeof(interpreted_port), NI_NUMERICHOST);
    std::cerr << "[i] Remote host's address is "s << ip_addr << ":"s << port_str << '\n';

    std::cerr << "[i] Creaing connection socket...\n"s;
    SOCKET conn_socket = socket(conn_addr->ai_family, conn_addr->ai_socktype, conn_addr->ai_protocol);
    if (!ISVALIDSOCKET(conn_socket)){
        std::cerr << "ConnectToHost() failed: socket(): "s << std::system_category().message(GETSOCKETERRNO()) << std::endl;
        return -1;
    }

    std::cerr << "[i] Connecting to the remote host...\n"s;
    if (connect(conn_socket, conn_addr->ai_addr, conn_addr->ai_addrlen) == -1){
        std::cerr << "ConnectToHost() failed: connect(): "s << std::system_category().message(GETSOCKETERRNO()) << std::endl;
        return -1;
    }

    std::cerr << "[i] Connected to the remote host!\n"s;
    freeaddrinfo(conn_addr);
    return conn_socket;
}

int DisplayHostResponse(SOCKET conn_socket){
    const clock_t response_wait_start_time = clock();

#define MAX_RESPONSE_LENGTH 8192
    char response_buffer[MAX_RESPONSE_SIZE + 1];
    memset(response_buffer, 0x00, sizeof(response_buffer));
    
    char* curr_ptr = response_buffer, *search_ptr;
    
    char* resp_buff_end_ptr = response_buffer + MAX_RESPONSE_SIZE;
    char* body_ptr = 0x00; // Null-terminating

    enum { length, chuncked, connection }; // Content-encoding types

    int encoding_type = 0;
    int remaining_bytes = 0;

    while (true){
        
        if ((clock() - response_wait_start_time) / CLOCKS_PER_SEC > TIMEOUT){
            std::cerr << "HTTP Remote Host response has timed out."s << std::endl;
            return -2;
        }

        fd_set reads;
        FD_ZERO(&reads);
        FD_SET(conn_socket, &reads);

        timeval select_timeout{.tv_sec = 0, .tv_usec = 200000};

        if (select(conn_socket + 1, &reads, nullptr, nullptr, &select_timeout) < 0){
            std::cerr << "Failed to read data from the connection socket: select(): "s << std::system_category().message(GETSOCKETERRNO()) << std::endl;
            return -1;
        }

        if (FD_ISSET(conn_socket, &reads)){

            int recved_bytes = recv(conn_socket, curr_ptr, resp_buff_end_ptr - curr_ptr, 0);
            if (recved_bytes <= 0){
                if (encoding_type == connection && body_ptr){
                    printf("%.*s", static_cast<int>(resp_buff_end_ptr - body_ptr), body_ptr);
                }
                if (recved_bytes == 0){
                    std::cerr << "Connection has been closed by the remote host."s << std::endl;
                }
                else if (recved_bytes == -1){
                    std::cerr << "Failed to receive data from the remote host: recv(): "s <<std::system_category().message(GETSOCKETERRNO()) << std::endl;
                }
                return recved_bytes;
            }

            curr_ptr += recved_bytes;
            *curr_ptr = 0x00; // Null-terminate the response buffer.

            if (!body_ptr && (body_ptr = strstr(response_buffer, "\r\n\r\n"))){ // If we haven't received the body yet and the separating line is found
                *body_ptr = 0x00;
                body_ptr += 4; // Skip the separating line and set the pointer to the beginning of the body section

                std::cout << "Received HTTP headers: \n"s << response_buffer << '\n'; // Since 'body' var has null-terminated the response buffer.
                std::cout << "Received HTTP body: \n"s;

                search_ptr = strstr(response_buffer, "\nContent-length: ");
                if (search_ptr){
                    encoding_type = length;
                    search_ptr = strchr(search_ptr, ' '); // move the pointer to the beginning of the length number
                    search_ptr += 1;
                    remaining_bytes = strtol(search_ptr, 0, 10);
                }
                else{
                    search_ptr = strstr(response_buffer, "\nTransfer-Encoding: chunked");
                    if (search_ptr){
                        encoding_type = chuncked;
                        remaining_bytes = 0;
                    }
                    else{
                        encoding_type = connection;
                    }
                }
            }
            if (body_ptr){
                if (encoding_type == length){
                    if (curr_ptr - body_ptr >= remaining_bytes){
                        printf("%.*s", remaining_bytes, body_ptr);
                        break;
                    }
                }
                else if (encoding_type == chuncked){
                    do {
                        if (remaining_bytes == 0){
                            if ((search_ptr = strstr(body_ptr, "\r\n"))){ // Jump to separating lines and read lengths of chunks
                                remaining_bytes = strtol(body_ptr, 0, 16);
                                if (!remaining_bytes){
                                    return 1;
                                }
                                body_ptr = search_ptr + 2;
                            }
                            if (remaining_bytes && curr_ptr - body_ptr >= remaining_bytes){
                                printf("%.*s", remaining_bytes, body_ptr);
                                body_ptr += 2 + remaining_bytes;
                                remaining_bytes = 0;
                            }
                        }
                    } while (!remaining_bytes);
                }
            } // if (body_ptr)
        } // if (FD_ISSET)
    } // while (true)
    return 1;
}


int main(int argc, char* argv[]){
    if (argc != 2){
        std::cerr << "[Usage] http_response_fetcher <web-url>" << std::endl;
        return 1;
    }
#ifdef _WIN32
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)){
        std::cerr << "Failed to initialize WinSockAPI: " << std::system_category().message(GETSOCKETERRNO()) << std::endl;
        return 1;
    }
#endif

    ParsedURL parsed_url = ParseURL(argv[1]);
    SOCKET conn_socket = ConnectToHost(parsed_url.hostname, parsed_url.port);
    if (!ISVALIDSOCKET(conn_socket)){
        return 1;
    }

    if (SendRequest(conn_socket, parsed_url) == -1){
        return -1;
    }

    int response_status_code = DisplayHostResponse(conn_socket);
    if (response_status_code < 0){ // An error has occurred
        return 1;
    }

    CLOSESOCKET(conn_socket);

#ifdef _WIN32
    WSACleanup();
#endif
}
