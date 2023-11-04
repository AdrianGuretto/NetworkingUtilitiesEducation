#include "defines.h"

#include <string>
#include <unordered_map>
#include <iostream>
#include <filesystem>
#include <fstream>


using namespace std::string_literals; /* String optimizations */

#define MAX_REQUEST_SIZE 2047
#define RESOURCE_PATH_MAX_LENGTH 12
#define HEADER_BUFFER_SIZE 1028

struct client_info{
    socklen_t addr_length;
    sockaddr_storage address;
    SOCKET client_socket;
    char request_buffer[MAX_REQUEST_SIZE + 1]; // + 1 for null-terminating character
    int received_bytes = 0;
    std::string ip_address_str;
    client_info* next_client = nullptr;
};


static std::string GetClientIPAddress(sockaddr_storage* conn_address){
    char address[INET6_ADDRSTRLEN];
    memset(&address, 0, sizeof(address));

    int port = 0;

    if (conn_address->ss_family == AF_INET) { // IPv4
        sockaddr_in* addr_inf = reinterpret_cast<sockaddr_in*>(conn_address);
        inet_ntop(AF_INET, &addr_inf->sin_addr, address, INET_ADDRSTRLEN);
        port = ntohs(addr_inf->sin_port);
    } else if (conn_address->ss_family == AF_INET6) { // IPv6
        sockaddr_in6* addr_inf = reinterpret_cast<sockaddr_in6*>(conn_address);
        inet_ntop(AF_INET6, &addr_inf->sin6_addr, address, INET6_ADDRSTRLEN);
        port = ntohs(addr_inf->sin6_port);
    }
   
    return std::string(std::string(address).append(":"s) + std::to_string(port));
}

class HTTP_Server{
public:
    explicit HTTP_Server(const char* hostname, const char* port) : hostname_(hostname), port_(port) {}


    explicit HTTP_Server(const HTTP_Server& other) = delete;
    HTTP_Server& operator=(const HTTP_Server& other) = delete;

    ~HTTP_Server(){
        Shutdown();
    }
public:

    int Start() noexcept{
        server_socket_ = CreateServerSocket(hostname_.data(), port_.data());
        if (!IS_VALID_SOCKET(server_socket_)){
            return -1;
        }

        return HandleConnections();
    }

    void Shutdown() noexcept{
        std::cerr << "[i] Shutting down the server...\n"s;
        CLOSE_SOCKET(server_socket_);
        std::cerr << "[i] Bye!\n"s;
    }

private:

    // Read data from the connected socket on `server` and write ready sockets to `reads_set`.
    // @return 0 on success, -1 on error with `errno` set.
    int GetReadySockets(SOCKET server, fd_set* reads_set) noexcept{
        FD_ZERO(reads_set);
        FD_SET(server, reads_set);

        SOCKET max_socket = server;
        // Populate the socket set and determine if there is a client with a bigger socket
        client_info* cl_ptr = clients_;

        while (cl_ptr){
            FD_SET(cl_ptr->client_socket, reads_set);
            if (cl_ptr->client_socket > max_socket){
                max_socket = cl_ptr->client_socket;
            }
            cl_ptr = cl_ptr->next_client;
        }

        if (select(max_socket + 1, reads_set, NULL, NULL, NULL) == -1){
            std::cerr << "[!] Failed to read data from the connected sockets: select(): "s << std::system_category().message(GET_LAST_SOCK_ERROR()) << std::endl;
            return -1;
        }

        return 0;
    }

    int Send400Code(client_info* client) noexcept{
        // clang-format off
        static const std::string response_str = 
        "HTTP/1.1 400 Bad Request\r\n" 
        "Connection: close\r\n"
        "Content-Length: 11\r\n\r\nBad Request";
        // clang-format on

        SendWholeMessageData(client, response_str);
        DisconnectClient(client);

        return 0;
    }
    int Send404Code(client_info* client) noexcept{
        // clang-format off
        static const std::string response_str = 
        "HTTP/1.1 404 Not Found\r\n" 
        "Connection: close\r\n"
        "Content-Length: 9\r\n\r\nNot Found";
        // clang-format on
        
        SendWholeMessageData(client, response_str);
        DisconnectClient(client);
        return 0;
    }

    // Makes sure that all bytes from `message_to_send` has been sent to `client`
    // @return 0 on success, -1 on error with `errno` set.
    int SendWholeMessageData(const client_info* client, const std::string& message_to_send) const noexcept{
        int total_bytes = message_to_send.size();
        int bytes_sent = 0;
        int tmp;

        while (total_bytes > bytes_sent){
            tmp = send(client->client_socket, message_to_send.data() + bytes_sent, total_bytes - bytes_sent, 0);
            if (tmp == -1){
                std::cerr << "[!] Failed to send message to ("s << client->ip_address_str << ") : send(): "s << std::system_category().message(GET_LAST_SOCK_ERROR()) << std::endl;
                return -1;
            }    
            bytes_sent += tmp;
        }

        return 0;
    }

    // Receive and process incoming data from the clients.
    // @return 0 on successful exit, -1 on error with `errno` set.
    int HandleConnections() noexcept{
        if (!IS_VALID_SOCKET(server_socket_)){
            std::cerr << "[!] Server has a broken connection socket."s << std::endl;
            return -1;
        }

        while(true){
            fd_set reads;
            if (GetReadySockets(server_socket_, &reads) == -1){
                return -1;
            }


            // Data on the server socket  = new connection
            if (FD_ISSET(server_socket_, &reads)){ 
                client_info* new_client = GetClient(-1); // since -1 is an invalid socket, this function will initialize a new client.

                new_client->client_socket = accept(server_socket_, reinterpret_cast<sockaddr*>(&(new_client->address)), reinterpret_cast<socklen_t*>(&(new_client->addr_length)));
                new_client->ip_address_str = GetClientIPAddress(&new_client->address);

                std::cout << "[+] New connection from "s << new_client->ip_address_str << '\n';
                
                if (!IS_VALID_SOCKET(new_client->client_socket)){
                    std::cerr << "[!] Failed to accept a new connection ("s << new_client->ip_address_str <<  "): accept(): "s << std::system_category().message(GET_LAST_SOCK_ERROR()) << std::endl;
                    return -1;
                }
            }

            client_info* client_ptr = clients_;
            while (client_ptr){
                client_info* next_client_ptr = client_ptr->next_client;

                if (FD_ISSET(client_ptr->client_socket, &reads)){
                    if (client_ptr->received_bytes >= MAX_REQUEST_SIZE){
                        std::cerr << "[i] Client "s << client_ptr->ip_address_str << " has exceeded the maximum request size limit (" << client_ptr->received_bytes << " / "s << MAX_REQUEST_SIZE << ")\n"s;
                        Send400Code(client_ptr);
                        client_ptr = next_client_ptr;
                        continue;
                    }

                    int recv_bytes_tmp = recv(client_ptr->client_socket, client_ptr->request_buffer + client_ptr->received_bytes, MAX_REQUEST_SIZE - client_ptr->received_bytes, 0);
                    if (recv_bytes_tmp <= 0){
                        if (recv_bytes_tmp == 0){
                            std::cerr << "[-] Client "s << client_ptr->ip_address_str << " has disconnected\n"s;
                        } else if (recv_bytes_tmp == -1){
                            std::cerr << "[!] Failed to receive request from " << client_ptr->ip_address_str << " : recv(): "s << std::system_category().message(GET_LAST_SOCK_ERROR()) << std::endl;
                        }
                        DisconnectClient(client_ptr);
                    }
                    else{
                        
                        client_ptr->received_bytes += recv_bytes_tmp;
                        client_ptr->request_buffer[client_ptr->received_bytes] = 0x00;

                        char* req_end = strstr(client_ptr->request_buffer, "\r\n\r\n");
                        if (req_end){
                            *req_end = 0x00;
                            if (strncmp("GET /", client_ptr->request_buffer, 5)){ // Only serve GET requests
                                std::cerr << "[i] "s << client_ptr->ip_address_str << " has made a forbidden request."s << std::endl;
                                Send400Code(client_ptr);
                            }
                            else{
                                char* path_begin = client_ptr->request_buffer + 4; // Skip the request type part
                                char* path_end = strstr(path_begin, " ");
                                if (!path_end){
                                    std::cerr << "[i] Could not determine requested path from "s << client_ptr->ip_address_str << std::endl;
                                    Send400Code(client_ptr);
                                }
                                else{
                                    *path_end = 0x00; // null-terminate the path string
                                    std::cout << "[i] " << client_ptr->ip_address_str << " requested: "s << client_ptr->request_buffer << "\n\n"s;
                                    ServeResource(client_ptr, path_begin);
                                }
                            }
                        }
                    }
                }
                client_ptr = next_client_ptr;
            }
        }
    }

    int ServeResource(client_info* client, const std::string& requested_path){
        
        if (requested_path.size() > RESOURCE_PATH_MAX_LENGTH){ // If the requested path is too long then it is either a bad request or a malicios code, or something in this manner.
            std::cerr << "[i] Resource max_length is exceeded by "s << client->ip_address_str << std::endl;
            Send400Code(client);
            return 0;
        } 
        if (requested_path.find(".."s) != requested_path.npos){ // Make sure that a client cannot access our root directory
            std::cerr << "[i] Forbidden resource path by "s << client->ip_address_str << std::endl;
            Send404Code(client);
            return 0;
        }

        std::filesystem::path resource_path("public"s);
        resource_path.append(requested_path);
        if (requested_path == "/"s){
            resource_path = std::filesystem::path("public"s).append("index.html"s);
        }
        if (!std::filesystem::exists(resource_path)){
            Send404Code(client);
            return 0;
        }
        std::cout << "[i] Serving resource at \""s << requested_path << "\" to "s << client->ip_address_str << '\n';
        std::ifstream requested_file(resource_path);
        if (!requested_file.is_open()){
            Send404Code(client);
        }

        const size_t file_size = std::filesystem::file_size(resource_path);
        const std::string content_type = GetContentType(resource_path.string().c_str());

        // Crafting header response
        std::string header_buffer_str;
        header_buffer_str.reserve(HEADER_BUFFER_SIZE);

        std::cerr << "=============== TO "s << client->ip_address_str << "===============\n"s;
        header_buffer_str.append("HTTP/1.1 200 OK\r\n"s);
        header_buffer_str.append("Connection: close\r\n"s);
        header_buffer_str.append("Content-Length: "s + std::to_string(file_size) + "\r\n"s);
        header_buffer_str.append("Content-Type: "s + std::string(content_type.data()) + "\r\n\r\n"s);

        if (SendWholeMessageData(client, header_buffer_str.data()) == -1){
            return -1;
        }
        std::cerr << header_buffer_str;
        std::cerr << "=============== END ===============\n\n"s;
        
        // Fetching data from the file and sending it to the client
        std::string line;
        while (std::getline(requested_file, line)){
            std::cerr << "Sending file data: "s << line.size() << " bytes\n"s; 
            if (SendWholeMessageData(client, line) == -1){
                return -1;
            }
        }

        return 0;
    }



    // Searches for the client with socket `sock`; if not found, creates a new client_info structure and appends it to the beginning of the clients list.
    client_info* GetClient(SOCKET sock) noexcept{
        client_info* cl_ptr = clients_;

        while (cl_ptr){
            if (cl_ptr->client_socket == sock){
                return cl_ptr;
            }
            cl_ptr = cl_ptr->next_client;
        }

        client_info* new_client = reinterpret_cast<client_info*>(calloc(1, sizeof(client_info))); // Allocate zeroed out memory space for the new client.
        if (!new_client){
            std::cerr << "Failed to allocate memory for the new client." << std::endl;
            return nullptr;
        }

        new_client->addr_length = sizeof(new_client->address);
        
        // Append the newly created client to the beginning of the clients list.
        new_client->client_socket = sock;
        new_client->next_client = clients_;
        clients_ = new_client;

        return new_client;
    }

    void DisconnectClient(client_info* client) noexcept{
        CLOSE_SOCKET(client->client_socket);
        
        client_info** curr_ptr = &clients_;
        while (*curr_ptr){
            if (*curr_ptr == client){
                *curr_ptr = client->next_client;
                std::cerr << "[-] "s << client->ip_address_str << " has been disconnected.\n"s;
                free(client);
                return;
            }
            curr_ptr = &(*curr_ptr)->next_client;
        }

        std::cerr << "Could not disconnect client ("s << client->ip_address_str << "): Not found.\n"s;
    }



    static std::string GetContentType(const char* path) noexcept{
        const static std::unordered_map<std::string, std::string> extentions_to_mime_format = {
            {".css"s, "text/css"s},
            {".csv"s, "text/csv"s},
            {".gif"s, "image/gif"s},
            {".htm"s, "text/html"s},
            {".html"s, "text/html"s},
            {".ico"s, "image/x-icon"s},
            {".jpeg"s, "text/jpeg"s},
            {".jpg"s, "text/jpeg"s},
            {".js"s, "application/javascript"s},
            {".json"s, "application/json"s},
            {".pdf"s, "application/pdf"s},
            {".svg"s, "image/svg+xml"s},
            {".txt"s, "text/plain"s},
        };

        std::string path_str(path);
        size_t extention_end_pos = path_str.rfind('.');
        if (extention_end_pos != path_str.npos){
            std::string extention_str = path_str.substr(extention_end_pos);
            if (extentions_to_mime_format.count(extention_str)){
                return extentions_to_mime_format.at(extention_str);
            }
        }

        return "application/octet-stream"s;
    }

    static SOCKET CreateServerSocket(const char* hostname, const char* port) noexcept{
        std::cerr << "[i] Configuring server address...\n"s;

        addrinfo hints, *bind_address;
        
        memset(&hints, 0x00, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_INET;
        hints.ai_flags = AI_PASSIVE;

        if (getaddrinfo(hostname, port, &hints, &bind_address) != 0){
            std::cerr << "[!] Failed to configure server address: getaddrinfo(): "s << std::system_category().message(GET_LAST_SOCK_ERROR()) << std::endl;
            return -1;
        }

        SOCKET server_socket = socket(bind_address->ai_family, bind_address->ai_socktype, bind_address->ai_protocol);
        if (!IS_VALID_SOCKET(server_socket)){
            std::cerr << "[!] Failed to create server socket: socket(): "s << std::system_category().message(GET_LAST_SOCK_ERROR()) << std::endl;
            return -1;
        }

        int yes = 1;
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1){
            std::cerr << "[!] Failed to configure server socket: setsockopt(): "s << std::system_category().message(GET_LAST_SOCK_ERROR()) << std::endl;
            return -1;
        }

        if (bind(server_socket, bind_address->ai_addr, bind_address->ai_addrlen) == -1){
            std::cerr << "[!] Failed to bind server socket to address "s << hostname << ':' << port << " : "s << std::system_category().message(GET_LAST_SOCK_ERROR()) << std::endl;
            return -1;
        }
        freeaddrinfo(bind_address);

        if (listen(server_socket, 15) == -1){
            std::cerr << "[!] Failed to set up the server listenner: listen(): " << std::system_category().message(GET_LAST_SOCK_ERROR()) << std::endl;
            return -1;
        }

        std::cout << "[i] Server is listenning on "s << hostname << ':' << port << '\n';
        return server_socket;
    }



private:
    SOCKET server_socket_;
    const std::string hostname_, port_;
    client_info *clients_ = nullptr; /* Implementing linked-list for learning algorithms better */
};



int main(int argc, char* argv[]){
    if (argc < 3){
        std::cerr << "[Usage] web_server <hostname> <port>"s << std::endl;
        return 1;
    }
#ifdef _WIN32
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)){
        std::cerr << "Failed to initialize WinSockAPI: "s << std::system_category().message(GET_LAST_SOCK_ERROR()) << std::endl;
        return 1;
    }
#endif 

    HTTP_Server server(argv[1], argv[2]);

    if (server.Start() == -1){
        return 1;
    }

}