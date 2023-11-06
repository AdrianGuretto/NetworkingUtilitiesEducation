#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <errno.h>
#endif

/* Networking cross-platform macros */
#ifdef _WIN32
    #define CLOSE_SOCKET(s) closesocket(s)
    #define IS_VALID_SOCKET(s) ((s) != INVALID_SOCKET)
    #define GET_SOCKET_ERROR(s) (WSAGetLastError()) 
#else
    #define CLOSE_SOCKET(s) close(s)
    #define IS_VALID_SOCKET(s) ((s) >= 0)
    #define GET_SOCKET_ERROR(s) (errno)
    #define SOCKET int
#endif  

#include <iostream>
#include <string>
#include <cstring>

using namespace std::string_literals;

#define MAX_INPUT_SIZE 512
#define MAX_RESPONSE_LENGTH 1024

inline static std::string GetInput(std::string&& input_prompt){
    char line[MAX_INPUT_SIZE];

    std::cout << input_prompt;
    std::cout.flush();

    std::cin.getline(line, MAX_INPUT_SIZE);
    return line;
}

int SendData(SOCKET socketfd, std::string&& message){
    int total_bytes = message.size();
    int sent_bytes = 0;
    int tmp_var;
    while (sent_bytes < total_bytes){
        tmp_var = send(socketfd, message.data(), total_bytes - sent_bytes, 0);
        if (tmp_var == -1){
            std::exit(1);
        }
        sent_bytes += tmp_var;
    }

    std::cout << "C: "s << message << '\n';

    return 0;
}

SOCKET CreateConnectionSocket(const char* hostname, const char* port){
    addrinfo hints, *conn_addr;
    memset(&hints, 0x00, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    std::cerr << "[i] Configuring remote address (hostname: "s << hostname << ", port: "s << port << ")...\n"s;
    if (getaddrinfo(hostname, port, &hints, &conn_addr) != 0){
        std::cerr << "[!] Failed to configure remote address: getaddrinfo(): "s << std::system_category().message(GET_SOCKET_ERROR()) << std::endl;
        return -1;
    }

    std::cerr << "[i] Creating connection socket...\n"s;
    SOCKET conn_socket = socket(conn_addr->ai_family, conn_addr->ai_socktype, conn_addr->ai_protocol);
    if (!IS_VALID_SOCKET(conn_socket)){
        std::cerr << "[!] Failed to create connection socket: socket(): "s << std::system_category().message(GET_SOCKET_ERROR()) << std::endl;
        return -1;
    }

    std::cerr << "[i] Trying to connect to "s << hostname << ':' << port << '\n';
    if (connect(conn_socket, conn_addr->ai_addr, conn_addr->ai_addrlen) == -1){
        std::cerr << "[!] Failed to connect to the remote host: connect(): "s << std::system_category().message(GET_SOCKET_ERROR()) << std::endl;
        return -1;
    }

    std::cerr << "[i] Successfully connected to "s << hostname << ':' << port << '\n';
    freeaddrinfo(conn_addr);

    return conn_socket;
}

int ParseResponseCode(const char* response_buff){
    // /*response type 1*/
    
    // 250 Message received!

    // /*response type 2*/

    // 250-Message
    // 250 received!

    if (strlen(response_buff) == 0){
        return 0;
    }
    if (!response_buff[0] && !response_buff[1] && !response_buff[2]){ // check whether the response is long enough to store the code
        return 0;
    }

    const char* ptr = response_buff;
    for (; ptr[3]; ++ptr){
        if (ptr == response_buff || ptr[-1] == '\n'){ // check whether the beginning of the string is the same as of the origi
            if (std::isdigit(ptr[0]) && std::isdigit(ptr[1]) && std::isdigit(ptr[2])){
                if (ptr[3] != '-'){
                    if (strstr(ptr, "\r\n")){ // find the end of the response
                        return strtol(ptr, 0, 10); // find the number and return a formed version of it.
                    }
                }
            }
        }
    }
    return 0;
}

int WaitForResponse(SOCKET conn_socketfd, const int expected_code){
    char response_buff[MAX_RESPONSE_LENGTH + 1];
    bzero(&response_buff, sizeof(response_buff));
    
    char* curr_ptr = response_buff;
    char* end_ptr = response_buff + MAX_RESPONSE_LENGTH;
    
    int code = 0;

    do{
        int recv_bytes = recv(conn_socketfd, curr_ptr, end_ptr - curr_ptr, 0);
        if (recv_bytes <= 0){
            if (recv_bytes == 0){
                std::cerr << "[i] Connection has been closed by the server."s << std::endl;
            } 
            else if (recv_bytes == -1){
                std::cerr << "[!] Failed to read data from the server: recv(): "s << std::system_category().message(GET_SOCKET_ERROR()) << std::endl;
                std::cerr << "[i] Closing the connection.\n"s;
            }
            std::exit(1);
        }

        curr_ptr += recv_bytes;
        *curr_ptr = 0x00; // null-terminate the string

        if (curr_ptr == end_ptr){
            std::cerr << "[!] Server response is too large ("s << end_ptr - curr_ptr << " bytes: \n"s << response_buff << std::endl;
            std::exit(1);
        }

        code = ParseResponseCode(response_buff);
    } while (code == 0);

    if (code != expected_code){
        std::cerr << "[i] Error from the server ( CODE: "s << code << " )\n"s;
        std::cerr << "[i] "s << response_buff << std::endl;
        std::exit(1);
    }

    std::cout << "S: "s << response_buff << '\n';

    return code;
}

int main(){
#ifdef _WIN32
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)){
        std::cerr << "[i] Failed to initialize WinSockAPI: "s << std::system_category().message(GET_SOCKET_ERROR()) << std::endl;
        return 1;
    }
#endif

    std::string hostname(GetInput("Enter address of the mail server: "s));
    SOCKET conn_socket = CreateConnectionSocket(hostname.data(), "25"); // 25 is a default port for the SMTP
    if (!IS_VALID_SOCKET(conn_socket)){
        return 1;
    }

    WaitForResponse(conn_socket, 220); // Wait for the server to tell us it is ready for incoming data

    SendData(conn_socket, "HELO HONPWC"s); // Say hello to the server and indicate that our machine doesn't have a domain address
    WaitForResponse(conn_socket, 250); // Server has received our hello message

    // Sending the sender name
    std::string from_n(GetInput("From: "s));
    SendData(conn_socket, "MAIL FROM:<"s + from_n + ">\r\n"s);
    WaitForResponse(conn_socket, 250);

    // Sending the receipient name
    std::string to_n(GetInput("To: "s));
    SendData(conn_socket, "RCPT TO:<"s + to_n + ">\r\n"s);
    WaitForResponse(conn_socket, 250);

    // Sending the subject
    SendData(conn_socket, "DATA\r\n"s);
    WaitForResponse(conn_socket, 354);

    std::string subject_n(GetInput("Subject: "s));

    SendData(conn_socket, "From:<"s + from_n + ">\r\n"s);
    SendData(conn_socket, "To:<"s + to_n + ">\r\n"s);
    SendData(conn_socket, "Subject:"s + subject_n + "\r\n"s);

    // Create a timestamp for the email.
    time_t timer;
    std::time(&timer);
    tm* timeinfo;
    timeinfo = std::gmtime(&timer);
    char date[128];
    std::strftime(date, 128, "%a, %d %b %Y %H:%M:%S +0000", timeinfo);

    SendData(conn_socket, "Date:"s + std::string(date) + "\r\n"s);
    SendData(conn_socket, "\r\n"s);

    std::cout << "[i] Enter your email body and end it with a dot ('.') on a new line.\n"s;
    std::cout.flush();
    
    while (true){
        std::string line(GetInput("> "s));
        SendData(conn_socket, line + "\r\n"s);
        if (line == "."s){
            break;
        }
    }

    WaitForResponse(conn_socket, 250);

    SendData(conn_socket, "QUIT\r\n"s);
    WaitForResponse(conn_socket, 221);

    std::cerr << "[i] Closing connection..."s << std::endl;
    CLOSE_SOCKET(conn_socket);
#ifdef _WIN32
    WSACleanup();
#endif
    std::cerr << "[i] Bye"s << std::endl;
}