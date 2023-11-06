// This script demonstrates a simple usage of OpenSSL library in C++
// To compile the script (on MacOS):
// g++ -std=c++17 -Wall -Wextra my_https_simple.cpp -lcrypto -lssl -o my_https_simple

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

#include <iostream>
#include <time.h>
#include <cstring>
#include <string>

#include <openssl/crypto.h>
#include <openssl/x509.h>       /* Certificates */
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std::string_literals;

inline static void ReportAndExit(std::string&& err_msg){
    std::cerr << err_msg;
    ERR_print_errors_fp(stderr);
    std::exit(1);
}

inline static void InitOpenSSL(){
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

SOCKET CreateConnectionSocket(const char* hostname, const char* port){
    addrinfo hints, *conn_addr;
    memset(&hints, 0x00, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    std::cerr << "[i] Configuring remote address for "s << hostname << ':' << port << '\n';
    if (getaddrinfo(hostname, port, &hints, &conn_addr) != 0){
        std::cerr << "[!] Failed to configure a remote address: getaddrinfo(): "s << std::system_category().message(GETSOCKETERRNO()) << std::endl;
        return -1;
    }

    std::cerr << "[i] Creating a connection socket...\n"s;
    SOCKET conn_socket = socket(conn_addr->ai_family, conn_addr->ai_socktype, conn_addr->ai_protocol);
    if (!ISVALIDSOCKET(conn_socket)){
        std::cerr << "[!] Failed to create a connection socket: socket(): "s << std::system_category().message(GETSOCKETERRNO()) << std::endl;
        return -1;
    }

    // Get readable connection information
    char addr_buff[INET_ADDRSTRLEN];
    char service_buff[100];
    bzero(&addr_buff, sizeof(addr_buff));
    bzero(&service_buff, sizeof(service_buff));
    getnameinfo(conn_addr->ai_addr, conn_addr->ai_addrlen, addr_buff, sizeof(addr_buff), service_buff, sizeof(service_buff), NI_NUMERICHOST);

    std::cerr << "[i] Trying to connect to remote host ("s << addr_buff << ':' << service_buff << ")...\n"s;
    if (connect(conn_socket, conn_addr->ai_addr, conn_addr->ai_addrlen) == -1){
        std::cerr << "[!] Failed to connect to the remote host: connect(): "s << std::system_category().message(GETSOCKETERRNO()) << std::endl;
        return -1;
    }

    std::cerr << "[i] Established TCP connection with "s << addr_buff << ':' << service_buff << std::endl;
    freeaddrinfo(conn_addr);
    return conn_socket;
}

SSL* EstablishSSLConnection(SOCKET conn_socket, SSL_CTX* ssl_context, const char* remote_host){
    SSL* ssl = SSL_new(ssl_context);
    if (!ssl){ 
        ReportAndExit("[!] Failed to create a new SSL connection: SSL_new(): "s);
    }

    if (!SSL_set_tlsext_host_name(ssl, remote_host)){ // Set the SSL to a particular hostname (SNI protocol usage, i.e. instead of sending all available certificates, the server sends only the requested one)
        ReportAndExit("[!] Failed to set TLS hostname: SSL_set_tlsext_host_name(): "s);
    }

    SSL_set_fd(ssl, conn_socket); // Add a socket to a SSL connecting context
    if (SSL_connect(ssl) == -1){
        ReportAndExit("[!] Failed to connect to SSL to the remote host: SSL_connect(): "s);
    }
    std::cerr << "[i] SSL/TLS uses cipher: "s << SSL_get_cipher(ssl) << '\n';

    return ssl;
}

void ConfirmRemoteCertificate(SSL* ssl_conn){
    X509* certificate = SSL_get_peer_certificate(ssl_conn);
    if (!certificate){
        ReportAndExit("[!] Failed to get remote host certificate: SSL_get_peer_certificate(): "s);
    }

    char* tmp_str;
    if ((tmp_str = X509_NAME_oneline(X509_get_subject_name(certificate), 0, 0))){
        std::cerr << "[i] Certificate's subject (host): "s << tmp_str << '\n';
        OPENSSL_free(tmp_str);
    }

    if ((tmp_str = X509_NAME_oneline(X509_get_issuer_name(certificate), 0, 0))){
        std::cerr << "[i] Certificate's issuer (authority): "s << tmp_str << '\n';
        OPENSSL_free(tmp_str);
    }
    X509_free(certificate);
}



int main(int argc, char* argv[]){
    if (argc != 3){
        std::cerr << "[Usage] my_https_simple.cpp <remote address> <remote port>"s << std::endl;
        return 1;
    }
#ifdef _WIN32
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)){
        std::cerr << "[!] Failed to initialize WinSockAPI: "s << std::system_category().message(GETSOCKETERRNO()) << std::endl;
        return 1;
    }
#endif

    InitOpenSSL();

    const char* hostname = argv[1];
    const char* port = argv[2]; // Default HTTPS port is 443

    SOCKET conn_socket = CreateConnectionSocket(hostname, port);

    // Create a new SSL context (like a SSL connection factury)
    SSL_CTX* ssl_context = SSL_CTX_new(TLS_client_method());
    if (!ssl_context){
        ReportAndExit("[!] Failed to create a new SSL context: SSL_CTX_new(): "s);
    }

    SSL* ssl = EstablishSSLConnection(conn_socket, ssl_context, hostname);

    ConfirmRemoteCertificate(ssl);

    // Now we are ready to send HTTP over the secure TLS channel

    std::string request_buff;
    request_buff.reserve(2048);

    request_buff.append("GET / HTTP/1.1\r\n"s);
    request_buff.append("Connection: close\r\n"s);
    request_buff.append("Host: "s + std::string(hostname) + ":"s + std::string(port) + "\r\n"s);
    request_buff.append("User-Agent: https-simple\r\n\r\n"s);

    SSL_write(ssl, request_buff.data(), static_cast<int>(request_buff.size()));

    std::cerr << "[i] Sent HTTP headers:\n"s << request_buff << '\n';
    request_buff.clear();

    char response_buff[2048];
    bzero(&response_buff, sizeof(response_buff));
    // Wait for the response from the remote host
    while (true){
        int recv_bytes = SSL_read(ssl, response_buff, sizeof(response_buff));
        if (recv_bytes <= 0){
            if (recv_bytes == 0){
                std::cerr << "[i] Connection closed by the remote host."s << std::endl;
            }
            else if (recv_bytes == -1){
                std::cerr << "[i] Failed to receive data from the remote host: SSL_read(): "s << std::system_category().message(GETSOCKETERRNO()) << std::endl;
            }
            break;
        }

        std::cerr << "[i] Received "s << recv_bytes << " bytes. Response:\n"s << response_buff << std::endl;
    }

    std::cerr << "[i] Closing connection socket...\n"s;

    SSL_shutdown(ssl);
    CLOSESOCKET(conn_socket);
    SSL_free(ssl);
    SSL_CTX_free(ssl_context);

#ifdef _WIN32
    WSACleanup();
#endif

    std::cerr << "[i] Bye!"s << std::endl;
}
