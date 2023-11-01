#include <string>
#include <iostream>
#include <cassert>

struct ParsedURL{
    std::string protocol;
    std::string hostname;
    std::string port = "Default";
    std::string path;
};

ParsedURL ParseURL(const std::string& raw_url){
    ParsedURL ret_struct;

    // Parsing URL's protocol
    size_t curr_pos = raw_url.find("://", 0);
    if (curr_pos == raw_url.npos){
        throw std::logic_error("URL is incorrect. Failed to parse protocol.");
    }
    ret_struct.protocol = raw_url.substr(0, curr_pos);
    if (ret_struct.protocol.empty()){
        throw std::logic_error("Failed to parse URL's protocol (empty).");
    }

    curr_pos += 3;
    size_t last_pos = curr_pos;

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
    if (ret_struct.hostname.empty()){
        throw std::logic_error("Failed to parse URL's hostname.");
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


    std::cout << "URL: " << raw_url << '\n';
    std::cout << "URL's protocol: " << ret_struct.protocol << '\n';
    std::cout << "URL's hostname: " << ret_struct.hostname << '\n';
    std::cout << "URL's port: " << ret_struct.port << '\n';
    std::cout << "URL's path: " << ret_struct.path << '\n';
    return ret_struct;
}

int main(){
    std::string url;
    std::getline(std::cin, url);

    try{
        ParseURL(url);
    } catch(std::exception& exc){
        std::cout << exc.what() << std::endl;
        return 1;
    }
}
