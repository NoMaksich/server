#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <netinet/in.h>
#include <sys/socket.h>

#define BUFLEN 1024

class Server {
public:
    Server(unsigned short port, int qlen, const std::string& db);
    void connecting();
    void get_base(const std::string& db_file);
    //std::string md5h(const std::string& salt, const std::string& pass);
    bool authentication(int work_sock, const std::unordered_map<std::string, std::string>& credentials);
    //std::string identifyUser(const std::string& username);
    float quad(int work_sock);
    std::string str_read(int work_sock);
    ~Server();
    void startListening(Server & server);
private:
    std::string db_file;
    std::unordered_map<std::string, std::string> userCredentials;
    //std::string generation_salt();
    int work_sock;
    int sock;
    std::string login;
    std::string password;
    std::unique_ptr<sockaddr_in> self_addr;
    std::unique_ptr<sockaddr_in> foreign_addr;
    int queueLen;
    void operator()(int sock);
};
