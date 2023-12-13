#include "ErrorLog.h"
#include "Server.h"
#include <iostream>
#include <unistd.h>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <limits>
#include <random>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <sys/ioctl.h>
#include <cryptopp/filters.h>
#include <unordered_map>

using namespace std;

Server::Server(unsigned short port, int qlen, const string& db):
    sock(socket(AF_INET, SOCK_STREAM, 0)),
    self_addr(new sockaddr_in),
    foreign_addr(new sockaddr_in),
    queueLen(qlen)
{
    // check error for socket creation
    if (sock == -1)
        throw std::system_error(errno, std::generic_category(), "Socket error");

    int on = 1;
    // set socket for fast reusing when server restarting
    int rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (rc == -1)
        throw std::system_error(errno, std::generic_category(), "Socket error");

    // fill self address
    self_addr->sin_family = AF_INET;
    self_addr->sin_port = htons(port);
    self_addr->sin_addr.s_addr = INADDR_ANY;

    // bind listening socket for self address
    if (bind(sock,
             reinterpret_cast<const sockaddr*>(self_addr.get()),
             sizeof(sockaddr_in)) == -1)
        throw std::system_error(errno, std::generic_category(), "Bind error");
}

void Server::get_base(const string& db_file)
{
    try {
        ifstream database(db_file);
        if (!database.is_open()) {
            ErrorLog::logError(true, "Failed to open database file");
            return;
        }

        string line;
        while (getline(database, line)) {
            auto delimiterPos = line.find(':');
            if (delimiterPos != string::npos) {
                string identifier = line.substr(0, delimiterPos);
                string password = line.substr(delimiterPos + 1);
                userCredentials.emplace(identifier, password);
            } else {
                ErrorLog::logError(true, "Invalid database format");
            }
        }
        database.close();
    } catch (const exception& e) {
        cerr << "Error occurred in get_base(): " << e.what() << endl;
    }
}


bool Server::authentication(int work_sock, const unordered_map<string, string>& credentials) {
    try {
        int rc;
        std::mt19937_64 gen(time(nullptr));

        string userLogin = str_read(work_sock);
        auto it = credentials.find(userLogin);
        if (it == credentials.end())
            throw std::system_error(errno, std::generic_category(), "Auth error: unknown user");

        std::clog << "log: username ok\n";


        string password = it->second;

        // Генерация соли
        uint64_t rnd = gen();
        std::string salt, message;
        CryptoPP::StringSource((const CryptoPP::byte*)&rnd,
                            8,
                            true,
                            new CryptoPP::HexEncoder(new CryptoPP::StringSink(salt)));
        
        // Отправка соли
        rc = send(work_sock, salt.c_str(), salt.size(), 0);
        if (rc == -1)
            throw std::system_error(errno, std::generic_category(), "Send salt error");
        
        std::clog << "log: sending SALT " << salt << std::endl;

        // Получение хеша от пароля и соли
        CryptoPP::Weak1::MD5 hash;
        CryptoPP::StringSource(salt + password,
                            true,
                            new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(message))));
        
        std::clog << "log: waiting MESSAGE " << message << std::endl;

        // Сравнение полученного хеша с хешем пароля на сервере
        string userMessage = str_read(work_sock);
        if (userMessage != message)
            throw std::system_error(errno, std::generic_category(), "Auth error: password mismatch");
        
        std::clog << "log: auth success, sending OK\n";
        
        // Отправка подтверждения успешной аутентификации
        const char* authSuccess = "OK";
        rc = send(work_sock, authSuccess, strlen(authSuccess), 0);
        if (rc == -1)
            throw std::system_error(errno, std::generic_category(), "Send OK error");
        
        return true; // Успешная аутентификация
    } catch (const std::exception& e) {
        std::cerr << "Error in authentication(): " << e.what() << std::endl;
        ErrorLog::logError(true, std::string("Error in authentication(): ") + e.what());
        return false; // Ошибка аутентификации
    }
}

float Server::quad(int work_sock) {
    try {
        const int floatSize = sizeof(float);
        int numbersOfVectors = 0;

        // Получаем количество векторов
        int rc = recv(work_sock, reinterpret_cast<char*>(&numbersOfVectors), sizeof(int), 0);
        if (rc != sizeof(int)) {
            throw std::runtime_error("Failed to receive the number of vectors");
        }

        for (int i = 0; i < numbersOfVectors; ++i) {
            int sizeOfVector = 0;
            // Получаем размер вектора
            rc = recv(work_sock, reinterpret_cast<char*>(&sizeOfVector), sizeof(int), 0);
            if (rc != sizeof(int)) {
                throw std::runtime_error("Failed to receive the size of vector");
            }

            std::vector<float> vectorData(sizeOfVector);

            // Получаем данные вектора
            rc = recv(work_sock, reinterpret_cast<char*>(vectorData.data()), sizeOfVector * floatSize, 0);
            if (rc != sizeOfVector * floatSize) {
                throw std::runtime_error("Failed to receive vector data");
            }

            // Выполняем операции над вектором
            float sum = 0.0f;
            for (float num : vectorData) {
                sum += num * num;
            }

            const float maxFloat = std::numeric_limits<float>::max();
            const float minFloat = std::numeric_limits<float>::lowest();

            if (sum > maxFloat) {
                sum = maxFloat - 1.0f;
            } else if (sum < minFloat) {
                sum = minFloat;
            }

            // Отправляем результат вычислений
            rc = send(work_sock, reinterpret_cast<char*>(&sum), sizeof(float), 0);
            if (rc != sizeof(float)) {
                throw std::runtime_error("Failed to send the result of calculation");
            }
        }

        return 0.0f; // При успешной обработке всех векторов
    } catch (const std::exception& e) {
        std::cerr << "Error occurred in quad(): " << e.what() << std::endl;
        ErrorLog::logError(true, std::string("Error occurred in quad(): ") + e.what());
        return 0.0f;
    }
}





void Server::operator()(int work_sock)
{
    bool authenticated = authentication(work_sock, userCredentials);
    if (authenticated) {
        float result = quad(work_sock);
        
        // Преобразование результата в строку для отправки
        std::ostringstream oss;
        oss << result;
        std::string resultStr = oss.str();

        // Отправка результата обратно клиенту
        int rc = send(work_sock, resultStr.c_str(), resultStr.size(), 0);
        if (rc == -1)
            throw std::system_error(errno, std::generic_category(), "Send result error");
    }
    close(work_sock); // Закрываем соединение после выполнения всех операций
}


void Server::startListening(Server & server) {
    try {
        // Прослушивание подключений
        if (listen(sock, queueLen) == -1)
            throw std::system_error(errno, std::generic_category(), "Listen error");

        socklen_t socklen = sizeof(sockaddr_in);
        while (true) {
            int work_sock = accept(sock, reinterpret_cast<sockaddr*>(foreign_addr.get()), &socklen);
            if (work_sock == -1)
                throw std::system_error(errno, std::generic_category(), "Accept error");

            std::string ip_addr(inet_ntoa(foreign_addr->sin_addr));
            std::clog << "log: Connection established with " << ip_addr << std::endl;

            try {
                server(work_sock); // Обработка запросов клиента
            } catch (std::system_error &e) {
                std::cerr << e.what() << "\nConnection with " << ip_addr << " aborted\n";
            } catch (std::bad_alloc &e) {
                std::cerr << e.what() << ": vector size too big\nConnection with " << ip_addr << " aborted\n";
            }
            close(work_sock);
            std::clog << "log: Connection closed\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "Error occurred in startListening(): " << e.what() << std::endl;
        ErrorLog::logError(true, std::string("Error occurred in startListening(): ") + e.what());
    }
}

std::string Server::str_read(int work_sock)
{
    int rc;
    int buflen = BUFLEN;
    std::unique_ptr<char[]> buf(new char[buflen]);
    rc = recv(work_sock, buf.get(), buflen, 0);
    if (rc == -1)
        throw std::system_error(errno, std::generic_category(), "Recv string error");
    std::string res(buf.get(), rc);
    if (rc == buflen) {
        int tail_size;
        rc = ioctl(work_sock, FIONREAD, &tail_size);
        if (rc == -1)
            throw std::system_error(errno, std::generic_category(), "IOCTL error");
        if (tail_size > 0) {
            if (tail_size > buflen)
                buf = std::unique_ptr<char[]>(new char[tail_size]);
            rc = recv(work_sock, buf.get(), tail_size, 0);
            if (rc == -1)
                throw std::system_error(errno, std::generic_category(), "Recv string error");
            res.append(buf.get(), rc);
        }
    }
    res.resize(res.find_last_not_of("\n\r") + 1);
    return res;
}
Server::~Server() {
    close(sock);
    self_addr.reset();
    foreign_addr.reset();
}
