#include <iostream>
#include <unistd.h>
#include "Server.h"

int main(int argc, char *argv[]) {
    unsigned short port = 8080; // Порт по умолчанию
    int qlen = 10; // Длина очереди по умолчанию
    std::string dbFile = "base.txt"; // Файл базы данных по умолчанию

    int opt;
    while ((opt = getopt(argc, argv, "p:q:d:")) != -1) {
        switch (opt) {
            case 'p':
                port = std::stoi(optarg);
                break;
            case 'q':
                qlen = std::stoi(optarg);
                break;
            case 'd':
                dbFile = optarg;
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " -p <port> -q <queue_length> -d <database_file>" << std::endl;
                return 1;
        }
    }

    try {
        Server server(port, qlen, dbFile);
        server.get_base(dbFile);
        server.startListening(server);
    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
