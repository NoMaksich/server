#include "ErrorLog.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <ctime>

using namespace std;

void ErrorLog::logError(bool critical, const string& errorMessage) {
    ofstream logFile("log.txt", ios_base::app);
    if (logFile.is_open()) {
        auto now = chrono::system_clock::now();
        time_t now_c = chrono::system_clock::to_time_t(now);
        logFile << "Date and time: " << ctime(&now_c);
        logFile << "Critical: " << (critical ? "Yes" : "No");
        logFile << "Error: " << errorMessage;
        logFile.close();
    } else {
        cout << "Unable to open log file." << endl;
    }
}
