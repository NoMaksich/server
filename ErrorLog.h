#pragma once
#include <iostream>
#include <string>

class ErrorLog {
public:
    static void logError(bool critical, const std::string& errorMessage);
};