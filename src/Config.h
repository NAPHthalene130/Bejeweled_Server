#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <iostream>

class Config {
public:
    static std::string sqlIP;
    static int sqlPort;
    static std::string sqlUsername;
    static std::string sqlPassword;
};

std::string Config::sqlIP = "127.0.0.1";
int Config::sqlPort = 3306;
std::string Config::sqlUsername = "root";

#endif // CONFIG_H
