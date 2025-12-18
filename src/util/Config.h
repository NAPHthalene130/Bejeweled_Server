#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <cstdlib>
#include <iostream>

class Config {
public:
    // Default values
    inline static std::string sqlIP = "127.0.0.1";
    inline static int sqlPort = 33060;
    inline static std::string sqlUsername = "root";
    inline static std::string sqlPassword = "password";

    static void loadEnv() {
        if (const char* env_p = std::getenv("DB_HOST")) sqlIP = env_p;
        if (const char* env_p = std::getenv("DB_PORT")) sqlPort = std::stoi(env_p);
        if (const char* env_p = std::getenv("DB_USER")) sqlUsername = env_p;
        if (const char* env_p = std::getenv("DB_PASS")) sqlPassword = env_p;
        
        std::cout << "Loaded Config: IP=" << sqlIP << " Port=" << sqlPort << " User=" << sqlUsername << std::endl;
    }
};

#endif // CONFIG_H
