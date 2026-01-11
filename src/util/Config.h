#ifndef CONFIG_H
#define CONFIG_H

#include <string>

class Config {
public:
    inline static std::string sqlIP = "127.0.0.1";
    inline static int sqlPort = 3306;
    inline static std::string sqlUsername = "root";
    inline static std::string sqlPassword = "123456";

    static void loadEnv();
};

#endif // CONFIG_H
