#include "Config.h"
#include <cstdlib>
#include <iostream>

// 静态成员变量已在头文件中通过 inline static 初始化，此处无需再次定义

void Config::loadEnv() {
    if (const char* env_p = std::getenv("DB_HOST")) sqlIP = env_p;
    if (const char* env_p = std::getenv("DB_PORT")) sqlPort = std::stoi(env_p);
    if (const char* env_p = std::getenv("DB_USER")) sqlUsername = env_p;
    if (const char* env_p = std::getenv("DB_PASS")) sqlPassword = env_p;
    
    std::cout << "Loaded Config: IP=" << sqlIP << " Port=" << sqlPort << " User=" << sqlUsername << std::endl;
}
