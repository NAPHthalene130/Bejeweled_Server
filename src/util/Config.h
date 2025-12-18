#ifndef CONFIG_H
#define CONFIG_H

#include <string>

class Config {
public:
    // 使用 inline static 允许在头文件中直接初始化，方便配置，且不会导致多重定义错误 (需C++17及以上)
    inline static std::string sqlIP = "127.0.0.1";
    inline static int sqlPort = 3306;
    inline static std::string sqlUsername = "root";
    inline static std::string sqlPassword = "123456";

    static void loadEnv();
};

#endif // CONFIG_H
