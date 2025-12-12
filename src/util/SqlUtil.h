#ifndef SQL_UTIL_H
#define SQL_UTIL_H

#include <string>
#include <iostream>

class SqlUtil {
public:
    static std::string getPlayerPasswordByPlayerIDfromPlayerinfo(std::string playerID);
    static std::string getEmailByPlayerIDfromPlayerinfo(std::string playerID);
    static std::string getStyleSetByPlayerIDfromPlayerinfo(std::string playerID);
    static void setPlayerPasswordByPlayerIDfromPlayerinfo(std::string playerID, std::string password);
    static void setEmailByPlayerIDfromPlayerinfo(std::string playerID, std::string email);
    static void setStyleSetByPlayerIDfromPlayerinfo(std::string playerID, std::string styleSet);
    static bool comparePassword(std::string passwordInDB, std::string password);
    static int authPasswordFromPlayerinfo(std::string playerID, std::string password);
    static int registerFromPlayerinfo(std::string playerID, std::string password, std::string email, std::string styleSet, std::string emailCode);
};


#endif // SQL_UTIL_H
