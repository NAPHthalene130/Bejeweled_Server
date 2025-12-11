#ifndef SQL_UTIL_H
#define SQL_UTIL_H

#include <string>
#include <iostream>

class SqlUtil {
public:
    static std::string getPlayerIDfromPlayerinfo();
    static std::string getPlayerPasswordfromPlayerinfo();
    static std::string getEmailfromPlayerinfo();
    static std::string getStyleSetfromPlayerinfo();
    static void setPlayerIDfromPlayerinfo();
    static void setPlayerPasswordfromPlayerinfo();
    static void setEmailfromPlayerinfo();
    static void setStyleSetfromPlayerinfo();
    static int authPasswordFromPlayerinfo(std::string playerID, std::string password);
    static int registerFromPlayerinfo(std::string playerID, std::string password, std::string email, std::string styleSet, std::string emailCode);
};


#endif // SQL_UTIL_H
