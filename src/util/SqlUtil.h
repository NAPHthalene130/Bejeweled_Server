#ifndef SQL_UTIL_H
#define SQL_UTIL_H

#include <string>
#include <iostream>
#include <memory>
#include <vector>

class SqlUtil {
public:
    static void testConnection();
    
    static std::string getPlayerPasswordByPlayerIDfromPlayerinfo(std::string playerID);
    static std::string getEmailByPlayerIDfromPlayerinfo(std::string playerID);
    static std::string getStyleSetByPlayerIDfromPlayerinfo(std::string playerID);
    static std::string getSaltByPlayerIDfromPlayerinfo(std::string playerID);
    static int getIterationsByPlayerIDfromPlayerinfo(std::string playerID);

    static void setPlayerPasswordByPlayerIDfromPlayerinfo(std::string playerID, std::string password);
    static void setEmailByPlayerIDfromPlayerinfo(std::string playerID, std::string email);
    static void setStyleSetByPlayerIDfromPlayerinfo(std::string playerID, std::string styleSet);
    static void setSaltByPlayerIDfromPlayerinfo(std::string playerID, std::string salt);
    static void setIterationsByPlayerIDfromPlayerinfo(std::string playerID, int iterations);
    
    static bool authEmailCode(std::string emailCode, std::string email);
    static int authPasswordFromPlayerinfo(std::string playerID, std::string password);
    static int registerFromPlayerinfo(std::string playerID, std::string password);

    static std::vector<int> getPropsFromPlayerinfo(std::string playerID);
    static bool setPropsFromPlayerinfo(std::string playerID, std::vector<int> props);

    static int getMoneyByPlayerIDfromPlayerinfo(std::string playerID);
    static void setMoneyByPlayerIDfromPlayerinfo(std::string playerID, int money);

    static int getNormalSecondsByPlayerIDfromPlayerinfo(std::string playerID);
    static void setNormalSecondsByPlayerIDfromPlayerinfo(std::string playerID, int normalSeconds);

    static int getWhirlSecondsByPlayerIDfromPlayerinfo(std::string playerID);
    static void setWhirlSecondsByPlayerIDfromPlayerinfo(std::string playerID, int whirlSeconds);

    static int getMultiScoreByPlayerIDfromPlayerinfo(std::string playerID);
    static void setMultiScoreByPlayerIDfromPlayerinfo(std::string playerID, int multiScore);

    static std::string getAchievementStrByPlayerIDfromPlayerinfo(std::string playerID);
    static void setAchievementStrByPlayerIDfromPlayerinfo(std::string playerID, std::string achievementStr);

    static std::vector<std::vector<std::pair<std::string, int>>> getRanksFromPlayerinfo();
};


#endif // SQL_UTIL_H
