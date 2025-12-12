#include "SqlUtil.h"
#include "mysql/jdbc.h"
#include "mysqlx/xdevapi.h"
#include <iostream>
#include <string>
#include "../Config.h"

bool SqlUtil::comparePassword(std::string passwordInDB, std::string password) {
    //TODO: 密码比较逻辑
    return true;
}

int SqlUtil::authPasswordFromPlayerinfo(std::string playerID, std::string password) {
    try {
        sql::mysql::MySQL_Driver *driver;
        sql::Connection *conn;
        sql::Statement *stmt;
        sql::ResultSet *res;
        driver = sql::mysql::get_mysql_driver_instance();
        conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
        conn->setSchema("bejeweled");
        stmt = conn->createStatement();
        res = stmt->executeQuery("SELECT password FROM playerinfo WHERE playerID = '" + playerID + "'");
        if (res->next()) {
            std::string pwGetFromDB = res->getString("password");
            bool compareFlag = comparePassword(pwGetFromDB, password);
            delete res;
            delete stmt;
            delete conn;
            if (compareFlag) {
                return 1;
            } else {
                return 2;
            }
        } else {
            delete res;
            delete stmt;
            delete conn;
            return 2;
        }
    } catch (sql::SQLException &e) {
        return 3;
    } catch (...) {
        return 3;
    }
}

int SqlUtil::registerFromPlayerinfo(std::string playerID, std::string password, std::string email, std::string styleSet, std::string emailCode) {
    //1 注册成功
    //2 邮箱验证码错误
    //3 账号已存在
    //4 邮箱已存在
    //5 其它错误
    //TODO 具体实现逻辑
    return 1;
}

std::string SqlUtil::getPlayerPasswordByPlayerIDfromPlayerinfo(std::string playerID) {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *conn;
    sql::Statement *stmt;
    sql::ResultSet *res;
    driver = sql::mysql::get_mysql_driver_instance();
    conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
    conn->setSchema("bejeweled");
    stmt = conn->createStatement();
    res = stmt->executeQuery("SELECT password FROM playerinfo WHERE playerID = '" + playerID + "'");
    if (res->next()) {
        return res->getString("password");
    }
    return "";
}
std::string SqlUtil::getEmailByPlayerIDfromPlayerinfo(std::string playerID) {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *conn;
    sql::Statement *stmt;
    sql::ResultSet *res;
    driver = sql::mysql::get_mysql_driver_instance();
    conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
    conn->setSchema("bejeweled");
    stmt = conn->createStatement();
    res = stmt->executeQuery("SELECT email FROM playerinfo WHERE playerID = '" + playerID + "'");
    if (res->next()) {
        return res->getString("email");
    }
    return "";
}
std::string SqlUtil::getStyleSetByPlayerIDfromPlayerinfo(std::string playerID) {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *conn;
    sql::Statement *stmt;
    sql::ResultSet *res;
    driver = sql::mysql::get_mysql_driver_instance();
    conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
    conn->setSchema("bejeweled");
    stmt = conn->createStatement();
    res = stmt->executeQuery("SELECT styleSet FROM playerinfo WHERE playerID = '" + playerID + "'");
    if (res->next()) {
        return res->getString("styleSet");
    }
    return "";
}

void SqlUtil::setPlayerPasswordByPlayerIDfromPlayerinfo(std::string playerID, std::string password) {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *conn;
    sql::Statement *stmt;
    driver = sql::mysql::get_mysql_driver_instance();
    conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
    conn->setSchema("bejeweled");
    stmt = conn->createStatement();
    stmt->executeUpdate("UPDATE playerinfo SET password = '" + password + "' WHERE playerID = '" + playerID + "'");
}
void SqlUtil::setEmailByPlayerIDfromPlayerinfo(std::string playerID, std::string email) {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *conn;
    sql::Statement *stmt;
    driver = sql::mysql::get_mysql_driver_instance();
    conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
    conn->setSchema("bejeweled");
    stmt = conn->createStatement();
    stmt->executeUpdate("UPDATE playerinfo SET email = '" + email + "' WHERE playerID = '" + playerID + "'");
}

void SqlUtil::setStyleSetByPlayerIDfromPlayerinfo(std::string playerID, std::string styleSet) {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *conn;
    sql::Statement *stmt;
    driver = sql::mysql::get_mysql_driver_instance();
    conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
    conn->setSchema("bejeweled");
    stmt = conn->createStatement();
    stmt->executeUpdate("UPDATE playerinfo SET styleSet = '" + styleSet + "' WHERE playerID = '" + playerID + "'");
}


