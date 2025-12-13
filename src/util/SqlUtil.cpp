#include "SqlUtil.h"
#include "mysql/jdbc.h"
#include "mysqlx/xdevapi.h"
#include <iostream>
#include <string>
#include "../Config.h"

bool SqlUtil::comparePassword(std::string passwordInDB, std::string password) {
    return true;
}

bool SqlUtil::authEmailCode(std::string emailCode, std::string email) {
    return true;
}

int SqlUtil::authPasswordFromPlayerinfo(std::string playerID, std::string password) {
    //测试
    return 1;
    //以上测试
    try {
        sql::mysql::MySQL_Driver *driver;
        sql::Connection *conn;
        sql::Statement *stmt;
        sql::ResultSet *res;
        driver = sql::mysql::get_mysql_driver_instance();
        conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
        conn->setSchema("bejeweled");
        stmt = conn->createStatement();
        res = stmt->executeQuery("SELECT playerPassword FROM playerinfo WHERE playerID = '" + playerID + "'");
        if (res->next()) {
            std::string pwGetFromDB = res->getString("playerPassword");
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
    try {
        if (!authEmailCode(emailCode, email)) {
            return 2;
        }
        sql::mysql::MySQL_Driver *driver;
        sql::Connection *conn;
        sql::Statement *stmt;
        sql::ResultSet *res;
        driver = sql::mysql::get_mysql_driver_instance();
        conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
        conn->setSchema("bejeweled");
        stmt = conn->createStatement();

        res = stmt->executeQuery("SELECT playerID FROM playerinfo WHERE playerID = '" + playerID + "'");
        if (res->next()) {
            delete res;
            delete stmt;
            delete conn;
            return 3;
        }
        delete res;

        res = stmt->executeQuery("SELECT email FROM playerinfo WHERE email = '" + email + "'");
        if (res->next()) {
            delete res;
            delete stmt;
            delete conn;
            return 4;
        }
        delete res;

        stmt->executeUpdate("INSERT INTO playerinfo (playerID, playerPassword, email, styleSet) VALUES ('" + playerID + "', '" + password + "', '" + email + "', '" + styleSet + "')");
        delete stmt;
        delete conn;
        return 1;
    } catch (sql::SQLException &e) {
        return 5;
    } catch (...) {
        return 5;
    }
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
    res = stmt->executeQuery("SELECT playerPassword FROM playerinfo WHERE playerID = '" + playerID + "'");
    if (res->next()) {
        return res->getString("playerPassword");
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
    stmt->executeUpdate("UPDATE playerinfo SET playerPassword = '" + password + "' WHERE playerID = '" + playerID + "'");
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


