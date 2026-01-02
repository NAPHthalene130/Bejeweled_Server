#include "SqlUtil.h"
#include <mysql/jdbc.h>
#include "mysqlx/xdevapi.h"
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "Config.h"

// Helper: Convert binary data to hex string
static std::string toHex(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    for (unsigned char b : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return ss.str();
}

// Helper: Convert hex string to binary data
static std::vector<unsigned char> fromHex(const std::string& hex) {
    std::vector<unsigned char> data;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        data.push_back(byte);
    }
    return data;
}

// Helper: Generate random salt
static std::string generateSalt(int length = 16) {
    std::vector<unsigned char> salt(length);
    if (RAND_bytes(salt.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }
    return toHex(salt);
}

// Helper: PBKDF2 Hashing
static std::string hashPassword(const std::string& password, const std::string& saltHex, int iterations) {
    std::vector<unsigned char> salt = fromHex(saltHex);
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), salt.size(),
                          iterations,
                          EVP_sha256(),
                          SHA256_DIGEST_LENGTH,
                          hash.data()) != 1) {
        throw std::runtime_error("PBKDF2 hashing failed");
    }
    
    return toHex(hash);
}

bool SqlUtil::authEmailCode(std::string emailCode, std::string email) {
    return true;
}

void SqlUtil::testConnection() {
    try {
        std::cout << "Testing MySQL Connection..." << std::endl;
        std::cout << "IP: " << Config::sqlIP << ", Port: " << Config::sqlPort << std::endl;
        
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        
        std::cout << "Connected to MySQL server!" << std::endl;
        
        conn->setSchema("bejeweled");
        std::cout << "Schema 'bejeweled' selected." << std::endl;
        
        std::cout << "Connection test passed." << std::endl;
    } catch (sql::SQLException &e) {
        std::cerr << "MySQL Connection Test Failed: " << e.what() << std::endl;
    } catch (const std::bad_alloc& e) {
        std::cerr << "MySQL Connection Test Failed: Memory allocation error (bad_alloc). "
                  << "This usually indicates a mismatch between Debug/Release builds. "
                  << "Please ensure you are using the correct MySQL libraries for your build configuration "
                  << "(e.g., don't link Release libraries in a Debug build)." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "MySQL Connection Test Exception: " << e.what() << std::endl;
    }
}

int SqlUtil::authPasswordFromPlayerinfo(std::string playerID, std::string password) {
    std::cout << "[SqlUtil][Info]: Authenticating user: " << playerID << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");
        
        // Retrieve password hash, salt, and iterations
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT playerPassword, salt, iterations FROM playerinfo WHERE playerID = ?"));
        pstmt->setString(1, playerID);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        
        if (res->next()) {
            std::string dbHash = res->getString("playerPassword");
            std::string salt = res->getString("salt");
            int iterations = res->getInt("iterations");
            
            // If legacy user (no salt/iter), fallback or fail (Assuming all new users)
            if (salt.empty() || iterations == 0) {
                 std::cout << "[SqlUtil][Info]: Legacy user or missing salt/iterations for: " << playerID << std::endl;
                 return 2; // Treat as fail for security
            }

            std::string computedHash = hashPassword(password, salt, iterations);
            
            if (computedHash == dbHash) {
                std::cout << "[SqlUtil][Info]: Authentication successful for: " << playerID << std::endl;
                return 1; // Success
            } else {
                std::cout << "[SqlUtil][Info]: Authentication failed (wrong password) for: " << playerID << std::endl;
                return 2; // Wrong password
            }
        } else {
            std::cout << "[SqlUtil][Info]: Authentication failed (user not found): " << playerID << std::endl;
            return 2; // User not found
        }
    } catch (sql::SQLException &e) {
        std::cerr << "[SqlUtil][Error]: SQLException in auth: " << e.what() << std::endl;
        return 3;
    } catch (const std::exception& e) {
        std::cerr << "[SqlUtil][Error]: Exception in auth: " << e.what() << std::endl;
        return 3;
    }
}

int SqlUtil::registerFromPlayerinfo(std::string playerID, std::string password) {
    try {
        std::cout << "[Register] Starting registration for ID: " << playerID << std::endl;
        
        std::cout << "[Register] Connecting to DB..." << std::endl;
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");

        // Check if account exists
        {
            std::cout << "[Register] Checking if account exists..." << std::endl;
            std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT playerID FROM playerinfo WHERE playerID = ?"));
            pstmt->setString(1, playerID);
            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
            if (res->next()) {
                std::cout << "[Register] Account already exists" << std::endl;
                return 3; // Account exists
            }
        }

        // Security: Generate Salt and Hash
        std::cout << "[Register] Generating salt and hash..." << std::endl;
        std::string salt = generateSalt();
        
        // Random iterations (10000 + random(0-5000))
        unsigned short randVal = 0;
        if (RAND_bytes((unsigned char*)&randVal, sizeof(randVal)) != 1) {
             randVal = 1234; // Fallback
        }
        int iterations = 10000 + (randVal % 5001);

        std::string passwordHash = hashPassword(password, salt, iterations);

        // Insert new user
        std::cout << "[Register] Inserting new user..." << std::endl;
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement(
            "INSERT INTO playerinfo (playerID, playerPassword, salt, iterations, "
            "money, normalSeconds, whirlSeconds, multiScore, achievementStr, "
            "prop_hammer, prop_resetTable, prop_clearTable, prop_freeze) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ));
        
        pstmt->setString(1, playerID);
        pstmt->setString(2, passwordHash);
        pstmt->setString(3, salt);
        pstmt->setInt(4, iterations);
        pstmt->setInt(5, 0);            // money
        pstmt->setInt(6, 99999);        // normalSeconds
        pstmt->setInt(7, 0);        // whirlSeconds
        pstmt->setInt(8, 0);            // multiScore
        pstmt->setString(9, "0000000000"); // achievementStr
        pstmt->setInt(10, 0);           // prop_hammer
        pstmt->setInt(11, 0);           // prop_resetTable
        pstmt->setInt(12, 0);           // prop_clearTable
        pstmt->setInt(13, 0);           // prop_freeze
                            
        pstmt->executeUpdate();
        std::cout << "[Register] Insert successful" << std::endl;
        return 1;
    } catch (sql::SQLException &e) {
        std::cerr << "SQLException in register: " << e.what() << std::endl;
        return 5;
    } catch (const std::exception& e) {
        std::cerr << "Exception in register: " << e.what() << std::endl;
        return 5;
    }
}

std::string SqlUtil::getPlayerPasswordByPlayerIDfromPlayerinfo(std::string playerID) {
    sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
    std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
    conn->setSchema("bejeweled");
    std::unique_ptr<sql::Statement> stmt(conn->createStatement());
    std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT playerPassword FROM playerinfo WHERE playerID = '" + playerID + "'"));
    if (res->next()) {
        return res->getString("playerPassword");
    }
    return "";
}
std::string SqlUtil::getEmailByPlayerIDfromPlayerinfo(std::string playerID) {
    sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
    std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
    conn->setSchema("bejeweled");
    std::unique_ptr<sql::Statement> stmt(conn->createStatement());
    std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT email FROM playerinfo WHERE playerID = '" + playerID + "'"));
    if (res->next()) {
        return res->getString("email");
    }
    return "";
}
std::string SqlUtil::getStyleSetByPlayerIDfromPlayerinfo(std::string playerID) {
    sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
    std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
    conn->setSchema("bejeweled");
    std::unique_ptr<sql::Statement> stmt(conn->createStatement());
    std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT styleSet FROM playerinfo WHERE playerID = '" + playerID + "'"));
    if (res->next()) {
        return res->getString("styleSet");
    }
    return "";
}

void SqlUtil::setPlayerPasswordByPlayerIDfromPlayerinfo(std::string playerID, std::string password) {
    sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
    std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
    conn->setSchema("bejeweled");
    std::unique_ptr<sql::Statement> stmt(conn->createStatement());
    stmt->executeUpdate("UPDATE playerinfo SET playerPassword = '" + password + "' WHERE playerID = '" + playerID + "'");
}
void SqlUtil::setEmailByPlayerIDfromPlayerinfo(std::string playerID, std::string email) {
    sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
    std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
    conn->setSchema("bejeweled");
    std::unique_ptr<sql::Statement> stmt(conn->createStatement());
    stmt->executeUpdate("UPDATE playerinfo SET email = '" + email + "' WHERE playerID = '" + playerID + "'");
}

void SqlUtil::setStyleSetByPlayerIDfromPlayerinfo(std::string playerID, std::string styleSet) {
    sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
    std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
    conn->setSchema("bejeweled");
    std::unique_ptr<sql::Statement> stmt(conn->createStatement());
    stmt->executeUpdate("UPDATE playerinfo SET styleSet = '" + styleSet + "' WHERE playerID = '" + playerID + "'");
}

std::string SqlUtil::getSaltByPlayerIDfromPlayerinfo(std::string playerID) {
    sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
    std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
    conn->setSchema("bejeweled");
    std::unique_ptr<sql::Statement> stmt(conn->createStatement());
    std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT salt FROM playerinfo WHERE playerID = '" + playerID + "'"));
    if (res->next()) {
        return res->getString("salt");
    }
    return "";
}

int SqlUtil::getIterationsByPlayerIDfromPlayerinfo(std::string playerID) {
    sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
    std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
    conn->setSchema("bejeweled");
    std::unique_ptr<sql::Statement> stmt(conn->createStatement());
    std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT iterations FROM playerinfo WHERE playerID = '" + playerID + "'"));
    if (res->next()) {
        return res->getInt("iterations");
    }
    return 0;
}

void SqlUtil::setSaltByPlayerIDfromPlayerinfo(std::string playerID, std::string salt) {
    sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
    std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
    conn->setSchema("bejeweled");
    std::unique_ptr<sql::Statement> stmt(conn->createStatement());
    stmt->executeUpdate("UPDATE playerinfo SET salt = '" + salt + "' WHERE playerID = '" + playerID + "'");
}

void SqlUtil::setIterationsByPlayerIDfromPlayerinfo(std::string playerID, int iterations) {
    sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
    std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
    conn->setSchema("bejeweled");
    std::unique_ptr<sql::Statement> stmt(conn->createStatement());
    stmt->executeUpdate("UPDATE playerinfo SET iterations = " + std::to_string(iterations) + " WHERE playerID = '" + playerID + "'");
}

std::vector<int> SqlUtil::getPropsFromPlayerinfo(std::string playerID) {
    std::cout << "[SqlUtil][Info]: Getting props for: " << playerID << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT prop_freeze, prop_hammer, prop_resetTable, prop_clearTable FROM playerinfo WHERE playerID = ?"));
        pstmt->setString(1, playerID);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        if (res->next()) {
            std::vector<int> props;
            props.push_back(res->getInt("prop_freeze"));
            props.push_back(res->getInt("prop_hammer"));
            props.push_back(res->getInt("prop_resetTable"));
            props.push_back(res->getInt("prop_clearTable"));
            std::cout << "[SqlUtil][Info]: Props retrieved for " << playerID << ": " 
                      << props[0] << ", " << props[1] << ", " << props[2] << ", " << props[3] << std::endl;
            return props;
        }
    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in getPropsFromPlayerinfo: " << e.what() << std::endl;
    }
    return {0, 0, 0, 0};
}

bool SqlUtil::setPropsFromPlayerinfo(std::string playerID, std::vector<int> props) {
    if (props.size() != 4) return false;
    std::cout << "[SqlUtil][Info]: Setting props for " << playerID << ": " 
              << props[0] << ", " << props[1] << ", " << props[2] << ", " << props[3] << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("UPDATE playerinfo SET prop_freeze = ?, prop_hammer = ?, prop_resetTable = ?, prop_clearTable = ? WHERE playerID = ?"));
        pstmt->setInt(1, props[0]);
        pstmt->setInt(2, props[1]);
        pstmt->setInt(3, props[2]);
        pstmt->setInt(4, props[3]);
        pstmt->setString(5, playerID);
        pstmt->executeUpdate();
        std::cout << "[SqlUtil][Info]: Props updated successfully for " << playerID << std::endl;
        return true;
    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in setPropsFromPlayerinfo: " << e.what() << std::endl;
        return false;
    }
}

int SqlUtil::getMoneyByPlayerIDfromPlayerinfo(std::string playerID) {
    std::cout << "[SqlUtil][Info]: Getting money for: " << playerID << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT money FROM playerinfo WHERE playerID = ?"));
        pstmt->setString(1, playerID);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        if (res->next()) {
            int money = res->getInt("money");
            std::cout << "[SqlUtil][Info]: Money for " << playerID << ": " << money << std::endl;
            return money;
        }
    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in getMoney: " << e.what() << std::endl;
    }
    return 0;
}

void SqlUtil::setMoneyByPlayerIDfromPlayerinfo(std::string playerID, int money) {
    std::cout << "[SqlUtil][Info]: Setting money for " << playerID << ": " << money << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("UPDATE playerinfo SET money = ? WHERE playerID = ?"));
        pstmt->setInt(1, money);
        pstmt->setString(2, playerID);
        pstmt->executeUpdate();
        std::cout << "[SqlUtil][Info]: Money updated successfully for " << playerID << std::endl;
    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in setMoney: " << e.what() << std::endl;
    }
}

int SqlUtil::getNormalSecondsByPlayerIDfromPlayerinfo(std::string playerID) {
    std::cout << "[SqlUtil][Info]: Getting normalSeconds for: " << playerID << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT normalSeconds FROM playerinfo WHERE playerID = ?"));
        pstmt->setString(1, playerID);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        if (res->next()) {
            int seconds = res->getInt("normalSeconds");
            std::cout << "[SqlUtil][Info]: NormalSeconds for " << playerID << ": " << seconds << std::endl;
            return seconds;
        }
    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in getNormalSeconds: " << e.what() << std::endl;
    }
    return 99999;
}

void SqlUtil::setNormalSecondsByPlayerIDfromPlayerinfo(std::string playerID, int normalSeconds) {
    std::cout << "[SqlUtil][Info]: Setting normalSeconds for " << playerID << ": " << normalSeconds << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");

        // Get current value
        std::unique_ptr<sql::PreparedStatement> pstmtGet(conn->prepareStatement("SELECT normalSeconds FROM playerinfo WHERE playerID = ?"));
        pstmtGet->setString(1, playerID);
        std::unique_ptr<sql::ResultSet> res(pstmtGet->executeQuery());
        
        int currentVal = 99999;
        if (res->next()) {
            currentVal = res->getInt("normalSeconds");
        }

        // Keep minimum
        int finalVal = (normalSeconds < currentVal) ? normalSeconds : currentVal;

        // Update if changed (optimization)
        if (finalVal != currentVal) {
             std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("UPDATE playerinfo SET normalSeconds = ? WHERE playerID = ?"));
             pstmt->setInt(1, finalVal);
             pstmt->setString(2, playerID);
             pstmt->executeUpdate();
             std::cout << "[SqlUtil][Info]: NormalSeconds updated successfully for " << playerID << " to " << finalVal << std::endl;
        } else {
             std::cout << "[SqlUtil][Info]: NormalSeconds not updated (new value " << normalSeconds << " >= current " << currentVal << ")" << std::endl;
        }

    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in setNormalSeconds: " << e.what() << std::endl;
    }
}

int SqlUtil::getWhirlSecondsByPlayerIDfromPlayerinfo(std::string playerID) {
    std::cout << "[SqlUtil][Info]: Getting whirlSeconds for: " << playerID << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT whirlSeconds FROM playerinfo WHERE playerID = ?"));
        pstmt->setString(1, playerID);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        if (res->next()) {
            int seconds = res->getInt("whirlSeconds");
            std::cout << "[SqlUtil][Info]: WhirlSeconds for " << playerID << ": " << seconds << std::endl;
            return seconds;
        }
    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in getWhirlSeconds: " << e.what() << std::endl;
    }
    return 99999;
}

void SqlUtil::setWhirlSecondsByPlayerIDfromPlayerinfo(std::string playerID, int whirlSeconds) {
    std::cout << "[SqlUtil][Info]: Setting whirlSeconds for " << playerID << ": " << whirlSeconds << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");

        // Get current value
        std::unique_ptr<sql::PreparedStatement> pstmtGet(conn->prepareStatement("SELECT whirlSeconds FROM playerinfo WHERE playerID = ?"));
        pstmtGet->setString(1, playerID);
        std::unique_ptr<sql::ResultSet> res(pstmtGet->executeQuery());
        
        int currentVal = 0;
        if (res->next()) {
            currentVal = res->getInt("whirlSeconds");
        }
        
        // Handle potential legacy default value 99999 which blocks MAX logic
        if (currentVal == 99999) currentVal = 0;

        // Keep maximum
        int finalVal = (whirlSeconds > currentVal) ? whirlSeconds : currentVal;

        if (finalVal != currentVal || currentVal == 0) { // Update if changed or if it was 0 (potentially uninitialized)
             std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("UPDATE playerinfo SET whirlSeconds = ? WHERE playerID = ?"));
             pstmt->setInt(1, finalVal);
             pstmt->setString(2, playerID);
             pstmt->executeUpdate();
             std::cout << "[SqlUtil][Info]: WhirlSeconds updated successfully for " << playerID << " to " << finalVal << std::endl;
        } else {
             std::cout << "[SqlUtil][Info]: WhirlSeconds not updated (new value " << whirlSeconds << " <= current " << currentVal << ")" << std::endl;
        }
    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in setWhirlSeconds: " << e.what() << std::endl;
    }
}

int SqlUtil::getMultiScoreByPlayerIDfromPlayerinfo(std::string playerID) {
    std::cout << "[SqlUtil][Info]: Getting multiScore for: " << playerID << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT multiScore FROM playerinfo WHERE playerID = ?"));
        pstmt->setString(1, playerID);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        if (res->next()) {
            int score = res->getInt("multiScore");
            std::cout << "[SqlUtil][Info]: MultiScore for " << playerID << ": " << score << std::endl;
            return score;
        }
    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in getMultiScore: " << e.what() << std::endl;
    }
    return 0;
}

void SqlUtil::setMultiScoreByPlayerIDfromPlayerinfo(std::string playerID, int multiScore) {
    std::cout << "[SqlUtil][Info]: Setting multiScore for " << playerID << ": " << multiScore << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");
        
        // Get current value
        std::unique_ptr<sql::PreparedStatement> pstmtGet(conn->prepareStatement("SELECT multiScore FROM playerinfo WHERE playerID = ?"));
        pstmtGet->setString(1, playerID);
        std::unique_ptr<sql::ResultSet> res(pstmtGet->executeQuery());
        
        int currentVal = 0;
        if (res->next()) {
            currentVal = res->getInt("multiScore");
        }

        // Keep maximum
        int finalVal = (multiScore > currentVal) ? multiScore : currentVal;

        if (finalVal != currentVal) {
             std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("UPDATE playerinfo SET multiScore = ? WHERE playerID = ?"));
             pstmt->setInt(1, finalVal);
             pstmt->setString(2, playerID);
             pstmt->executeUpdate();
             std::cout << "[SqlUtil][Info]: MultiScore updated successfully for " << playerID << " to " << finalVal << std::endl;
        } else {
             std::cout << "[SqlUtil][Info]: MultiScore not updated (new value " << multiScore << " <= current " << currentVal << ")" << std::endl;
        }
    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in setMultiScore: " << e.what() << std::endl;
    }
}

std::string SqlUtil::getAchievementStrByPlayerIDfromPlayerinfo(std::string playerID) {
    std::cout << "[SqlUtil][Info]: Getting achievementStr for: " << playerID << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT achievementStr FROM playerinfo WHERE playerID = ?"));
        pstmt->setString(1, playerID);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        if (res->next()) {
            std::string achStr = res->getString("achievementStr");
            std::cout << "[SqlUtil][Info]: AchievementStr for " << playerID << ": " << achStr << std::endl;
            return achStr;
        }
    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in getAchievementStr: " << e.what() << std::endl;
    }
    return "0000000000";
}

void SqlUtil::setAchievementStrByPlayerIDfromPlayerinfo(std::string playerID, std::string achievementStr) {
    std::cout << "[SqlUtil][Info]: Setting achievementStr for " << playerID << ": " << achievementStr << std::endl;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");

        // 1. Get current achievement string
        std::unique_ptr<sql::PreparedStatement> pstmtGet(conn->prepareStatement("SELECT achievementStr FROM playerinfo WHERE playerID = ?"));
        pstmtGet->setString(1, playerID);
        std::unique_ptr<sql::ResultSet> res(pstmtGet->executeQuery());
        
        std::string currentAch = "0000000000";
        if (res->next()) {
            currentAch = res->getString("achievementStr");
        }

        // Ensure length is 10
        if (currentAch.length() != 10) currentAch = "0000000000";
        if (achievementStr.length() != 10) achievementStr = "0000000000";

        // 2. Perform OR operation
        std::string finalAch = "0000000000";
        for (int i = 0; i < 10; ++i) {
            if (currentAch[i] == '1' || achievementStr[i] == '1') {
                finalAch[i] = '1';
            } else {
                finalAch[i] = '0';
            }
        }

        // 3. Check first 9 bits
        bool firstNineAllOne = true;
        for (int i = 0; i < 9; ++i) {
            if (finalAch[i] != '1') {
                firstNineAllOne = false;
                break;
            }
        }

        // 4. Set 10th bit if condition met
        if (firstNineAllOne) {
            finalAch[9] = '1';
        }

        // 5. Update database
        std::unique_ptr<sql::PreparedStatement> pstmtUpdate(conn->prepareStatement("UPDATE playerinfo SET achievementStr = ? WHERE playerID = ?"));
        pstmtUpdate->setString(1, finalAch);
        pstmtUpdate->setString(2, playerID);
        pstmtUpdate->executeUpdate();
        std::cout << "[SqlUtil][Info]: AchievementStr updated successfully for " << playerID << " to " << finalAch << std::endl;
    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in setAchievementStr: " << e.what() << std::endl;
    }
}

std::vector<std::vector<std::pair<std::string, int>>> SqlUtil::getRanksFromPlayerinfo() {
    std::cout << "[SqlUtil][Info]: Getting ranks from playerinfo" << std::endl;
    std::vector<std::vector<std::pair<std::string, int>>> ranks;
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword));
        conn->setSchema("bejeweled");

        // 1. Normal Seconds (Ascending)
        {
            std::vector<std::pair<std::string, int>> normalRank;
            std::unique_ptr<sql::Statement> stmt(conn->createStatement());
            std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT playerID, normalSeconds FROM playerinfo ORDER BY normalSeconds ASC LIMIT 10"));
            while (res->next()) {
                normalRank.push_back({res->getString("playerID"), res->getInt("normalSeconds")});
            }
            ranks.push_back(normalRank);
        }

        // 2. Whirl Seconds (Ascending)
        {
            std::vector<std::pair<std::string, int>> whirlRank;
            std::unique_ptr<sql::Statement> stmt(conn->createStatement());
            std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT playerID, whirlSeconds FROM playerinfo ORDER BY whirlSeconds DESC LIMIT 10"));
            while (res->next()) {
                whirlRank.push_back({res->getString("playerID"), res->getInt("whirlSeconds")});
            }
            ranks.push_back(whirlRank);
        }

        // 3. Multi Score (Descending)
        {
            std::vector<std::pair<std::string, int>> multiRank;
            std::unique_ptr<sql::Statement> stmt(conn->createStatement());
            std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT playerID, multiScore FROM playerinfo ORDER BY multiScore DESC LIMIT 10"));
            while (res->next()) {
                multiRank.push_back({res->getString("playerID"), res->getInt("multiScore")});
            }
            ranks.push_back(multiRank);
        }

        std::cout << "[SqlUtil][Info]: Ranks retrieved successfully" << std::endl;
        return ranks;

    } catch (std::exception &e) {
        std::cerr << "[SqlUtil][Error]: Exception in getRanksFromPlayerinfo: " << e.what() << std::endl;
        return {};
    }
}


