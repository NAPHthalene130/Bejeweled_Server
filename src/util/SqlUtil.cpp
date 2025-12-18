#include "SqlUtil.h"
#include "mysql/jdbc.h"
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
        sql::Connection *conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
        
        std::cout << "Connected to MySQL server!" << std::endl;
        
        conn->setSchema("bejeweled");
        std::cout << "Schema 'bejeweled' selected." << std::endl;
        
        delete conn;
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
    try {
        sql::mysql::MySQL_Driver *driver;
        sql::Connection *conn;
        sql::PreparedStatement *pstmt;
        sql::ResultSet *res;
        driver = sql::mysql::get_mysql_driver_instance();
        conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
        conn->setSchema("bejeweled");
        
        // Retrieve password hash, salt, and iterations
        pstmt = conn->prepareStatement("SELECT playerPassword, salt, iterations FROM playerinfo WHERE playerID = ?");
        pstmt->setString(1, playerID);
        res = pstmt->executeQuery();
        
        if (res->next()) {
            std::string dbHash = res->getString("playerPassword");
            std::string salt = res->getString("salt");
            int iterations = res->getInt("iterations");
            
            delete res;
            delete pstmt;
            delete conn;
            
            // If legacy user (no salt/iter), fallback or fail (Assuming all new users)
            if (salt.empty() || iterations == 0) {
                 return 2; // Treat as fail for security
            }

            std::string computedHash = hashPassword(password, salt, iterations);
            
            if (computedHash == dbHash) {
                return 1; // Success
            } else {
                return 2; // Wrong password
            }
        } else {
            delete res;
            delete pstmt;
            delete conn;
            return 2; // User not found
        }
    } catch (sql::SQLException &e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
        return 3;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 3;
    }
}

int SqlUtil::registerFromPlayerinfo(std::string playerID, std::string password, std::string email, std::string styleSet, std::string emailCode) {
    try {
        std::cout << "[Register] Starting registration for ID: " << playerID << std::endl;
        
        if (!authEmailCode(emailCode, email)) {
            std::cout << "[Register] Email code auth failed" << std::endl;
            return 2;
        }
        
        std::cout << "[Register] Connecting to DB..." << std::endl;
        sql::mysql::MySQL_Driver *driver;
        sql::Connection *conn;
        sql::PreparedStatement *pstmt;
        sql::ResultSet *res;
        driver = sql::mysql::get_mysql_driver_instance();
        conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
        conn->setSchema("bejeweled");

        // Check if account exists
        std::cout << "[Register] Checking if account exists..." << std::endl;
        pstmt = conn->prepareStatement("SELECT playerID FROM playerinfo WHERE playerID = ?");
        pstmt->setString(1, playerID);
        res = pstmt->executeQuery();
        if (res->next()) {
            std::cout << "[Register] Account already exists" << std::endl;
            delete res;
            delete pstmt;
            delete conn;
            return 3; // Account exists
        }
        delete res;
        delete pstmt;

        // Check if email exists
        std::cout << "[Register] Checking if email exists..." << std::endl;
        pstmt = conn->prepareStatement("SELECT email FROM playerinfo WHERE email = ?");
        pstmt->setString(1, email);
        res = pstmt->executeQuery();
        if (res->next()) {
            std::cout << "[Register] Email already exists" << std::endl;
            delete res;
            delete pstmt;
            delete conn;
            return 4; // Email exists
        }
        delete res;
        delete pstmt;

        // Security: Generate Salt and Hash
        std::cout << "[Register] Generating salt and hash..." << std::endl;
        std::string salt = generateSalt();
        int iterations = 10000;
        std::string passwordHash = hashPassword(password, salt, iterations);

        // Insert new user
        std::cout << "[Register] Inserting new user..." << std::endl;
        pstmt = conn->prepareStatement("INSERT INTO playerinfo (playerID, playerPassword, email, styleSet, salt, iterations) VALUES (?, ?, ?, ?, ?, ?)");
        pstmt->setString(1, playerID);
        pstmt->setString(2, passwordHash);
        pstmt->setString(3, email);
        pstmt->setString(4, styleSet);
        pstmt->setString(5, salt);
        pstmt->setInt(6, iterations);
                            
        pstmt->executeUpdate();
        std::cout << "[Register] Insert successful" << std::endl;
        delete pstmt;
        delete conn;
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

std::string SqlUtil::getSaltByPlayerIDfromPlayerinfo(std::string playerID) {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *conn;
    sql::Statement *stmt;
    sql::ResultSet *res;
    driver = sql::mysql::get_mysql_driver_instance();
    conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
    conn->setSchema("bejeweled");
    stmt = conn->createStatement();
    res = stmt->executeQuery("SELECT salt FROM playerinfo WHERE playerID = '" + playerID + "'");
    if (res->next()) {
        return res->getString("salt");
    }
    return "";
}

int SqlUtil::getIterationsByPlayerIDfromPlayerinfo(std::string playerID) {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *conn;
    sql::Statement *stmt;
    sql::ResultSet *res;
    driver = sql::mysql::get_mysql_driver_instance();
    conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
    conn->setSchema("bejeweled");
    stmt = conn->createStatement();
    res = stmt->executeQuery("SELECT iterations FROM playerinfo WHERE playerID = '" + playerID + "'");
    if (res->next()) {
        return res->getInt("iterations");
    }
    return 0;
}

void SqlUtil::setSaltByPlayerIDfromPlayerinfo(std::string playerID, std::string salt) {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *conn;
    sql::Statement *stmt;
    driver = sql::mysql::get_mysql_driver_instance();
    conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
    conn->setSchema("bejeweled");
    stmt = conn->createStatement();
    stmt->executeUpdate("UPDATE playerinfo SET salt = '" + salt + "' WHERE playerID = '" + playerID + "'");
}

void SqlUtil::setIterationsByPlayerIDfromPlayerinfo(std::string playerID, int iterations) {
    sql::mysql::MySQL_Driver *driver;
    sql::Connection *conn;
    sql::Statement *stmt;
    driver = sql::mysql::get_mysql_driver_instance();
    conn = driver->connect(Config::sqlIP + ":" + std::to_string(Config::sqlPort), Config::sqlUsername, Config::sqlPassword);
    conn->setSchema("bejeweled");
    stmt = conn->createStatement();
    stmt->executeUpdate("UPDATE playerinfo SET iterations = " + std::to_string(iterations) + " WHERE playerID = '" + playerID + "'");
}


