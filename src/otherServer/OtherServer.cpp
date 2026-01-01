#include "OtherServer.h"
#include <functional>
#include <nlohmann/json.hpp>
#include "../util/SqlUtil.h"
#include "OtherNetData.h"

using json = nlohmann::json;

OtherServer::OtherServer(unsigned short port)
    : acceptor(ioContext, tcp::endpoint(tcp::v4(), port)) {
    
    // Set socket reuse address option
    acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    startAccept();
    std::cout << "[OtherServer][Info]: Listening on port " << port << std::endl;
}

OtherServer::~OtherServer() {
    stop();
}

void OtherServer::run() {
    // Create worker thread pool
    std::size_t threadPoolSize = std::thread::hardware_concurrency();
    if (threadPoolSize == 0) threadPoolSize = 2;
    
    std::cout << "[OtherServer][Info]: Starting OtherServer with " << threadPoolSize << " worker threads" << std::endl;
    
    workerThreads.reserve(threadPoolSize);
    for (std::size_t i = 0; i < threadPoolSize; ++i) {
        workerThreads.emplace_back([this, i]() {
            try {
                ioContext.run();
            } catch (const std::exception& e) {
                std::cerr << "[OtherServer][Error]: Exception in worker thread " << i << ": " << e.what() << std::endl;
            }
        });
    }
    
    // Wait for all worker threads
    for (auto& t : workerThreads) {
        if (t.joinable()) t.join();
    }
    
    std::cout << "[OtherServer][Info]: All worker threads have finished" << std::endl;
}

void OtherServer::stop() {
    if (!stopped.exchange(true)) {
        std::cout << "[OtherServer][Info]: Stopping OtherServer..." << std::endl;
        
        // Stop accepting new connections
        boost::system::error_code ec;
        acceptor.close(ec);
        if (ec) {
            std::cerr << "[OtherServer][Error]: Error closing acceptor: " << ec.message() << std::endl;
        }
        
        // Stop ioContext
        ioContext.stop();
    }
}

void OtherServer::startAccept() {
    if (stopped) return;
    
    auto newSocket = std::make_shared<tcp::socket>(ioContext);
    
    acceptor.async_accept(*newSocket,
        [this, newSocket](const boost::system::error_code& error) {
            handleAccept(newSocket, error);
        });
}

void OtherServer::handleAccept(std::shared_ptr<tcp::socket> socket,
                                 const boost::system::error_code& error) {
    if (!error && !stopped) {
        try {
            // Set socket options
            socket->set_option(boost::asio::ip::tcp::no_delay(true)); 
            
            std::cout << "[OtherServer][Info]: New connection from: "
                      << socket->remote_endpoint().address().to_string()
                      << ":" << socket->remote_endpoint().port() << std::endl;
            
            startReceive(socket, "");
        } catch (const boost::system::system_error& e) {
            std::cerr << "[OtherServer][Error]: Error setting socket options: " << e.what() << std::endl;
        }
        
        // Continue accepting
        startAccept();
    } else if (error) {
        if (error != boost::asio::error::operation_aborted) {
            std::cerr << "[OtherServer][Error]: Accept error: " << error.message() << std::endl;
        }
    }
}

void OtherServer::startReceive(std::shared_ptr<tcp::socket> socket, std::string accumulatedBuffer) {
    if (stopped) return;
    
    // Use shared_ptr for buffer
    auto buffer = std::make_shared<std::vector<char>>(4096); 
    
    socket->async_read_some(boost::asio::buffer(*buffer),
        [this, socket, buffer, accumulatedBuffer](const boost::system::error_code& error,
                               std::size_t bytesTransferred) {
            handleReceive(socket, buffer, error, bytesTransferred, accumulatedBuffer);
        });
}

void OtherServer::handleReceive(std::shared_ptr<tcp::socket> socket,
                                  std::shared_ptr<std::vector<char>> buffer,
                                  const boost::system::error_code& error,
                                  std::size_t bytesTransferred,
                                  std::string accumulatedBuffer) {
    if (stopped) return;
    
    if (!error) {
        // Append new data to accumulated buffer
        accumulatedBuffer.append(buffer->data(), bytesTransferred);
        
        // Process accumulated buffer for complete JSON objects
        while (!accumulatedBuffer.empty()) {
            // Skip whitespace/garbage at start
            size_t startPos = accumulatedBuffer.find('{');
            if (startPos == std::string::npos) {
                // No JSON start found, keep buffer if it might be incomplete, or clear if garbage
                // For simplicity, if we don't find '{', we might clear it or wait for more.
                // But if the buffer is just garbage, we should clear it. 
                // However, we might have received half a string before '{'.
                // If the buffer doesn't contain '{' at all, and we just appended, 
                // it's possible we are in the middle of something or just garbage.
                // Let's assume we look for the first '{'.
                accumulatedBuffer.clear(); 
                break;
            }
            
            if (startPos > 0) {
                accumulatedBuffer.erase(0, startPos);
            }
            
            // Try to find the matching closing brace
            // Simple brace counting
            int braceCount = 0;
            size_t endPos = std::string::npos;
            bool insideString = false;
            bool escape = false;
            
            for (size_t i = 0; i < accumulatedBuffer.length(); ++i) {
                char c = accumulatedBuffer[i];
                if (escape) {
                    escape = false;
                    continue;
                }
                if (c == '\\') {
                    escape = true;
                    continue;
                }
                if (c == '"') {
                    insideString = !insideString;
                    continue;
                }
                if (!insideString) {
                    if (c == '{') {
                        braceCount++;
                    } else if (c == '}') {
                        braceCount--;
                        if (braceCount == 0) {
                            endPos = i;
                            break;
                        }
                    }
                }
            }
            
            if (endPos != std::string::npos) {
                // Found a complete JSON object
                std::string jsonStr = accumulatedBuffer.substr(0, endPos + 1);
                accumulatedBuffer.erase(0, endPos + 1);
                
                std::cout << "[OtherServer][Info]: Processing JSON: " << jsonStr << std::endl;
                
                bool parseSuccess = false;
                OtherNetData receivedData;

                try {
                    auto j = json::parse(jsonStr);
                    receivedData = j.get<OtherNetData>();
                    parseSuccess = true;
                } catch (const std::exception& e) {
                    std::cerr << "[OtherServer][Error]: JSON parse error: " << e.what() << std::endl;
                }

                if (parseSuccess) {
                    int type = receivedData.getType();
                    if (type == 10) { // Client get achievement
                        std::string playerID = receivedData.getId();
                        std::string achievementStr = SqlUtil::getAchievementStrByPlayerIDfromPlayerinfo(playerID);
                        receivedData.setAchievementStr(achievementStr);
                        sendData(socket, receivedData);
                    } else if (type == 11) { // Client set achievement
                        std::string playerID = receivedData.getId();
                        std::string achievementStr = receivedData.getAchievementStr();
                        SqlUtil::setAchievementStrByPlayerIDfromPlayerinfo(playerID, achievementStr);
                    } else if (type == 20) { // Client get money
                        std::string playerID = receivedData.getId();
                        int money = SqlUtil::getMoneyByPlayerIDfromPlayerinfo(playerID);
                        receivedData.setMoney(money);
                        sendData(socket, receivedData);
                    } else if (type == 21) { // Client set money
                        std::string playerID = receivedData.getId();
                        int money = receivedData.getMoney();
                        SqlUtil::setMoneyByPlayerIDfromPlayerinfo(playerID, money);
                    } else if (type == 30) { // Client get rank
                        std::vector<std::vector<std::pair<std::string, int>>> ranks = SqlUtil::getRanksFromPlayerinfo();
                        receivedData.setNormalRank(ranks[0]);
                        receivedData.setWhirlRank(ranks[1]);
                        receivedData.setMultiRank(ranks[2]);
                        sendData(socket, receivedData);
                    } else if (type == 31) {
                        // TODO
                    } else if (type == 40) { // Client get prop nums
                        std::string playerID = receivedData.getId();
                        std::vector<int> propNums = SqlUtil::getPropsFromPlayerinfo(playerID);
                        receivedData.setPropNums(propNums);
                        sendData(socket, receivedData);
                    } else if (type == 41) { // Client set prop nums
                        std::string playerID = receivedData.getId();
                        std::vector<int> propNums = receivedData.getPropNums();
                        SqlUtil::setPropsFromPlayerinfo(playerID, propNums);
                    } else if (type == 50) { // Client submit normal mode time
                        std::string playerID = receivedData.getId();
                        int normalTime = receivedData.getNormalTime();
                        SqlUtil::setNormalSecondsByPlayerIDfromPlayerinfo(playerID, normalTime);
                    } else if (type == 51) { // Client submit whirl mode time
                        // TODO
                        std::string playerID = receivedData.getId();
                        int whirlTime = receivedData.getWhirlTime();
                        SqlUtil::setWhirlSecondsByPlayerIDfromPlayerinfo(playerID, whirlTime);
                    }
                }
            } else {
                // Incomplete JSON, wait for more data
                break;
            }
        }
        
        // Continue receive with remaining buffer
        startReceive(socket, accumulatedBuffer);
        
    } else if (error != boost::asio::error::eof) {
        if (error != boost::asio::error::operation_aborted) {
            std::cerr << "[OtherServer][Error]: Receive error: " << error.message() << std::endl;
        }
    } else {
        // Connection closed
        std::cout << "[OtherServer][Info]: Connection closed by peer" << std::endl;
    }
}

void OtherServer::sendData(std::shared_ptr<tcp::socket> socket, OtherNetData data) {
    if (!socket || !socket->is_open()) return;

    // Convert data to json string
    json j = data;
    std::string response = j.dump();

    boost::asio::async_write(*socket,
                             boost::asio::buffer(response),
                             [socket](const boost::system::error_code& writeError,
                                      std::size_t /*bytesWritten*/) {
                                 if (writeError) {
                                     if (writeError != boost::asio::error::operation_aborted) {
                                         std::cerr << "[OtherServer][Error]: Write error: " << writeError.message() << std::endl;
                                     }
                                 }
                             });
}
