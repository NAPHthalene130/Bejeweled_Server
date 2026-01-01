#include "GameServer.h"
#include <functional>
#include <nlohmann/json.hpp>
#include "../util/SqlUtil.h"

using json = nlohmann::json;

GameServer::GameServer(unsigned short port)
    : acceptor(ioContext, tcp::endpoint(tcp::v4(), port)),
      gameTimer(ioContext) {
    
    // Set socket reuse address option
    acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    startAccept();
    std::cout << "[GameServer][Info]: Listening on port " << port << std::endl;
    
    resetGame();
}

GameServer::~GameServer() {
    stop();
}

void GameServer::run() {
    // Create worker thread pool
    std::size_t threadPoolSize = std::thread::hardware_concurrency();
    if (threadPoolSize == 0) threadPoolSize = 2;
    
    std::cout << "[GameServer][Info]: Starting GameServer with " << threadPoolSize << " worker threads" << std::endl;
    
    workerThreads.reserve(threadPoolSize);
    for (std::size_t i = 0; i < threadPoolSize; ++i) {
        workerThreads.emplace_back([this, i]() {
            try {
                ioContext.run();
            } catch (const std::exception& e) {
                std::cerr << "[GameServer][Error]: Exception in worker thread " << i << ": " << e.what() << std::endl;
            }
        });
    }
    
    // Wait for all worker threads
    for (auto& t : workerThreads) {
        if (t.joinable()) t.join();
    }
    
    std::cout << "[GameServer][Info]: All worker threads have finished" << std::endl;
}

void GameServer::stop() {
    if (!stopped.exchange(true)) {
        std::cout << "[GameServer][Info]: Stopping GameServer..." << std::endl;
        
        gameTimer.cancel();

        // Stop accepting new connections
        boost::system::error_code ec;
        acceptor.close(ec);
        if (ec) {
            std::cerr << "[GameServer][Error]: Error closing acceptor: " << ec.message() << std::endl;
        }
        
        // Stop ioContext
        ioContext.stop();
    }
}

void GameServer::startAccept() {
    if (stopped) return;
    
    auto newSocket = std::make_shared<tcp::socket>(ioContext);
    
    acceptor.async_accept(*newSocket,
        [this, newSocket](const boost::system::error_code& error) {
            handleAccept(newSocket, error);
        });
}

void GameServer::handleAccept(std::shared_ptr<tcp::socket> socket,
                                 const boost::system::error_code& error) {
    if (!error && !stopped) {
        try {
            // Set socket options
            socket->set_option(boost::asio::ip::tcp::no_delay(true)); 
            
            std::cout << "New connection from: "
                      << socket->remote_endpoint().address().to_string()
                      << ":" << socket->remote_endpoint().port() << std::endl;
            
            startReceive(socket, "");
        } catch (const boost::system::system_error& e) {
            std::cerr << "Error setting socket options: " << e.what() << std::endl;
        }
        
        // Continue accepting
        startAccept();
    } else if (error) {
        if (error != boost::asio::error::operation_aborted) {
            std::cerr << "Accept error: " << error.message() << std::endl;
        }
    }
}

void GameServer::startReceive(std::shared_ptr<tcp::socket> socket, std::string accumulatedBuffer) {
    if (stopped) return;
    
    // Use shared_ptr for buffer
    auto buffer = std::make_shared<std::vector<char>>(4096); 
    
    socket->async_read_some(boost::asio::buffer(*buffer),
        [this, socket, buffer, accumulatedBuffer](const boost::system::error_code& error,
                               std::size_t bytesTransferred) {
            handleReceive(socket, buffer, error, bytesTransferred, accumulatedBuffer);
        });
}

void GameServer::handleReceive(std::shared_ptr<tcp::socket> socket,
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
                // No JSON start found, clear buffer if too large to avoid memory growth
                if (accumulatedBuffer.length() > 4096) accumulatedBuffer.clear(); 
                break; 
            }
            
            if (startPos > 0) {
                accumulatedBuffer.erase(0, startPos);
                startPos = 0;
            }

            // Try to find the matching closing brace
            int braceCount = 0;
            bool inString = false;
            bool escaped = false;
            size_t endPos = std::string::npos;
            
            for (size_t i = 0; i < accumulatedBuffer.length(); ++i) {
                char c = accumulatedBuffer[i];
                if (escaped) {
                    escaped = false;
                    continue;
                }
                if (c == '\\') {
                    escaped = true;
                    continue;
                }
                if (c == '"') {
                    inString = !inString;
                    continue;
                }
                
                if (!inString) {
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
                
                std::cout << "[GameServer][Info]: Processing JSON: " << jsonStr << std::endl;
                
                bool parseSuccess = false;
                GameNetData receivedData;

                try {
                    auto j = json::parse(jsonStr);
                    receivedData = j.get<GameNetData>();
                    parseSuccess = true;
                } catch (const std::exception& e) {
                    std::cerr << "[GameServer][Error]: JSON parse error: " << e.what() << std::endl;
                }

                if (parseSuccess) {
                    int type = receivedData.getType();
                    if (type == 0) {
                        std::lock_guard<std::mutex> lock(gameMutex); // Protect shared state
                        std::string dataStr = receivedData.getData();
                        std::string id = receivedData.getID();

                        if (gameStarted) {
                            GameNetData reply;
                            reply.setType(0);
                            reply.setData("GAME_STARTED");
                            sendData(socket, reply);
                        } else {
                            if (dataStr == "EXIT") {
                                std::cout << "[GameServer][Info]: Client requested EXIT: " << id << std::endl;
                                
                                // Remove from maps
                                if (IdToNum.count(id)) {
                                    int num = IdToNum[id];
                                    numToId.erase(num);
                                    IdToNum.erase(id);
                                }
                                idToNetIOStream.erase(id);
                                connectedIds.erase(id);
                                
                                // Test connect and get room count
                                int roomHave = testConnectLocked();
                                
                                // Broadcast room count
                                GameNetData broadcastData;
                                broadcastData.setType(11);
                                broadcastData.setData(std::to_string(roomHave));
                                
                                // Inline globalSend logic (since we hold lock)
                                for (auto const& [currId, s] : idToNetIOStream) {
                                    if (s) {
                                        try {
                                            sendData(s, broadcastData);
                                        } catch (...) {
                                            // Ignore errors during broadcast
                                        }
                                    }
                                }
                            } else {
                                // Add ID to socket map
                                idToNetIOStream[id] = socket;
                                connectedIds.insert(id);
                                
                                // Send ENTER_ROOM to current socket
                                GameNetData privateData;
                                privateData.setType(0);
                                privateData.setData("ENTER_ROOM");
                                sendData(socket, privateData);
                                
                                // Add ID to number map
                                
                                int roomHave = testConnectLocked();
                                
                                // Broadcast room count
                                GameNetData broadcastData;
                                broadcastData.setType(11);
                                broadcastData.setData(std::to_string(roomHave));
                                
                                // Inline globalSend logic (since we hold lock)
                                for (auto const& [currId, s] : idToNetIOStream) {
                                    if (s) {
                                        try {
                                            sendData(s, broadcastData);
                                        } catch (...) {
                                            // Ignore errors during broadcast
                                        }
                                    }
                                }

                                if (roomHave == 3) {
                                    GameNetData data;
                                    data.setType(10);
                                    data.setData("GAME_STARTED");
                                    int index = 0;
                                    for (const std::string id : connectedIds) {
                                        IdToNum[id] = index++;
                                        numToId[index - 1] = id;
                                    }
                                    player1Score = 0;
                                    player2Score = 0;
                                    player3Score = 0;
                                    player4Score = 0;
                                    data.setIdToNum(IdToNum);
                                    for (auto const& [currId, s] : idToNetIOStream) {
                                        if (s) {
                                            try {
                                                sendData(s, data);
                                            } catch (...) {
                                                // Ignore errors during broadcast
                                            }
                                        }
                                    }
                                    gameStarted = true;
                                    startTimer(90);
                                }
                            }
                        }
                    } else if (type == 1) {
                        // TODO
                    } else if (type == 2) {
                        std::string id = receivedData.getID();
                        if (IdToNum.find(id) != IdToNum.end()) {
                            int num = IdToNum[id];
                            try {
                                std::string dataStr = receivedData.getData();
                                if (!dataStr.empty()) {
                                    int score = std::stoi(dataStr);
                                    if (num == 0) {
                                        player1Score = score;
                                    } else if (num == 1) {
                                        player2Score = score;
                                    } else if (num == 2) {
                                        player3Score = score;
                                    } else if (num == 3) {
                                        player4Score = score;
                                    }
                                }
                            } catch (const std::exception& e) {
                                std::cerr << "[GameServer][Error]: Invalid score data for type 2: " << receivedData.getData() << ", error: " << e.what() << std::endl;
                            }
                        }
                        for (auto const& [currId, s] : idToNetIOStream) {
                            if (s) {
                                try {
                                    sendData(s, receivedData);
                                } catch (...) {
                                    // Ignore errors during broadcast
                                }
                            }
                        }
                    } else if (type == 3) {
                        // TODO
                    } else if (type == 4) {
                        std::string id = receivedData.getID();
                        int score = receivedData.getMyScore();
                        if (IdToNum.find(id) != IdToNum.end()) {
                            int num = IdToNum[id];
                            if (num == 0) {
                                player1Score = score;
                            } else if (num == 1) {
                                player2Score = score;
                            } else if (num == 2) {
                                player3Score = score;
                            } else if (num == 3) {
                                player4Score = score;
                            }
                        }
                        for (auto const& [currId, s] : idToNetIOStream) {
                            if (s) {
                                try {
                                    sendData(s, receivedData);
                                } catch (...) {
                                    // Ignore errors during broadcast
                                }
                            }
                        }
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
            std::cerr << "[GameServer][Error]: Receive error: " << error.message() << std::endl;
        }
        // Ensure we clean up the connection on error as well
        removeConnection(socket);
    } else {
        // Connection closed
        std::cout << "[GameServer][Info]: Connection closed by peer" << std::endl;
        removeConnection(socket);
    }
}

void GameServer::removeConnection(std::shared_ptr<tcp::socket> socket) {
    std::lock_guard<std::mutex> lock(gameMutex);
    std::string idToRemove;
    for (auto const& [id, s] : idToNetIOStream) {
        if (s == socket) {
            idToRemove = id;
            break;
        }
    }
    if (!idToRemove.empty()) {
        idToNetIOStream.erase(idToRemove);
        connectedIds.erase(idToRemove);
        if (IdToNum.count(idToRemove)) {
            int num = IdToNum[idToRemove];
            numToId.erase(num);
            IdToNum.erase(idToRemove);
        }
        std::cout << "[GameServer][Info]: Removed connection for ID: " << idToRemove << std::endl;
        
        int roomHave = testConnectLocked();
        GameNetData broadcastData;
        broadcastData.setType(11);
        broadcastData.setData(std::to_string(roomHave));
        
        for (auto const& [currId, s] : idToNetIOStream) {
            if (s) {
                try {
                    sendData(s, broadcastData);
                } catch (...) {
                }
            }
        }
    }
}

void GameServer::startTimer(int seconds) {
    gameTimer.expires_after(std::chrono::seconds(seconds));
    gameTimer.async_wait([this](const boost::system::error_code& error) {
        handleTimer(error);
    });
}

void GameServer::handleTimer(const boost::system::error_code& error) {
    if (error != boost::asio::error::operation_aborted) {
        timeUp();
    }
}

void GameServer::timeUp() {
    std::lock_guard<std::mutex> lock(gameMutex);
    gameStarted = false;
    // TODO: Handle time up logic
    GameNetData timeUpData;
    timeUpData.setType(12);
    timeUpData.setData("Time Up");
    timeUpData.setIdToNum(IdToNum);
    timeUpData.setNumToId(numToId);
    timeUpData.setPlayer1Score(player1Score);
    timeUpData.setPlayer2Score(player2Score);
    timeUpData.setPlayer3Score(player3Score);
    timeUpData.setPlayer4Score(player4Score);
    
    // Send to all clients
    for (auto const& [id, socket] : idToNetIOStream) {
        if (socket) {
            try {
                sendData(socket, timeUpData);
            } catch (...) {
                // Ignore errors during broadcast
            }
        }
    }
    std::string id1 = numToId[0];
    std::string id2 = numToId[1];
    std::string id3 = numToId[2];

    SqlUtil::setMultiScoreByPlayerIDfromPlayerinfo(id1, player1Score);
    SqlUtil::setMultiScoreByPlayerIDfromPlayerinfo(id2, player2Score);
    SqlUtil::setMultiScoreByPlayerIDfromPlayerinfo(id3, player3Score);

    idToNetIOStream.clear();
    IdToNum.clear();
    numToId.clear();
    connectedIds.clear();
    roomPeopleHave = 0;
}

void GameServer::resetGame() {
    std::lock_guard<std::mutex> lock(gameMutex);
    gameStarted = false;
    roomPeopleHave = 0;
    IdToNum.clear();
    numToId.clear();
    idToNetIOStream.clear();
    connectedIds.clear();
    player1Board.clear();
    player2Board.clear();
    player3Board.clear();
    player4Board.clear();
    player1Score = 0;
    player2Score = 0;
    player3Score = 0;
    player4Score = 0;
}

// Getters and Setters - Adding locks where appropriate

bool GameServer::getGameStarted() const { 
    return gameStarted; 
}
void GameServer::setGameStarted(bool started) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    gameStarted = started; 
}

int GameServer::getRoomPeopleHave() const { return roomPeopleHave; }
void GameServer::setRoomPeopleHave(int count) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    roomPeopleHave = count; 
}

std::map<std::string, int> GameServer::getIdToNum() const { return IdToNum; }
void GameServer::setIdToNum(const std::map<std::string, int>& map) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    IdToNum = map; 
}

std::map<int, std::string> GameServer::getNumToId() const { return numToId; }
void GameServer::setNumToId(const std::map<int, std::string>& map) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    numToId = map; 
}

std::map<std::string, std::shared_ptr<boost::asio::ip::tcp::socket>> GameServer::getIdToNetIOStream() const { return idToNetIOStream; }
void GameServer::setIdToNetIOStream(const std::map<std::string, std::shared_ptr<boost::asio::ip::tcp::socket>>& map) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    idToNetIOStream = map; 
}

std::vector<std::vector<int>> GameServer::getPlayer1Board() const { return player1Board; }
void GameServer::setPlayer1Board(const std::vector<std::vector<int>>& board) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    player1Board = board; 
}

std::vector<std::vector<int>> GameServer::getPlayer2Board() const { return player2Board; }
void GameServer::setPlayer2Board(const std::vector<std::vector<int>>& board) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    player2Board = board; 
}

std::vector<std::vector<int>> GameServer::getPlayer3Board() const { return player3Board; }
void GameServer::setPlayer3Board(const std::vector<std::vector<int>>& board) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    player3Board = board; 
}

std::vector<std::vector<int>> GameServer::getPlayer4Board() const { return player4Board; }
void GameServer::setPlayer4Board(const std::vector<std::vector<int>>& board) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    player4Board = board; 
}

int GameServer::getPlayer1Score() const { return player1Score; }
void GameServer::setPlayer1Score(int score) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    player1Score = score; 
}

int GameServer::getPlayer2Score() const { return player2Score; }
void GameServer::setPlayer2Score(int score) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    player2Score = score; 
}

int GameServer::getPlayer3Score() const { return player3Score; }
void GameServer::setPlayer3Score(int score) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    player3Score = score; 
}

int GameServer::getPlayer4Score() const { return player4Score; }
void GameServer::setPlayer4Score(int score) { 
    std::lock_guard<std::mutex> lock(gameMutex);
    player4Score = score; 
}

std::set<std::string> GameServer::getConnectedIDs() const {
    std::lock_guard<std::mutex> lock(gameMutex);
    return connectedIds;
}

void GameServer::setConnectedIDs(const std::set<std::string>& ids) {
    std::lock_guard<std::mutex> lock(gameMutex);
    connectedIds = ids;
}

void GameServer::globalSend(GameNetData data) {
    std::lock_guard<std::mutex> lock(gameMutex);
    for (auto const& [id, socket] : idToNetIOStream) {
        if (socket) {
            try {
                sendData(socket, data);
            } catch (...) {
                // Ignore errors during broadcast
            }
        }
    }
}

void GameServer::sendData(std::shared_ptr<tcp::socket> socket, GameNetData data) {
    if (!socket || !socket->is_open()) return;

    // Convert data to json string
    json j = data;
    std::string s = j.dump();
    
    std::cout << "[GameServer][Info]: Sending data: " << s << std::endl;

    // Send data
    boost::asio::write(*socket, boost::asio::buffer(s));
    
    // Do not close the socket here. Let the connection persist or be closed by the client/error handler.
}

void GameServer::sendData(const std::string& id, GameNetData data) {
    std::lock_guard<std::mutex> lock(gameMutex);
    if (idToNetIOStream.count(id)) {
        auto socket = idToNetIOStream[id];
        sendData(socket, data);
    }
}

int GameServer::testConnect() {
    std::lock_guard<std::mutex> lock(gameMutex);
    return testConnectLocked();
}

int GameServer::testConnectLocked() {
    GameNetData data;
    data.setType(13);
    
    std::vector<std::string> idsToRemove;
    
    for (auto const& [id, socket] : idToNetIOStream) {
        try {
            sendData(socket, data);
        } catch (...) {
            idsToRemove.push_back(id);
        }
    }
    
    for (const auto& id : idsToRemove) {
        std::cout << "[GameServer][Info]: Removing disconnected client ID: " << id << std::endl;
        if (IdToNum.count(id)) {
            int num = IdToNum[id];
            numToId.erase(num);
            IdToNum.erase(id);
        }
        idToNetIOStream.erase(id);
        connectedIds.erase(id);
    }
    
    std::cout << "[GameServer][Info]: Active connections count: " << idToNetIOStream.size() << std::endl;
    if (!idToNetIOStream.empty()) {
        std::cout << "[GameServer][Info]: Connected Client IDs: ";
        for (auto const& [id, _] : idToNetIOStream) {
            std::cout << id << " ";
        }
        std::cout << std::endl;
    }
    
    return idToNetIOStream.size();
}
