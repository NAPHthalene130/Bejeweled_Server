#include "GameServer.h"
#include <functional>
#include "json.hpp"

using json = nlohmann::json;

GameServer::GameServer(unsigned short port)
    : acceptor(ioContext, tcp::endpoint(tcp::v4(), port)),
      gameTimer(ioContext) {
    
    // Set socket reuse address option
    acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    startAccept();
    std::cout << "GameServer listening on port " << port << std::endl;
    
    resetGame();
}

GameServer::~GameServer() {
    stop();
}

void GameServer::run() {
    // Create worker thread pool
    std::size_t threadPoolSize = std::thread::hardware_concurrency();
    if (threadPoolSize == 0) threadPoolSize = 2;
    
    std::cout << "Starting GameServer with " << threadPoolSize << " worker threads" << std::endl;
    
    workerThreads.reserve(threadPoolSize);
    for (std::size_t i = 0; i < threadPoolSize; ++i) {
        workerThreads.emplace_back([this, i]() {
            try {
                ioContext.run();
            } catch (const std::exception& e) {
                std::cerr << "Exception in worker thread " << i << ": " << e.what() << std::endl;
            }
        });
    }
    
    // Wait for all worker threads
    for (auto& t : workerThreads) {
        if (t.joinable()) t.join();
    }
    
    std::cout << "All worker threads have finished" << std::endl;
}

void GameServer::stop() {
    if (!stopped.exchange(true)) {
        std::cout << "Stopping GameServer..." << std::endl;
        
        gameTimer.cancel();

        // Stop accepting new connections
        boost::system::error_code ec;
        acceptor.close(ec);
        if (ec) {
            std::cerr << "Error closing acceptor: " << ec.message() << std::endl;
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
            
            startReceive(socket);
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

void GameServer::startReceive(std::shared_ptr<tcp::socket> socket) {
    if (stopped) return;
    
    // Use shared_ptr for buffer
    auto buffer = std::make_shared<std::vector<char>>(4096); 
    
    socket->async_read_some(boost::asio::buffer(*buffer),
        [this, socket, buffer](const boost::system::error_code& error,
                               std::size_t bytesTransferred) {
            handleReceive(socket, buffer, error, bytesTransferred);
        });
}

void GameServer::handleReceive(std::shared_ptr<tcp::socket> socket,
                                  std::shared_ptr<std::vector<char>> buffer,
                                  const boost::system::error_code& error,
                                  std::size_t bytesTransferred) {
    if (stopped) return;
    
    if (!error) {
        std::string receivedStr(buffer->data(), bytesTransferred);
        // std::cout << "Received " << bytesTransferred << " bytes" << std::endl;
        
        GameNetData receivedData;
        bool parseSuccess = false;

        // Attempt to parse JSON
        try {
            auto j = json::parse(receivedStr);
            receivedData = j.get<GameNetData>();
            parseSuccess = true;
        } catch (...) {
            // Parsing failed, might need base64 decode or other handling if required
            // For now, we assume simple JSON or try base64 if simple fails as per AuthServer pattern
             try {
                // Simple Base64 decode attempt (simplified version of AuthServer's logic without OpenSSL dependency if possible, 
                // but since we are in the same project, we could reuse or just stick to basic JSON for GameServer)
                // For this task, I'll stick to basic JSON parsing success/fail. 
                // If the user needs the full AuthServer decryption logic, I'd need to include OpenSSL headers and copy those methods.
                // Given the prompt "similar to receiving GameNetData info method", I'll assume standard JSON.
            } catch (...) {}
        }

        if (parseSuccess) {
            int type = receivedData.getType();
            if (type == 0) {
                if (gameStarted) {
                    GameNetData reply;
                    reply.setType(0);
                    reply.setData("GAME_STARTED");
                    sendData(socket, reply);
                } else {
                    // Add ID to socket map
                    idToNetIOStream[receivedData.getID()] = socket;
                    
                    int roomHave = testConnect();
                    
                    // Broadcast room count
                    GameNetData broadcastData;
                    broadcastData.setType(11);
                    broadcastData.setData(std::to_string(roomHave));
                    globalSend(broadcastData);
                    
                    // Send ENTER_ROOM to current socket
                    GameNetData privateData;
                    privateData.setType(0);
                    privateData.setData("ENTER_ROOM");
                    sendData(socket, privateData);
                }
            } else if (type == 1) {
                // TODO
            } else if (type == 2) {
                // TODO
            } else if (type == 3) {
                // TODO
            } else if (type == 4) {
                // TODO
            }
        } else {
            // std::cerr << "Failed to parse GameNetData" << std::endl;
        }
        
        // Continue receive
        startReceive(socket);
    } else if (error != boost::asio::error::eof) {
        if (error != boost::asio::error::operation_aborted) {
            std::cerr << "Receive error: " << error.message() << std::endl;
        }
    } else {
        // Connection closed
        // std::cout << "Connection closed by peer" << std::endl;
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
    // TODO: Handle time up logic
}

void GameServer::resetGame() {
    gameStarted = false;
    roomPeopleHave = 0;
    IdToNum.clear();
    numToId.clear();
    idToNetIOStream.clear();
    player1Board.clear();
    player2Board.clear();
    player3Board.clear();
    player4Board.clear();
    player1Score = 0;
    player2Score = 0;
    player3Score = 0;
    player4Score = 0;
}

// Getters and Setters

bool GameServer::getGameStarted() const { return gameStarted; }
void GameServer::setGameStarted(bool started) { gameStarted = started; }

int GameServer::getRoomPeopleHave() const { return roomPeopleHave; }
void GameServer::setRoomPeopleHave(int count) { roomPeopleHave = count; }

std::map<std::string, int> GameServer::getIdToNum() const { return IdToNum; }
void GameServer::setIdToNum(const std::map<std::string, int>& map) { IdToNum = map; }

std::map<int, std::string> GameServer::getNumToId() const { return numToId; }
void GameServer::setNumToId(const std::map<int, std::string>& map) { numToId = map; }

std::map<std::string, std::shared_ptr<boost::asio::ip::tcp::socket>> GameServer::getIdToNetIOStream() const { return idToNetIOStream; }
void GameServer::setIdToNetIOStream(const std::map<std::string, std::shared_ptr<boost::asio::ip::tcp::socket>>& map) { idToNetIOStream = map; }

std::vector<std::vector<int>> GameServer::getPlayer1Board() const { return player1Board; }
void GameServer::setPlayer1Board(const std::vector<std::vector<int>>& board) { player1Board = board; }

std::vector<std::vector<int>> GameServer::getPlayer2Board() const { return player2Board; }
void GameServer::setPlayer2Board(const std::vector<std::vector<int>>& board) { player2Board = board; }

std::vector<std::vector<int>> GameServer::getPlayer3Board() const { return player3Board; }
void GameServer::setPlayer3Board(const std::vector<std::vector<int>>& board) { player3Board = board; }

std::vector<std::vector<int>> GameServer::getPlayer4Board() const { return player4Board; }
void GameServer::setPlayer4Board(const std::vector<std::vector<int>>& board) { player4Board = board; }

int GameServer::getPlayer1Score() const { return player1Score; }
void GameServer::setPlayer1Score(int score) { player1Score = score; }

int GameServer::getPlayer2Score() const { return player2Score; }
void GameServer::setPlayer2Score(int score) { player2Score = score; }

int GameServer::getPlayer3Score() const { return player3Score; }
void GameServer::setPlayer3Score(int score) { player3Score = score; }

int GameServer::getPlayer4Score() const { return player4Score; }
void GameServer::setPlayer4Score(int score) { player4Score = score; }

void GameServer::globalSend(GameNetData data) {
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
    
    // Send data
    boost::asio::write(*socket, boost::asio::buffer(s));
    
    // Close the socket as requested
    boost::system::error_code ec;
    socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket->close(ec);
}

int GameServer::testConnect() {
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
        if (IdToNum.count(id)) {
            int num = IdToNum[id];
            numToId.erase(num);
            IdToNum.erase(id);
        }
        idToNetIOStream.erase(id);
    }
    
    return idToNetIOStream.size();
}
