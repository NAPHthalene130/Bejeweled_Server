#ifndef GAMESERVER_H
#define GAMESERVER_H

#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <string>
#include <map>
#include <boost/asio.hpp>
#include "GameNetData.h"

class GameServer {
    using tcp = boost::asio::ip::tcp;
public:
    GameServer(unsigned short port);
    ~GameServer();
    void run();
    void stop();

    // Timer methods
    void startTimer(int seconds);
    void timeUp();

    // Game logic methods
    void resetGame();
    
    void globalSend(GameNetData data);
    void sendData(std::shared_ptr<tcp::socket> socket, GameNetData data);
    void sendData(const std::string& id, GameNetData data);
    int testConnect();

    // Getters and Setters
    bool getGameStarted() const;
    void setGameStarted(bool started);

    int getRoomPeopleHave() const;
    void setRoomPeopleHave(int count);

    std::map<std::string, int> getIdToNum() const;
    void setIdToNum(const std::map<std::string, int>& map);

    std::map<int, std::string> getNumToId() const;
    void setNumToId(const std::map<int, std::string>& map);

    std::map<std::string, std::shared_ptr<tcp::socket>> getIdToNetIOStream() const;
    void setIdToNetIOStream(const std::map<std::string, std::shared_ptr<tcp::socket>>& map);

    std::vector<std::vector<int>> getPlayer1Board() const;
    void setPlayer1Board(const std::vector<std::vector<int>>& board);

    std::vector<std::vector<int>> getPlayer2Board() const;
    void setPlayer2Board(const std::vector<std::vector<int>>& board);

    std::vector<std::vector<int>> getPlayer3Board() const;
    void setPlayer3Board(const std::vector<std::vector<int>>& board);

    std::vector<std::vector<int>> getPlayer4Board() const;
    void setPlayer4Board(const std::vector<std::vector<int>>& board);

    int getPlayer1Score() const;
    void setPlayer1Score(int score);

    int getPlayer2Score() const;
    void setPlayer2Score(int score);

    int getPlayer3Score() const;
    void setPlayer3Score(int score);

    int getPlayer4Score() const;
    void setPlayer4Score(int score);

private:
    void startAccept();
    void handleAccept(std::shared_ptr<tcp::socket> socket,
                       const boost::system::error_code& error);
    void startReceive(std::shared_ptr<tcp::socket> socket);
    void handleReceive(std::shared_ptr<tcp::socket> socket,
                        std::shared_ptr<std::vector<char>> buffer,
                        const boost::system::error_code& error,
                        std::size_t bytesTransferred);
    
    // Timer handler
    void handleTimer(const boost::system::error_code& error);

    boost::asio::io_context ioContext;
    tcp::acceptor acceptor;
    std::vector<std::thread> workerThreads;
    std::atomic<bool> stopped{false};
    
    boost::asio::steady_timer gameTimer;

    // Game State
    bool gameStarted;
    int roomPeopleHave;
    std::map<std::string, int> IdToNum;
    std::map<int, std::string> numToId;
    std::map<std::string, std::shared_ptr<tcp::socket>> idToNetIOStream;
    std::vector<std::vector<int>> player1Board;
    std::vector<std::vector<int>> player2Board;
    std::vector<std::vector<int>> player3Board;
    std::vector<std::vector<int>> player4Board;
    int player1Score;
    int player2Score;
    int player3Score;
    int player4Score;
};

#endif // GAMESERVER_H
