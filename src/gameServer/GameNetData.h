#ifndef GAME_NET_DATA_H
#define GAME_NET_DATA_H
#include <string>
#include <json.hpp>
#include <vector>
#include <map>

class GameNetData{
    using string = std::string;
public:
    GameNetData();
    ~GameNetData();

    int getType() const;
    void setType(int type);

    string getID() const;
    void setID(const string& ID);

    string getData() const;
    void setData(const string& data);

    std::map<string, int> getIdToNum() const;
    void setIdToNum(const std::map<string, int>& IdToNum);

    std::map<int, string> getNumToId() const;
    void setNumToId(const std::map<int, string>& NumToId);

    std::vector<std::vector<int>> getPlayer1Board() const;
    void setPlayer1Board(const std::vector<std::vector<int>>& player1Board);

    std::vector<std::vector<int>> getPlayer2Board() const;
    void setPlayer2Board(const std::vector<std::vector<int>>& player2Board);

    std::vector<std::vector<int>> getPlayer3Board() const;
    void setPlayer3Board(const std::vector<std::vector<int>>& player3Board);

    std::vector<std::vector<int>> getPlayer4Board() const;
    void setPlayer4Board(const std::vector<std::vector<int>>& player4Board);

    std::vector<std::vector<int>> getMyBoard() const;
    void setMyBoard(const std::vector<std::vector<int>>& myBoard);

    int getPlayer1Score() const;
    void setPlayer1Score(int player1Score);

    int getPlayer2Score() const;
    void setPlayer2Score(int player2Score);

    int getPlayer3Score() const;
    void setPlayer3Score(int player3Score);

    int getPlayer4Score() const;
    void setPlayer4Score(int player4Score);

    int getMyScore() const;
    void setMyScore(int myScore);

private:
    int type;
    string ID;
    string data;
    std::map<string,int> IdToNum;
    std::map<int,string> NumToId;
    std::vector<std::vector<int>> player1Board;
    std::vector<std::vector<int>> player2Board;
    std::vector<std::vector<int>> player3Board;
    std::vector<std::vector<int>> player4Board;
    std::vector<std::vector<int>> myBoard;
    int player1Score;
    int player2Score;
    int player3Score;
    int player4Score;
    int myScore;
    friend void to_json(nlohmann::json& j, const GameNetData& p);
    friend void from_json(const nlohmann::json& j, GameNetData& p);
};

#endif // GAME_NET_DATA_H
