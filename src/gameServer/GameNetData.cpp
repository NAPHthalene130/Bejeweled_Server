#include "GameNetData.h"

GameNetData::GameNetData() : 
    type(0), 
    player1Score(0), 
    player2Score(0), 
    player3Score(0), 
    player4Score(0), 
    myScore(0) 
{
}

GameNetData::~GameNetData() 
{
}

int GameNetData::getType() const { return type; }
void GameNetData::setType(int type) { this->type = type; }

std::string GameNetData::getID() const { return ID; }
void GameNetData::setID(const std::string& ID) { this->ID = ID; }

std::string GameNetData::getData() const { return data; }
void GameNetData::setData(const std::string& data) { this->data = data; }

std::map<std::string, int> GameNetData::getIdToNum() const { return IdToNum; }
void GameNetData::setIdToNum(const std::map<std::string, int>& IdToNum) { this->IdToNum = IdToNum; }

std::map<int, std::string> GameNetData::getNumToId() const { return NumToId; }
void GameNetData::setNumToId(const std::map<int, std::string>& NumToId) { this->NumToId = NumToId; }

std::vector<std::vector<int>> GameNetData::getPlayer1Board() const { return player1Board; }
void GameNetData::setPlayer1Board(const std::vector<std::vector<int>>& player1Board) { this->player1Board = player1Board; }

std::vector<std::vector<int>> GameNetData::getPlayer2Board() const { return player2Board; }
void GameNetData::setPlayer2Board(const std::vector<std::vector<int>>& player2Board) { this->player2Board = player2Board; }

std::vector<std::vector<int>> GameNetData::getPlayer3Board() const { return player3Board; }
void GameNetData::setPlayer3Board(const std::vector<std::vector<int>>& player3Board) { this->player3Board = player3Board; }

std::vector<std::vector<int>> GameNetData::getPlayer4Board() const { return player4Board; }
void GameNetData::setPlayer4Board(const std::vector<std::vector<int>>& player4Board) { this->player4Board = player4Board; }

std::vector<std::vector<int>> GameNetData::getMyBoard() const { return myBoard; }
void GameNetData::setMyBoard(const std::vector<std::vector<int>>& myBoard) { this->myBoard = myBoard; }

int GameNetData::getPlayer1Score() const { return player1Score; }
void GameNetData::setPlayer1Score(int player1Score) { this->player1Score = player1Score; }

int GameNetData::getPlayer2Score() const { return player2Score; }
void GameNetData::setPlayer2Score(int player2Score) { this->player2Score = player2Score; }

int GameNetData::getPlayer3Score() const { return player3Score; }
void GameNetData::setPlayer3Score(int player3Score) { this->player3Score = player3Score; }

int GameNetData::getPlayer4Score() const { return player4Score; }
void GameNetData::setPlayer4Score(int player4Score) { this->player4Score = player4Score; }

int GameNetData::getMyScore() const { return myScore; }
void GameNetData::setMyScore(int myScore) { this->myScore = myScore; }

void to_json(nlohmann::json& j, const GameNetData& p) {
    j = nlohmann::json{
        {"type", p.type},
        {"ID", p.ID},
        {"data", p.data},
        {"IdToNum", p.IdToNum},
        {"NumToId", p.NumToId},
        {"player1Board", p.player1Board},
        {"player2Board", p.player2Board},
        {"player3Board", p.player3Board},
        {"player4Board", p.player4Board},
        {"myBoard", p.myBoard},
        {"player1Score", p.player1Score},
        {"player2Score", p.player2Score},
        {"player3Score", p.player3Score},
        {"player4Score", p.player4Score},
        {"myScore", p.myScore}
    };
}

void from_json(const nlohmann::json& j, GameNetData& p) {
    if (j.contains("type")) j.at("type").get_to(p.type);
    if (j.contains("ID")) j.at("ID").get_to(p.ID);
    if (j.contains("data")) j.at("data").get_to(p.data);
    if (j.contains("IdToNum")) j.at("IdToNum").get_to(p.IdToNum);
    if (j.contains("NumToId")) j.at("NumToId").get_to(p.NumToId);
    if (j.contains("player1Board")) j.at("player1Board").get_to(p.player1Board);
    if (j.contains("player2Board")) j.at("player2Board").get_to(p.player2Board);
    if (j.contains("player3Board")) j.at("player3Board").get_to(p.player3Board);
    if (j.contains("player4Board")) j.at("player4Board").get_to(p.player4Board);
    if (j.contains("myBoard")) j.at("myBoard").get_to(p.myBoard);
    if (j.contains("player1Score")) j.at("player1Score").get_to(p.player1Score);
    if (j.contains("player2Score")) j.at("player2Score").get_to(p.player2Score);
    if (j.contains("player3Score")) j.at("player3Score").get_to(p.player3Score);
    if (j.contains("player4Score")) j.at("player4Score").get_to(p.player4Score);
    if (j.contains("myScore")) j.at("myScore").get_to(p.myScore);
}
