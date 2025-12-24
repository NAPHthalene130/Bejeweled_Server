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

int GameNetData::getSeconds() const { return seconds; }
void GameNetData::setSeconds(int seconds) { this->seconds = seconds; }

std::vector<std::pair<int,int>> GameNetData::getCoordinates() const { return coordinates; }
void GameNetData::setCoordinates(const std::vector<std::pair<int,int>>& coordinates) { this->coordinates = coordinates; }

void to_json(nlohmann::json& j, const GameNetData& p) {
    j = nlohmann::json{
        {"type", p.type},
        {"ID", p.ID},
        {"data", p.data},
        {"IdToNum", p.IdToNum},
        {"NumToId", p.NumToId},

        {"myBoard", p.myBoard},
        {"player1Score", p.player1Score},
        {"player2Score", p.player2Score},
        {"player3Score", p.player3Score},
        {"player4Score", p.player4Score},
        {"myScore", p.myScore},
        {"seconds", p.seconds},
        {"coordinates", p.coordinates}
    };
}

void from_json(const nlohmann::json& j, GameNetData& p) {
    if (j.contains("type")) j.at("type").get_to(p.type);
    if (j.contains("ID")) j.at("ID").get_to(p.ID);
    if (j.contains("data")) j.at("data").get_to(p.data);
    if (j.contains("IdToNum")) j.at("IdToNum").get_to(p.IdToNum);
    if (j.contains("NumToId")) j.at("NumToId").get_to(p.NumToId);

    if (j.contains("myBoard")) j.at("myBoard").get_to(p.myBoard);
    if (j.contains("player1Score")) j.at("player1Score").get_to(p.player1Score);
    if (j.contains("player2Score")) j.at("player2Score").get_to(p.player2Score);
    if (j.contains("player3Score")) j.at("player3Score").get_to(p.player3Score);
    if (j.contains("player4Score")) j.at("player4Score").get_to(p.player4Score);
    if (j.contains("myScore")) j.at("myScore").get_to(p.myScore);
    if (j.contains("seconds")) j.at("seconds").get_to(p.seconds);
    if (j.contains("coordinates")) j.at("coordinates").get_to(p.coordinates);
}
