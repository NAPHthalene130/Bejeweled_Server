#include "OtherNetData.h"

// Implement Getters
const std::string& OtherNetData::getId() const { return id; }
int OtherNetData::getMoney() const { return money; }
const std::string& OtherNetData::getAchievementStr() const { return achievementStr; }
const std::vector<std::pair<std::string, int>>& OtherNetData::getNormalRank() const { return normalRank; }
const std::vector<std::pair<std::string, int>>& OtherNetData::getWhirlRank() const { return whirlRank; }
const std::vector<std::pair<std::string, int>>& OtherNetData::getMultiRank() const { return multiRank; }
int OtherNetData::getType() const { return type; }
const std::string& OtherNetData::getData() const { return data; }
const std::vector<int>& OtherNetData::getPropNums() const { return propNums; }
int OtherNetData::getNormalTime() const { return normalTime; }
int OtherNetData::getWhirlTime() const { return whirlTime; }

// Implement Setters
void OtherNetData::setId(const std::string& id) { this->id = id; }
void OtherNetData::setMoney(int money) { this->money = money; }
void OtherNetData::setAchievementStr(const std::string& achievementStr) { this->achievementStr = achievementStr; }
void OtherNetData::setNormalRank(const std::vector<std::pair<std::string, int>>& normalRank) { this->normalRank = normalRank; }
void OtherNetData::setWhirlRank(const std::vector<std::pair<std::string, int>>& whirlRank) { this->whirlRank = whirlRank; }
void OtherNetData::setMultiRank(const std::vector<std::pair<std::string, int>>& multiRank) { this->multiRank = multiRank; }
void OtherNetData::setType(int type) { this->type = type; }
void OtherNetData::setData(const std::string& data) { this->data = data; }
void OtherNetData::setPropNums(const std::vector<int>& propNums) { this->propNums = propNums; }
void OtherNetData::setNormalTime(int normalTime) { this->normalTime = normalTime; }
void OtherNetData::setWhirlTime(int whirlTime) { this->whirlTime = whirlTime; }

// Implement JSON functions
void to_json(nlohmann::json& j, const OtherNetData& p) {
    j = nlohmann::json{
        {"type", p.type},
        {"data", p.data},
        {"id", p.id},
        {"money", p.money},
        {"achievementStr", p.achievementStr},
        {"normalRank", p.normalRank},
        {"whirlRank", p.whirlRank},
        {"multiRank", p.multiRank},
        {"propNums", p.propNums},
        {"normalTime", p.normalTime},
        {"whirlTime", p.whirlTime}
    };
}

void from_json(const nlohmann::json& j, OtherNetData& p) {
    if(j.contains("type")) j.at("type").get_to(p.type);
    if(j.contains("data")) j.at("data").get_to(p.data);
    if(j.contains("id")) j.at("id").get_to(p.id);
    if(j.contains("money")) j.at("money").get_to(p.money);
    if(j.contains("achievementStr")) j.at("achievementStr").get_to(p.achievementStr);
    if(j.contains("normalRank")) j.at("normalRank").get_to(p.normalRank);
    if(j.contains("whirlRank")) j.at("whirlRank").get_to(p.whirlRank);
    if(j.contains("multiRank")) j.at("multiRank").get_to(p.multiRank);
    if(j.contains("propNums")) j.at("propNums").get_to(p.propNums);
    if(j.contains("normalTime")) j.at("normalTime").get_to(p.normalTime);
    if(j.contains("whirlTime")) j.at("whirlTime").get_to(p.whirlTime);
}
