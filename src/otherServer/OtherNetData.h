#ifndef OTHER_NET_DATA_H
#define OTHER_NET_DATA_H

#include <string>
#include <vector>
#include <json.hpp>

class OtherNetData
{
public:
    OtherNetData() = default;
    ~OtherNetData() = default;

    const std::string& getId() const;
    int getMoney() const;
    const std::string& getAchievementStr() const;
    const std::vector<std::pair<std::string, int>>& getNormalRank() const;
    const std::vector<std::pair<std::string, int>>& getWhirlRank() const;
    const std::vector<std::pair<std::string, int>>& getMultiRank() const;
    int getType() const;
    const std::string& getData() const;

    void setId(const std::string& id);
    void setMoney(int money);
    void setAchievementStr(const std::string& achievementStr);
    void setNormalRank(const std::vector<std::pair<std::string, int>>& normalRank);
    void setWhirlRank(const std::vector<std::pair<std::string, int>>& whirlRank);
    void setMultiRank(const std::vector<std::pair<std::string, int>>& multiRank);
    void setType(int type);
    void setData(const std::string& data);

private:
    int type;
    std::string data;
    std::string id;
    int money;
    std::string achievementStr;
    std::vector<std::pair<std::string, int>> normalRank;
    std::vector<std::pair<std::string, int>> whirlRank;
    std::vector<std::pair<std::string, int>> multiRank;

    friend void to_json(nlohmann::json& j, const OtherNetData& p);
    friend void from_json(const nlohmann::json& j, OtherNetData& p);
};

#endif // OTHER_NET_DATA_H
