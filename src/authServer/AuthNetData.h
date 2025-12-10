#ifndef AUTH_NET_DATA_H
#define AUTH_NET_DATA_H
#include <string>
#include <json.hpp>

class AuthNetData{
    using string = std::string;
public:
    AuthNetData();
    ~AuthNetData();
    int getType();
    string getId();
    string getPassword();
    string getEmail();
    string getData();
    void setType(int type);
    void setId(string id);
    void setPassword(string password);
    void setEmail(string email);
    void setData(string data);
private:
    int type; //1:登录 2:注册
    string id;
    string password;
    string email;
    string data;
    
    friend void toJson(nlohmann::json& j, const AuthNetData& p);
    friend void fromJson(const nlohmann::json& j, AuthNetData& p);
};

#endif // AUTH_NET_DATA_H
