#include "AuthNetData.h"

AuthNetData::AuthNetData()
{
}

AuthNetData::~AuthNetData()
{
}

int AuthNetData::getType()
{
    return type;
}

std::string AuthNetData::getId()
{
    return id;
}

std::string AuthNetData::getPassword()
{
    return password;
}

std::string AuthNetData::getEmail()
{
    return email;
}

std::string AuthNetData::getData()
{
    return data;
}

void AuthNetData::setType(int type)
{
    this->type = type;
}

void AuthNetData::setId(std::string id)
{
    this->id = id;
}

void AuthNetData::setPassword(std::string password)
{
    this->password = password;
}

void AuthNetData::setEmail(std::string email)
{
    this->email = email;
}

void AuthNetData::setData(std::string data)
{
    this->data = data;
}

void toJson(nlohmann::json& j, const AuthNetData& p) {
    j = nlohmann::json{
        {"type", p.type},
        {"id", p.id},
        {"password", p.password},
        {"email", p.email},
        {"data", p.data}
    };
}

void fromJson(const nlohmann::json& j, AuthNetData& p) {
    j.at("type").get_to(p.type);
    j.at("id").get_to(p.id);
    j.at("password").get_to(p.password);
    j.at("email").get_to(p.email);
    j.at("data").get_to(p.data);
}

