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

