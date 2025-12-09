#ifndef REGISTER_SERVER_H
#define REGISTER_SERVER_H

#include <iostream>
#include <thread>

class RegisterServer{
public:
    RegisterServer(int port);
    ~RegisterServer();
    void run();
    void stop();
private:
};

#endif // REGISTER_SERVER_H