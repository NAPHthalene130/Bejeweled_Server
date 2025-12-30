#include <iostream>
#include <thread>
#include "authServer/AuthServer.h"
#include "util/Config.h"
#include "gameServer/GameServer.h"
#include "otherServer/OtherServer.h"

int main() {
    Config::loadEnv();
    try {
        AuthServer authServer(10086);
        GameServer gameServer(10090);
        OtherServer otherServer(10088);
        std::thread authThread([&authServer]() {
            authServer.run();
        });

        std::thread gameThread([&gameServer]() {
            gameServer.run();
        });
        std::thread otherThread([&otherServer]() {
            otherServer.run();
        });

        authThread.join();
        gameThread.join();
        otherThread.join();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return 0;
}
