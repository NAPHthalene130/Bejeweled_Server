#include <iostream>
#include <thread>
#include "authServer/AuthServer.h"
#include "util/Config.h"
#include "gameServer/GameServer.h"

int main() {
    Config::loadEnv();
    try {
        AuthServer authServer(10086);
        GameServer gameServer(10090);

        std::thread authThread([&authServer]() {
            authServer.run();
        });

        std::thread gameThread([&gameServer]() {
            gameServer.run();
        });

        authThread.join();
        gameThread.join();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return 0;
}
