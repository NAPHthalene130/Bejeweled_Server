#include <iostream>
#include "authServer/AuthServer.h"
#include "util/Config.h"

int main() {
    Config::loadEnv();
    try {
        unsigned short port = 10086;
        AuthServer server(port);
        server.run();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return 0;
}
