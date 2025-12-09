#include <iostream>
#include "authServer/AuthServer.h"

int main() {
    try {
        unsigned short port = 10086;
        AuthServer server(port);
        server.run();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    return 0;
}
