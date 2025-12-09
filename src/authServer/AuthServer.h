#ifndef AUTH_SERVER_H
#define AUTH_SERVER_H

#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <boost/asio.hpp>

class AuthServer {
    using tcp = boost::asio::ip::tcp;
public:
    AuthServer(unsigned short port);
    ~AuthServer();
    void run();
    void stop();

private:
    void startAccept();
    void handleAccept(std::shared_ptr<tcp::socket> socket,
                       const boost::system::error_code& error);
    void startReceive(std::shared_ptr<tcp::socket> socket);
    void handleReceive(std::shared_ptr<tcp::socket> socket,
                        std::shared_ptr<std::vector<char>> buffer,
                        const boost::system::error_code& error,
                        std::size_t bytesTransferred);

    boost::asio::io_context ioContext;
    tcp::acceptor acceptor;
    std::vector<std::thread> workerThreads;
    std::atomic<bool> stopped{false};
};

#endif // AUTH_SERVER_H
