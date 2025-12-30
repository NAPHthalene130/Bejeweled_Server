#ifndef OTHERSERVER_H
#define OTHERSERVER_H

#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <string>
#include <boost/asio.hpp>
#include "OtherNetData.h"

class OtherServer {
    using tcp = boost::asio::ip::tcp;
public:
    OtherServer(unsigned short port);
    ~OtherServer();
    void run();
    void stop();

private:
    void startAccept();
    void handleAccept(std::shared_ptr<tcp::socket> socket,
                       const boost::system::error_code& error);
    void startReceive(std::shared_ptr<tcp::socket> socket, std::string accumulatedBuffer = "");
    void handleReceive(std::shared_ptr<tcp::socket> socket,
                        std::shared_ptr<std::vector<char>> buffer,
                        const boost::system::error_code& error,
                        std::size_t bytesTransferred,
                        std::string accumulatedBuffer);
    void sendData(std::shared_ptr<tcp::socket> socket, OtherNetData data);

    boost::asio::io_context ioContext;
    tcp::acceptor acceptor;
    std::vector<std::thread> workerThreads;
    std::atomic<bool> stopped{false};
};

#endif // OTHERSERVER_H
