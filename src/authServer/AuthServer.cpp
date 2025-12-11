#include "AuthServer.h"
#include "AuthNetData.h"
#include <functional>
#include "json.hpp"
#include "../util/SqlUtil.h"
using json = nlohmann::json;
AuthServer::AuthServer(unsigned short port)
    : acceptor(ioContext, tcp::endpoint(tcp::v4(), port)) {
    // 设置套接字重用选项，避免端口占用问题
    acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    startAccept();
    std::cout << "AuthServer listening on port " << port << std::endl;
}

AuthServer::~AuthServer() {
    stop();
}

void AuthServer::run() {
    // 1. 创建工作线程池（数量通常为CPU核心数）
    std::size_t threadPoolSize = std::thread::hardware_concurrency();
    if (threadPoolSize == 0) threadPoolSize = 2;
    
    std::cout << "Starting server with " << threadPoolSize << " worker threads" << std::endl;
    
    workerThreads.reserve(threadPoolSize);
    for (std::size_t i = 0; i < threadPoolSize; ++i) {
        workerThreads.emplace_back([this, i]() {
            try {
                std::cout << "Worker thread " << i << " started" << std::endl;
                // 所有线程共享ioContext，run()会阻塞直到ioContext停止
                ioContext.run();
                std::cout << "Worker thread " << i << " exited" << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Exception in worker thread " << i << ": " << e.what() << std::endl;
            }
        });
    }
    
    // 2. 主线程等待所有工作线程结束
    for (auto& thread : workerThreads) {
        if (thread.joinable()) thread.join();
    }
    
    std::cout << "All worker threads have finished" << std::endl;
}

void AuthServer::stop() {
    if (!stopped.exchange(true)) {
        std::cout << "Stopping server..." << std::endl;
        
        // 先停止接受新连接
        boost::system::error_code ec;
        acceptor.close(ec);
        if (ec) {
            std::cerr << "Error closing acceptor: " << ec.message() << std::endl;
        }
        
        // 停止ioContext，这将导致所有异步操作取消
        ioContext.stop();
    }
}

void AuthServer::startAccept() {
    if (stopped) return;
    
    auto newSocket = std::make_shared<tcp::socket>(ioContext);
    
    acceptor.async_accept(*newSocket,
        [this, newSocket](const boost::system::error_code& error) {
            handleAccept(newSocket, error);
        });
}

void AuthServer::handleAccept(std::shared_ptr<tcp::socket> socket,
                                 const boost::system::error_code& error) {
    if (!error && !stopped) {
        try {
            // 设置套接字选项
            socket->set_option(boost::asio::ip::tcp::no_delay(true)); // 禁用Nagle算法
            
            std::cout << "New connection from: "
                      << socket->remote_endpoint().address().to_string()
                      << ":" << socket->remote_endpoint().port() << std::endl;
            
            startReceive(socket);
        } catch (const boost::system::system_error& e) {
            std::cerr << "Error setting socket options: " << e.what() << std::endl;
        }
        
        // 继续接受下一个连接
        startAccept();
    } else if (error) {
        if (error != boost::asio::error::operation_aborted) {
            std::cerr << "Accept error: " << error.message() << std::endl;
        }
    }
}

void AuthServer::startReceive(std::shared_ptr<tcp::socket> socket) {
    if (stopped) return;
    
    // 使用shared_ptr管理缓冲区，确保其生命周期覆盖整个异步操作链
    auto buffer = std::make_shared<std::vector<char>>(4096); // 4KB缓冲区
    
    socket->async_read_some(boost::asio::buffer(*buffer),
        [this, socket, buffer](const boost::system::error_code& error,
                               std::size_t bytesTransferred) {
            handleReceive(socket, buffer, error, bytesTransferred);
        });
}

void AuthServer::handleReceive(std::shared_ptr<tcp::socket> socket,
                                  std::shared_ptr<std::vector<char>> buffer,
                                  const boost::system::error_code& error,
                                  std::size_t bytesTransferred) {
    if (stopped) return;
    
    if (!error) {
        // 处理接收到的数据
        std::string receivedStr(buffer->data(), bytesTransferred);
        std::cout << "Received " << bytesTransferred << " bytes: " 
                  << receivedStr << std::endl;
        
        //TODO:此处完成登录解析
        AuthNetData receivedData = nlohmann::json::parse(receivedStr).get<AuthNetData>();
        std::string response;
        AuthNetData responseData;
        responseData.setType(-1);
        try {
            if (receivedData.getType() == 1) { //登录逻辑
                responseData.setType(1);
                int authResult = SqlUtil::authPasswordFromPlayerinfo(receivedData.getId(), receivedData.getPassword());
                if (authResult == 1) { //1 登录成功
                    responseData.setData("LOGIN_SUCCESS");
                } else if (authResult == 2) { //2 登录失败
                    responseData.setData("LOGIN_FAIL");
                } else if (authResult == 3) { //3 其它错误
                    responseData.setData("LOGIN_FAIL");
                }
            } else if (receivedData.getType() == 2) { //注册逻辑
                responseData.setType(2);
                int registerResult = SqlUtil::registerFromPlayerinfo(receivedData.getId(), receivedData.getPassword(), receivedData.getEmail(), receivedData.getData(), receivedData.getData());
                if (registerResult == 1) { //1 注册成功
                    responseData.setData("REGISTER_SUCCESS");
                } else if (registerResult == 2) { //2 邮箱验证码错误
                    responseData.setData("REGISTER_FAIL_EMAILCODE");
                } else if (registerResult == 3) { //3 账号已存在
                    responseData.setData("REGISTER_FAIL_ACCOUNT");
                } else if (registerResult == 4) {  //4 邮箱已存在
                    responseData.setData("REGISTER_FAIL_EMAIL");
                } else if (registerResult == 5) { //5 其它错误
                    responseData.setData("REGISTER_FAIL_UNKNOWN");
                }
            } else if (receivedData.getType() == 3) { //验证码逻辑
                responseData.setType(3);
                if (emailCodeSend(receivedData.getEmail())) {
                    responseData.setData("EMAIL_SUCCESS");
                } else {
                    responseData.setData("EMAIL_FAIL_UNKNOWN");
                }
            }
        } catch (std::exception const& e) {
            std::cerr << "Exception in handleReceive: " << e.what() << std::endl;
            responseData.setType(-1);
        }        
        // 异步发送响应
        boost::asio::async_write(*socket,
                                 boost::asio::buffer(response),
                                 [socket](const boost::system::error_code& writeError,
                                          std::size_t /*bytesWritten*/) {
                                     if (writeError) {
                                         if (writeError != boost::asio::error::operation_aborted) {
                                             std::cerr << "Write error: " << writeError.message() << std::endl;
                                         }
                                     }
                                 });
        
        // 继续接收下一条消息（形成异步操作链）
        startReceive(socket);
    } else if (error != boost::asio::error::eof) {
        if (error != boost::asio::error::operation_aborted) {
            std::cerr << "Receive error: " << error.message() << std::endl;
        }
    } else {
        // 对方关闭连接
        std::cout << "Connection closed by peer" << std::endl;
        // TODO: 清理连接相关资源，如从在线用户列表中移除
    }
}

bool AuthServer::emailCodeSend(std::string email) {
    //TODO: 发送邮箱验证码和保存数据的逻辑
    return true;
}