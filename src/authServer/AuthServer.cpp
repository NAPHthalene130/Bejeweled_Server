#include "AuthServer.h"
#include "AuthNetData.h"
#include <functional>
#include "json.hpp"
#include "../util/SqlUtil.h"
using json = nlohmann::json;
AuthServer::AuthServer(unsigned short port)
    : acceptor(ioContext, tcp::endpoint(tcp::v4(), port)) {
    // Generate RSA keys on startup
    generateKeys();

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
        
        AuthNetData receivedData;
        bool parseSuccess = false;

        // 尝试1：假设是普通的JSON字符串
        try {
            auto j = nlohmann::json::parse(receivedStr);
            receivedData = j.get<AuthNetData>();
            parseSuccess = true;
        } catch (...) {
            // JSON解析失败，可能是加密数据
        }

        // 尝试2：假设是加密后的Base64字符串
        if (!parseSuccess) {
            try {
                std::string decrypted = rsaDecryptBase64(receivedStr);
                auto j = nlohmann::json::parse(decrypted);
                receivedData = j.get<AuthNetData>();
                parseSuccess = true;
                std::cout << "Decrypted data successfully." << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Decryption/Parsing failed: " << e.what() << std::endl;
            }
        }

        std::string response;
        AuthNetData responseData;
        responseData.setType(-1);

        if (parseSuccess) {
            try {
                if (receivedData.getType() == 0 && receivedData.getData() == "KEY_REQUEST") {
                    // 0: 请求公钥
                    responseData.setType(0);
                    responseData.setData(publicKey);
                    std::cout << "Sent Public Key." << std::endl;
                } else if (receivedData.getType() == 1) { //登录逻辑
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
                std::cerr << "Exception in processing logic: " << e.what() << std::endl;
                responseData.setType(-1);
            }
        } else {
            std::cerr << "Failed to process received data." << std::endl;
        }

        response = nlohmann::json(responseData).dump();
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

void AuthServer::generateKeys() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        std::cerr << "EVP_PKEY_CTX_new_id failed" << std::endl;
        return;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "EVP_PKEY_keygen_init failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_bits failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "EVP_PKEY_keygen failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    EVP_PKEY_CTX_free(ctx);

    // Save Public Key
    BIO *bp_public = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(bp_public, pkey) != 1) {
         std::cerr << "PEM_write_bio_PUBKEY failed" << std::endl;
    }
    
    char *data = NULL;
    long len = BIO_get_mem_data(bp_public, &data);
    if (len > 0) {
        publicKey = std::string(data, len);
    }
    BIO_free(bp_public);

    // Save Private Key
    BIO *bp_private = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PrivateKey(bp_private, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        std::cerr << "PEM_write_bio_PrivateKey failed" << std::endl;
    }
    len = BIO_get_mem_data(bp_private, &data);
    if (len > 0) {
        privateKey = std::string(data, len);
    }
    BIO_free(bp_private);
    
    EVP_PKEY_free(pkey);
    std::cout << "RSA Keys generated successfully." << std::endl;
}

std::string AuthServer::rsaDecryptBase64(const std::string& cipherTextBase64) {
    if (privateKey.empty()) {
        throw std::runtime_error("Private key is empty");
    }

    // 1. Base64 Decode
    BIO *bio, *b64;
    int decodeLen = cipherTextBase64.length();
    std::vector<unsigned char> decodedData(decodeLen); 
    
    bio = BIO_new_mem_buf(cipherTextBase64.data(), -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
    int decodedSize = BIO_read(bio, decodedData.data(), cipherTextBase64.length());
    BIO_free_all(bio);
    
    if (decodedSize <= 0) {
        throw std::runtime_error("Base64 decode failed");
    }

    // 2. Decrypt
    BIO *keyBio = BIO_new_mem_buf(privateKey.data(), -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(keyBio, NULL, NULL, NULL);
    BIO_free(keyBio);
    
    if (!pkey) throw std::runtime_error("Load private key failed");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_CTX_new failed");
    }
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_decrypt_init failed");
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Set padding failed");
    }
    
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Set oaep md failed");
    }
    
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Set mgf1 md failed");
    }

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, decodedData.data(), decodedSize) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Decryption size check failed");
    }
    
    std::string out;
    out.resize(outlen);
    if (EVP_PKEY_decrypt(ctx, (unsigned char*)out.data(), &outlen, decodedData.data(), decodedSize) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Decryption failed");
    }
    
    out.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return out;
}