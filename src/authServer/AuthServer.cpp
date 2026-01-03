#include "AuthServer.h"
#include "AuthNetData.h"
#include <functional>
#include <nlohmann/json.hpp>
#include "../util/SqlUtil.h"

using json = nlohmann::json;

AuthServer::AuthServer(unsigned short port)
    : acceptor(ioContext) {
    // Generate RSA keys on startup
    generateKeys();

    // Test DB connection
    SqlUtil::testConnection();

    // Open the acceptor with the option to reuse the address (i.e. SO_REUSEADDR).
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v6(), port);
    acceptor.open(endpoint.protocol());
    acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor.set_option(boost::asio::ip::v6_only(false));
    acceptor.bind(endpoint);
    acceptor.listen();
    
    startAccept();
    std::cout << "[AuthServer][Info]: Listening on port " << port << " (IPv4/IPv6)" << std::endl;
}

AuthServer::~AuthServer() {
    stop();
}

void AuthServer::run() {
    // 1. Create worker thread pool
    std::size_t threadPoolSize = std::thread::hardware_concurrency();
    if (threadPoolSize == 0) threadPoolSize = 2;
    
    std::cout << "[AuthServer][Info]: Starting server with " << threadPoolSize << " worker threads" << std::endl;
    
    workerThreads.reserve(threadPoolSize);
    for (std::size_t i = 0; i < threadPoolSize; ++i) {
        workerThreads.emplace_back([this, i]() {
            try {
                std::cout << "[AuthServer][Info]: Worker thread " << i << " started" << std::endl;
                // Run ioContext
                ioContext.run();
                std::cout << "[AuthServer][Info]: Worker thread " << i << " exited" << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "[AuthServer][Error]: Exception in worker thread " << i << ": " << e.what() << std::endl;
            }
        });
    }
    
    // 2. Wait for all worker threads
    for (auto& t : workerThreads) {
        if (t.joinable()) t.join();
    }
    
    std::cout << "[AuthServer][Info]: All worker threads have finished" << std::endl;
}

void AuthServer::stop() {
    if (!stopped.exchange(true)) {
        std::cout << "Stopping server..." << std::endl;
        
        // Stop accepting new connections
        boost::system::error_code ec;
        acceptor.close(ec);
        if (ec) {
            std::cerr << "Error closing acceptor: " << ec.message() << std::endl;
        }
        
        // Stop ioContext
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
            // Set socket options
            socket->set_option(boost::asio::ip::tcp::no_delay(true)); 
            
            std::cout << "[AuthServer][Info]: New connection from: "
                      << socket->remote_endpoint().address().to_string()
                      << ":" << socket->remote_endpoint().port() << std::endl;
            
            startReceive(socket);
        } catch (const boost::system::system_error& e) {
            std::cerr << "[AuthServer][Error]: Error setting socket options: " << e.what() << std::endl;
        }
        
        // Continue accepting
        startAccept();
    } else if (error) {
        if (error != boost::asio::error::operation_aborted) {
            std::cerr << "[AuthServer][Error]: Accept error: " << error.message() << std::endl;
        }
    }
}

void AuthServer::startReceive(std::shared_ptr<tcp::socket> socket) {
    if (stopped) return;
    
    // Use shared_ptr for buffer
    auto buffer = std::make_shared<std::vector<char>>(4096); 
    
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
        // Handle received data
        std::string receivedStr(buffer->data(), bytesTransferred);
        std::cout << "[AuthServer][Info]: Received " << bytesTransferred << " bytes: " 
                  << receivedStr << std::endl;
        
        AuthNetData receivedData;
        bool parseSuccess = false;

        // Attempt 1: Assume plain JSON string
        try {
            auto j = nlohmann::json::parse(receivedStr);
            receivedData = j.get<AuthNetData>();
            parseSuccess = true;
        } catch (...) {
            // Failed
        }

        // Attempt 2: Assume Base64 encoded JSON (Unencrypted)
        if (!parseSuccess) {
            try {
                std::string decoded = base64Decode(receivedStr);
                auto j = nlohmann::json::parse(decoded);
                receivedData = j.get<AuthNetData>();
                parseSuccess = true;
                std::cout << "[AuthServer][Info]: Base64 decoded data successfully (No RSA)." << std::endl;
            } catch (...) {
                // Ignore
            }
        }

        // Attempt 3: Assume RSA Encrypted Base64
        if (!parseSuccess) {
            try {
                std::string decrypted = rsaDecryptBase64(receivedStr);
                auto j = nlohmann::json::parse(decrypted);
                receivedData = j.get<AuthNetData>();
                parseSuccess = true;
                std::cout << "[AuthServer][Info]: Decrypted data successfully." << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "[AuthServer][Error]: Decryption/Parsing failed: " << e.what() << std::endl;
            }
        }

        std::string response;
        AuthNetData responseData;
        responseData.setType(-1);

        if (parseSuccess) {
            try {
                if (receivedData.getType() == 0 && receivedData.getData() == "KEY_REQUEST") {
                    // 0: Request Public Key
                    responseData.setType(0);
                    responseData.setData(publicKey);
                    std::cout << "[AuthServer][Info]: Sent Public Key." << std::endl;
                } else if (receivedData.getType() == 1) { // Login
                    responseData.setType(1);
                    int authResult = SqlUtil::authPasswordFromPlayerinfo(receivedData.getId(), receivedData.getPassword());
                    if (authResult == 1) { // Success
                        responseData.setData("LOGIN_SUCCESS");
                    } else if (authResult == 2) { // Fail
                        responseData.setData("LOGIN_FAIL");
                    } else if (authResult == 3) { // Error
                        responseData.setData("LOGIN_FAIL");
                    }
                } else if (receivedData.getType() == 2) { // Register
                    responseData.setType(2);
                    int registerResult = SqlUtil::registerFromPlayerinfo(receivedData.getId(), receivedData.getPassword());
                    if (registerResult == 1) { // Success
                        responseData.setData("REGISTER_SUCCESS");
                    } else if (registerResult == 3) { // Account Exists
                        responseData.setData("REGISTER_FAIL_ACCOUNT");
                    } else { // Unknown Error
                        responseData.setData("REGISTER_FAIL_UNKNOWN");
                    }
                } else if (receivedData.getType() == 3) { // Verify Code
                    responseData.setType(3);
                    if (emailCodeSend(receivedData.getEmail())) {
                        responseData.setData("EMAIL_SUCCESS");
                    } else {
                        responseData.setData("EMAIL_FAIL_UNKNOWN");
                    }
                }
            } catch (std::exception const& e) {
                std::cerr << "pg logic: " << e.what() << std::endl;
                responseData.setType(-1);
            }
        } else {
            std::cerr << "eived data." << std::endl;
        }

        response = nlohmann::json(responseData).dump();
        // Async write response
        boost::asio::async_write(*socket,
                                 boost::asio::buffer(response),
                                 [socket](const boost::system::error_code& writeError,
                                          std::size_t /*bytesWritten*/) {
                                     if (writeError) {
                                         if (writeError != boost::asio::error::operation_aborted) {
                                             std::cerr << "[AuthServer][Error]: Write error: " << writeError.message() << std::endl;
                                         }
                                     }
                                 });
        
        // Continue receive
        startReceive(socket);
    } else if (error != boost::asio::error::eof) {
        if (error != boost::asio::error::operation_aborted) {
            std::cerr << "[AuthServer][Error]: Receive error: " << error.message() << std::endl;
        }
    } else {
        // Connection closed
        std::cout << "[AuthServer][Info]: Connection closed by peer" << std::endl;
    }
}

bool AuthServer::emailCodeSend(std::string email) {
    // TODO: Email sending logic
    return true;
}

void AuthServer::generateKeys() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        std::cerr << "[AuthServer][Error]: EVP_PKEY_CTX_new_id failed" << std::endl;
        return;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "[AuthServer][Error]: EVP_PKEY_keygen_init failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "[AuthServer][Error]: EVP_PKEY_CTX_set_rsa_keygen_bits failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "[AuthServer][Error]: EVP_PKEY_keygen failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    EVP_PKEY_CTX_free(ctx);

    // Save Public Key
    BIO *bp_public = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(bp_public, pkey) != 1) {
         std::cerr << "[AuthServer][Error]: PEM_write_bio_PUBKEY failed" << std::endl;
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
        std::cerr << "[AuthServer][Error]: PEM_write_bio_PrivateKey failed" << std::endl;
    }
    len = BIO_get_mem_data(bp_private, &data);
    if (len > 0) {
        privateKey = std::string(data, len);
    }
    BIO_free(bp_private);
    
    EVP_PKEY_free(pkey);
    std::cout << "[AuthServer][Info]: RSA Keys generated successfully." << std::endl;
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

std::string AuthServer::base64Decode(const std::string& encoded) {
    BIO *bio, *b64;
    int decodeLen = encoded.length();
    std::vector<char> decodedData(decodeLen); 
    
    bio = BIO_new_mem_buf(encoded.data(), -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
    int decodedSize = BIO_read(bio, decodedData.data(), encoded.length());
    BIO_free_all(bio);
    
    if (decodedSize <= 0) {
        throw std::runtime_error("Base64 decode failed");
    }
    
    return std::string(decodedData.data(), decodedSize);
}
