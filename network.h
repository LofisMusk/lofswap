#ifndef NETWORK_H
#define NETWORK_H

#include <boost/asio.hpp>
#include <thread>
#include <vector>
#include <functional>
#include <memory>

class Network {
public:
    Network(int port);
    void startServer();
    void connectToPeer(const std::string& host, int port);
    void broadcast(const std::string& message);

    std::function<void(const std::string&)> onMessageReceived;

private:
    void handleSession(std::shared_ptr<boost::asio::ip::tcp::socket> socket);

    int port_;
    boost::asio::io_context io_context_;
    std::vector<std::shared_ptr<boost::asio::ip::tcp::socket>> peers_;
};

#endif // NETWORK_H
