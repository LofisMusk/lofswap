#ifndef NETWORK_H
#define NETWORK_H

#include <boost/asio.hpp>
#include <thread>
#include <vector>
#include <functional>
#include <memory>
#include <string>

struct PeerInfo {
    std::string address;
    int port;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket;
};

class Network {
public:
    Network(int port);
    void startServer();
    void connectToPeer(const std::string& host, int port);
    void broadcast(const std::string& message);
    std::vector<PeerInfo> getPeers() const;

    std::function<void(const std::string&)> onMessageReceived;

private:
    void handleSession(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                       const std::string& remote_ip, int remote_port);

    int port_;
    boost::asio::io_context io_context_;
    std::vector<PeerInfo> peers_;
};

// Deklaracja funkcji pomocniczej do wypisywania peerów
void printConnectedPeers(const Network& network);

#endif // NETWORK_H
