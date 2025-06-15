#include "network.h"
#include <iostream>
#include <nlohmann/json.hpp>

using boost::asio::ip::tcp;

Network::Network(int port) : port_(port) {}

void Network::startServer() {
    std::thread([&]() {
        try {
            tcp::acceptor acceptor(io_context_, tcp::endpoint(tcp::v4(), port_));
            while (true) {
                auto socket = std::make_shared<tcp::socket>(io_context_);
                acceptor.accept(*socket);

                std::string remote_ip = socket->remote_endpoint().address().to_string();
                int remote_port = socket->remote_endpoint().port();

                peers_.push_back({remote_ip, remote_port, socket});

                std::thread(&Network::handleSession, this, socket, remote_ip, remote_port).detach();
            }
        } catch (std::exception& e) {
            std::cerr << "❌ Server error: " << e.what() << std::endl;
        }
    }).detach();
}

void Network::connectToPeer(const std::string& host, int port) {
    try {
        auto socket = std::make_shared<tcp::socket>(io_context_);
        tcp::resolver resolver(io_context_);
        auto endpoints = resolver.resolve(host, std::to_string(port));
        boost::asio::connect(*socket, endpoints);

        peers_.push_back({host, port, socket});

        std::thread(&Network::handleSession, this, socket, host, port).detach();

        // Send HELLO
        nlohmann::json hello = {
            {"type", "HELLO"},
            {"port", port_}
        };
        std::string msg = hello.dump() + "\n";
        boost::asio::write(*socket, boost::asio::buffer(msg));

        std::cout << "🔗 Connected to peer " << host << ":" << port << std::endl;
    } catch (std::exception& e) {
        std::cerr << "❌ Connect error: " << e.what() << std::endl;
    }
}

void Network::handleSession(std::shared_ptr<tcp::socket> socket,
                            const std::string& remote_ip,
                            int remote_port) {
    try {
        boost::asio::streambuf buffer;
        while (true) {
            boost::asio::read_until(*socket, buffer, "\n");

            std::istream is(&buffer);
            std::string message;
            std::getline(is, message);

            if (!message.empty()) {
                if (onMessageReceived)
                    onMessageReceived(message);
            }
        }
    } catch (std::exception& e) {
        std::cerr << "⚠️ Peer " << remote_ip << ":" << remote_port
                  << " disconnected: " << e.what() << std::endl;

        peers_.erase(std::remove_if(peers_.begin(), peers_.end(), [&](const PeerInfo& p) {
            return p.socket == socket;
        }), peers_.end());
    }
}

void Network::broadcast(const std::string& message) {
    for (const auto& peer : peers_) {
        try {
            boost::asio::write(*peer.socket, boost::asio::buffer(message + "\n"));
        } catch (...) {
            std::cerr << "⚠️ Nie udało się wysłać do "
                      << peer.address << ":" << peer.port << std::endl;
        }
    }
}

std::vector<PeerInfo> Network::getPeers() const {
    return peers_;
}
