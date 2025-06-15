#include "network.h"
#include <iostream>

using boost::asio::ip::tcp;

Network::Network(int port) : port_(port) {}

void Network::startServer() {
    std::thread([this]() {
        try {
            tcp::acceptor acceptor(io_context_, tcp::endpoint(tcp::v4(), port_));
            while (true) {
                auto socket = std::make_shared<tcp::socket>(io_context_);
                acceptor.accept(*socket);
                peers_.push_back(socket);
                std::thread(&Network::handleSession, this, socket).detach();
            }
        } catch (std::exception& e) {
            std::cerr << "Server error: " << e.what() << std::endl;
        }
    }).detach();
}

void Network::connectToPeer(const std::string& host, int port) {
    try {
        tcp::resolver resolver(io_context_);
        auto endpoints = resolver.resolve(host, std::to_string(port));
        auto socket = std::make_shared<tcp::socket>(io_context_);
        boost::asio::connect(*socket, endpoints);
        peers_.push_back(socket);
        std::thread(&Network::handleSession, this, socket).detach();
    } catch (std::exception& e) {
        std::cerr << "Connection error: " << e.what() << std::endl;
    }
}

void Network::broadcast(const std::string& message) {
    for (auto& peer : peers_) {
        try {
            boost::asio::write(*peer, boost::asio::buffer(message + "\n"));
        } catch (...) {
            // rozłączony peer
        }
    }
}

void Network::handleSession(std::shared_ptr<tcp::socket> socket) {
    try {
        boost::asio::streambuf buffer;
        while (true) {
            boost::asio::read_until(*socket, buffer, "\n");
            std::istream is(&buffer);
            std::string line;
            std::getline(is, line);
            if (!line.empty() && onMessageReceived) {
                onMessageReceived(line);
            }
        }
    } catch (...) {
        // połączenie zakończone
    }
}
