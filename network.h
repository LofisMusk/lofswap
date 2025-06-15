#ifndef NETWORK_H
#define NETWORK_H

#include <boost/asio.hpp>
#include <thread>
#include <vector>
#include <functional>
#include <memory>
#include <string>

// Informacje o połączeniu z peerem
struct PeerInfo {
    std::string address;
    int port;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket;
};

class Network {
public:
    // Konstruktor z numerem portu lokalnego
    Network(int port);

    // Uruchomienie serwera do nasłuchu na połączenia przychodzące
    void startServer();

    // Połączenie z innym peerem (IP, port)
    void connectToPeer(const std::string& host, int port);

    // Rozesłanie wiadomości do wszystkich znanych peerów
    void broadcast(const std::string& message);

    // Zwraca aktualną listę peerów
    std::vector<PeerInfo> getPeers() const;

    // Callback do obsługi odebranych wiadomości
    std::function<void(const std::string&)> onMessageReceived;

private:
    // Obsługa jednej sesji z peerem (czytanie wiadomości)
    void handleSession(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                       const std::string& remote_ip,
                       int remote_port);

    int port_; // port lokalny
    boost::asio::io_context io_context_; // kontekst Boost Asio
    std::vector<PeerInfo> peers_; // lista aktywnych peerów
};

#endif // NETWORK_H
