// main.cpp
#include "blockchain.h"
#include "transaction.h"
#include "network.h"
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>

int main(int argc, char* argv[]) {
    Blockchain chain;
    Network network(4000);

    chain.loadFromFile("chain.json");

    network.onMessageReceived = [&](const std::string& msg) {
        try {
            auto j = nlohmann::json::parse(msg);
            std::string type = j.at("type");

            if (type == "NEW_TX") {
                Transaction tx = Transaction::fromJson(j.at("data"));
                chain.addTransactionToMempool(tx);
            }
            else if (type == "NEW_BLOCK") {
                Block b = Block::fromJson(j.at("data"));
                if (b.prevHash == chain.getLatestBlock().hash) {
                    chain.chain.push_back(b);
                    chain.mempool.clear();
                    std::cout << "✅ Dodano blok z sieci\n";
                } else {
                    std::cout << "⚠️ Odrzucono blok (niespójny hash)\n";
                }
            }
            else if (type == "GET_CHAIN") {
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& block : chain.chain)
                    arr.push_back(block.toJson());
                network.broadcast(nlohmann::json{{"type", "CHAIN"}, {"data", arr}}.dump());
            }
            else if (type == "CHAIN") {
                auto newChain = j.at("data");
                if (newChain.size() > chain.chain.size()) {
                    chain.chain.clear();
                    for (const auto& jb : newChain)
                        chain.chain.push_back(Block::fromJson(jb));
                    std::cout << "🔄 Zaktualizowano chain z sieci\n";
                }
            }
        } catch (...) {
            std::cerr << "❌ Nieprawidłowy JSON z sieci\n";
        }
    };

    network.startServer();

    std::string cmd;
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, cmd);

        if (cmd == "exit") break;
        else if (cmd == "print") chain.printChain();
        else if (cmd == "save") chain.saveToFile("chain.json");
        else if (cmd == "peers") printConnectedPeers(network);
        else if (cmd.rfind("connect", 0) == 0) {
            std::string ip;
            int port;
            std::stringstream ss(cmd);
            std::string tmp;
            ss >> tmp >> ip >> port;
            network.connectToPeer(ip, port);
        }
        else if (cmd == "get") {
            network.broadcast(nlohmann::json{{"type", "GET_CHAIN"}}.dump());
        }
        else if (cmd == "tx") {
            std::string from, to;
            double amount;
            std::cout << "from: "; std::cin >> from;
            std::cout << "to: "; std::cin >> to;
            std::cout << "amount: "; std::cin >> amount;
            std::cin.ignore();
            Transaction tx = {from, to, amount};
            chain.addTransactionToMempool(tx);
            network.broadcast(nlohmann::json{{"type", "NEW_TX"}, {"data", tx.toJson()}}.dump());
        }
        else {
            std::cout << "Dostępne komendy: connect <ip> <port>, peers, tx, print, get, save, exit\n";
        }
    }

    chain.saveToFile("chain.json");
    return 0;
}
