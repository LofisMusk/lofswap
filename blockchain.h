#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <vector>
#include <string>
#include <ctime>
#include "transaction.h"
#include <nlohmann/json.hpp>

class Block {
public:
    int index;
    time_t timestamp;
    std::vector<Transaction> transactions;
    std::string prevHash;
    std::string hash;
    int nonce;

    Block(int idx, const std::vector<Transaction>& txs, const std::string& prev);
    std::string calculateHash() const;
    void mineBlock(int difficulty);

    nlohmann::json toJson() const;
    static Block fromJson(const nlohmann::json& j);
};

class Blockchain {
public:
    std::vector<Block> chain;
    std::vector<Transaction> mempool; // 🔁 Mempool: oczekujące transakcje
    int difficulty;

    Blockchain();

    Block createGenesisBlock();
    Block getLatestBlock();
    void addBlock(const std::vector<Transaction>& txs);
    void printChain() const;

    // 🔄 Zapis i odczyt z pliku
    void saveToFile(const std::string& filename) const;
    bool loadFromFile(const std::string& filename);

    // 📨 Dodanie transakcji do mempoola
    void addTransactionToMempool(const Transaction& tx);
};

std::string sha256(const std::string& str);

#endif // BLOCKCHAIN_H
