// blockchain.cpp
#include "blockchain.h"
#include <sstream>
#include <iomanip>
#include <fstream>
#include <openssl/sha.h>
#include <iostream>

using json = nlohmann::json;

std::string sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)str.c_str(), str.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

Block::Block(int idx, const std::vector<Transaction>& txs, const std::string& prev)
    : index(idx), transactions(txs), prevHash(prev), nonce(0) {
    timestamp = time(nullptr);
    hash = calculateHash();
}

std::string Block::calculateHash() const {
    std::stringstream ss;
    ss << index << timestamp << prevHash << nonce;
    for (const auto& tx : transactions) {
        ss << tx.toString();
    }
    return sha256(ss.str());
}

void Block::mineBlock(int difficulty) {
    std::string target(difficulty, '0');
    while (hash.substr(0, difficulty) != target) {
        nonce++;
        hash = calculateHash();
    }
    std::cout << "Block mined: " << hash << std::endl;
}

json Block::toJson() const {
    json jtxs = json::array();
    for (const auto& tx : transactions) {
        jtxs.push_back(tx.toJson());
    }

    return {
        {"index", index},
        {"timestamp", timestamp},
        {"transactions", jtxs},
        {"prevHash", prevHash},
        {"hash", hash},
        {"nonce", nonce}
    };
}

Block Block::fromJson(const json& j) {
    std::vector<Transaction> txs;
    for (const auto& txj : j.at("transactions")) {
        txs.push_back(Transaction::fromJson(txj));
    }
    Block block(j.at("index").get<int>(), txs, j.at("prevHash").get<std::string>());
    block.timestamp = j.at("timestamp").get<time_t>();
    block.hash = j.at("hash").get<std::string>();
    block.nonce = j.at("nonce").get<int>();
    return block;
}

Blockchain::Blockchain() {
    difficulty = 4;
    chain.push_back(createGenesisBlock());
}

Block Blockchain::createGenesisBlock() {
    std::vector<Transaction> emptyTxs;
    return Block(0, emptyTxs, "0");
}

Block Blockchain::getLatestBlock() {
    return chain.back();
}

void Blockchain::addBlock(const std::vector<Transaction>& txs) {
    Block newBlock(chain.size(), txs, getLatestBlock().hash);
    newBlock.mineBlock(difficulty);
    chain.push_back(newBlock);
    mempool.clear();
}

void Blockchain::printChain() const {
    for (const auto& block : chain) {
        std::cout << "Index: " << block.index << "\n"
                  << "Timestamp: " << block.timestamp << "\n"
                  << "Previous Hash: " << block.prevHash << "\n"
                  << "Hash: " << block.hash << "\n"
                  << "Nonce: " << block.nonce << "\n";
        for (const auto& tx : block.transactions) {
            std::cout << "  -> " << tx.toString() << "\n";
        }
        std::cout << "\n";
    }
}

void Blockchain::saveToFile(const std::string& filename) const {
    json jchain = json::array();
    for (const auto& block : chain) {
        jchain.push_back(block.toJson());
    }
    std::ofstream file(filename);
    if (file.is_open()) {
        file << jchain.dump(4);
        file.close();
    } else {
        std::cerr << "Nie można zapisać łańcucha do pliku:"  << filename << std::endl;
    }
}

bool Blockchain::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "⚠️ Nie znaleziono pliku łańcucha: " << filename << std::endl;
        return false;
    }
    json jchain;
    file >> jchain;
    chain.clear();
    for (const auto& jb : jchain) {
        chain.push_back(Block::fromJson(jb));
    }
    return true;
}

void Blockchain::addTransactionToMempool(const Transaction& tx) {
    mempool.push_back(tx);
    std::cout << "Dodano transakcję do mempoola: " << tx.toString() << std::endl;
}