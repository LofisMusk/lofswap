#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <string>
#include <nlohmann/json.hpp>

struct Transaction {
    std::string sender;
    std::string recipient;
    double amount;

    std::string toString() const {
        return sender + "->" + recipient + ": " + std::to_string(amount);
    }

    nlohmann::json toJson() const {
        return {
            {"sender", sender},
            {"recipient", recipient},
            {"amount", amount}
        };
    }

    static Transaction fromJson(const nlohmann::json& j) {
        return {
            j.at("sender").get<std::string>(),
            j.at("recipient").get<std::string>(),
            j.at("amount").get<double>()
        };
    }
};

#endif
