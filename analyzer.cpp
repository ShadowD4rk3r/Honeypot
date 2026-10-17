
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

int main() {
    std::ifstream file("events.csv");

    if (!file) {
        std::cerr << "Cannot open events.csv. "
                  << "Run the Python honeypot first.\n";
        return 1;
    }

    std::string line;
    std::getline(file, line); // Skip CSV header.

    std::unordered_map<std::string, int> counts;
    int totalEvents = 0;

    while (std::getline(file, line)) {
        std::stringstream row(line);
        std::string timestamp, ip, event, bytes;

        if (!std::getline(row, timestamp, ',')) continue;
        if (!std::getline(row, ip, ',')) continue;
        if (!std::getline(row, event, ',')) continue;
        if (!std::getline(row, bytes, ',')) continue;

        ++totalEvents;

        if (event == "connection") {
            ++counts[ip];
        }
    }

    std::cout << "=== Honeypot Report ===\n";
    std::cout << "Total events: " << totalEvents << '\n';
    std::cout << "Unique source IPs: " << counts.size() << '\n';

    for (const auto& [ip, count] : counts) {
        std::cout << ip << ": " << count
                  << " connection(s)\n";
    }

    return 0;
}
