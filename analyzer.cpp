
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

string trim(string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

string lower(string value) {
    transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return value;
}

// Parse CSV fields, including fields wrapped in double quotes.
vector<string> parseCSV(const string& line) {
    vector<string> fields;
    string field;
    bool quoted = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];

        if (c == '"') {
            if (quoted && i + 1 < line.size() && line[i + 1] == '"') {
                field += '"';
                ++i;
            } else {
                quoted = !quoted;
            }
        } else if (c == ',' && !quoted) {
            fields.push_back(trim(field));
            field.clear();
        } else {
            field += c;
        }
    }

    fields.push_back(trim(field));
    return fields;
}

int findColumn(const vector<string>& headers,
               const vector<string>& candidates) {
    for (size_t i = 0; i < headers.size(); ++i) {
        string name = lower(trim(headers[i]));
        for (const string& candidate : candidates) {
            if (name == candidate) return static_cast<int>(i);
        }
    }
    return -1;
}

string fieldAt(const vector<string>& row, int index,
               const string& fallback = "") {
    if (index < 0 || static_cast<size_t>(index) >= row.size()) {
        return fallback;
    }
    return trim(row[index]).empty() ? fallback : trim(row[index]);
}

struct Report {
    string source;
    int totalEvents = 0;
    int connections = 0;
    set<string> uniqueIPs;
    unordered_map<string, int> eventTypes;
    bool foundFile = false;
};

Report analyzeFile(const string& source, const string& path) {
    Report report;
    report.source = source;

    ifstream file(path);
    if (!file) {
        cout << "[INFO] " << path << " not found; skipping.\n";
        return report;
    }

    report.foundFile = true;

    string line;
    if (!getline(file, line)) {
        cout << "[INFO] " << path << " is empty.\n";
        return report;
    }

    vector<string> headers = parseCSV(line);

    int ipColumn = findColumn(headers, {
        "ip", "source_ip", "client_ip", "remote_ip", "src_ip", "address"
    });
    int eventColumn = findColumn(headers, {
        "event", "event_type", "type", "action", "event_name"
    });

    while (getline(file, line)) {
        if (trim(line).empty()) continue;

        vector<string> row = parseCSV(line);
        ++report.totalEvents;

        string event = lower(fieldAt(row, eventColumn, "event"));
        string ip = fieldAt(row, ipColumn);

        ++report.eventTypes[event];

        // Only count explicit TCP connection events as connections.
        if (source == "TCP Honeypot" && event == "connection") {
            ++report.connections;
            if (!ip.empty() && ip != "Unknown") {
                report.uniqueIPs.insert(ip);
            }
        }
    }

    return report;
}

void printReport(const Report& report) {
    cout << "\n=== " << report.source << " ===\n";
    cout << "Total events: " << report.totalEvents << '\n';

    if (report.source == "TCP Honeypot") {
        cout << "Connections: " << report.connections << '\n';
        cout << "Unique source IPs: " << report.uniqueIPs.size() << '\n';

        for (const string& ip : report.uniqueIPs) {
            cout << "  " << ip << '\n';
        }
    }

    cout << "Event types:\n";
    if (report.eventTypes.empty()) {
        cout << "  (No events recorded.)\n";
    } else {
        for (const auto& item : report.eventTypes) {
            cout << "  " << item.first << ": " << item.second << '\n';
        }
    }
}

int main() {
    vector<Report> reports;
    reports.push_back(analyzeFile("TCP Honeypot", "events.csv"));
    reports.push_back(analyzeFile("Web Decoy", "Actual/web_events.csv"));
    reports.push_back(analyzeFile("SQL Lab", "Actual/lab_events.csv"));

    int totalEvents = 0;
    int totalConnections = 0;
    int filesFound = 0;

    cout << "========== ShadowNet Combined Report ==========\n";

    for (const Report& report : reports) {
        printReport(report);
        totalEvents += report.totalEvents;
        totalConnections += report.connections;
        if (report.foundFile) ++filesFound;
    }

    cout << "\n========== Overall Summary ==========\n";
    cout << "Log files found: " << filesFound << " of "
         << reports.size() << '\n';
    cout << "Combined events: " << totalEvents << '\n';
    cout << "TCP connections: " << totalConnections << '\n';

    if (filesFound == 0) {
        cerr << "\nNo log files could be opened. Check the working "
             << "directory and file paths.\n";
        return 1;
    }

    return 0;
}
