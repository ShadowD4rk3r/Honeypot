
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

uint32_t read32(const unsigned char* p, bool little) {
    if (little) {
        return uint32_t(p[0]) |
               (uint32_t(p[1]) << 8) |
               (uint32_t(p[2]) << 16) |
               (uint32_t(p[3]) << 24);
    }

    return (uint32_t(p[0]) << 24) |
           (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) |
           uint32_t(p[3]);
}

uint16_t read16(const unsigned char* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

string ipv4(const unsigned char* p) {
    return to_string(p[0]) + "." +
           to_string(p[1]) + "." +
           to_string(p[2]) + "." +
           to_string(p[3]);
}

int main(int argc, char* argv[]) {
    const string path = argc > 1 ? argv[1] : "lab_capture.pcap";
    ifstream file(path, ios::binary);

    if (!file) {
        cerr << "Cannot open PCAP file: " << path << '\n';
        return 1;
    }

    array<unsigned char, 24> global{};
    file.read(reinterpret_cast<char*>(global.data()), global.size());

    if (file.gcount() != static_cast<streamsize>(global.size())) {
        cerr << "Invalid or incomplete PCAP global header.\n";
        return 1;
    }

    bool little = false;

    // Classic PCAP magic numbers, including nanosecond variants.
    if (global[0] == 0xd4 && global[1] == 0xc3 &&
        global[2] == 0xb2 && global[3] == 0xa1) {
        little = true;
    } else if (global[0] == 0xa1 && global[1] == 0xb2 &&
               global[2] == 0xc3 && global[3] == 0xd4) {
        little = false;
    } else if (global[0] == 0x4d && global[1] == 0x3c &&
               global[2] == 0xb2 && global[3] == 0xa1) {
        little = true;
    } else if (global[0] == 0xa1 && global[1] == 0xb2 &&
               global[2] == 0x3c && global[3] == 0x4d) {
        little = false;
    } else {
        cerr << "Unsupported file format. Expected classic PCAP, not PCAPNG.\n";
        return 1;
    }

    const uint32_t linkType = read32(global.data() + 20, little);

    // This first version expects Ethernet frames.
    if (linkType != 1) {
        cerr << "Unsupported link type. Export an Ethernet PCAP for this version.\n";
        return 1;
    }

    uint64_t packets = 0;
    uint64_t tcpPackets = 0;
    uint64_t malformed = 0;
    uint64_t synCount = 0, ackCount = 0, finCount = 0, rstCount = 0;
    uint64_t totalCapturedBytes = 0;

    cout << "ShadowNet TCP Metadata Report\n";
    cout << "File: " << path << "\n";
    cout << "Payload inspection: disabled\n\n";

    while (true) {
        array<unsigned char, 16> packetHeader{};
        file.read(reinterpret_cast<char*>(packetHeader.data()),
                  packetHeader.size());

        if (file.gcount() == 0) break;

        if (file.gcount() != static_cast<streamsize>(packetHeader.size())) {
            cerr << "Warning: incomplete packet header at end of file.\n";
            break;
        }

        const uint32_t captured = read32(packetHeader.data() + 8, little);
        const uint32_t original = read32(packetHeader.data() + 12, little);

        // Avoid unreasonable allocations on corrupt files.
        if (captured > 16 * 1024 * 1024) {
            cerr << "Invalid packet length; stopping analysis.\n";
            return 1;
        }

        vector<unsigned char> frame(captured);
        file.read(reinterpret_cast<char*>(frame.data()), captured);

        if (file.gcount() != static_cast<streamsize>(captured)) {
            cerr << "Warning: incomplete packet data at end of file.\n";
            break;
        }

        ++packets;
        totalCapturedBytes += captured;

        // Ethernet header.
        if (frame.size() < 14) {
            ++malformed;
            continue;
        }

        size_t offset = 14;
        uint16_t etherType = read16(frame.data() + 12);

        // Skip common VLAN tags.
        while (etherType == 0x8100 || etherType == 0x88a8) {
            if (frame.size() < offset + 4) {
                offset = frame.size();
                break;
            }
            etherType = read16(frame.data() + offset + 2);
            offset += 4;
        }

        if (offset > frame.size() || etherType != 0x0800) continue;

        // IPv4 header.
        if (frame.size() < offset + 20) {
            ++malformed;
            continue;
        }

        const unsigned char* ip = frame.data() + offset;
        if ((ip[0] >> 4) != 4) continue;

        const size_t ipHeaderLength = (ip[0] & 0x0f) * 4;
        if (ipHeaderLength < 20 || frame.size() < offset + ipHeaderLength) {
            ++malformed;
            continue;
        }

        if (ip[9] != 6) continue; // TCP only.

        // Fragmented IPv4 packets without the first fragment don't
        // contain a TCP header at this offset.
        const uint16_t fragment = read16(ip + 6);
        if ((fragment & 0x1fff) != 0) continue;

        const size_t tcpOffset = offset + ipHeaderLength;
        if (frame.size() < tcpOffset + 20) {
            ++malformed;
            continue;
        }

        const unsigned char* tcp = frame.data() + tcpOffset;
        const size_t tcpHeaderLength = (tcp[12] >> 4) * 4;

        if (tcpHeaderLength < 20 ||
            frame.size() < tcpOffset + tcpHeaderLength) {
            ++malformed;
            continue;
        }

        const uint16_t srcPort = read16(tcp);
        const uint16_t dstPort = read16(tcp + 2);
        const unsigned char flags = tcp[13];

        ++tcpPackets;
        if (flags & 0x02) ++synCount;
        if (flags & 0x10) ++ackCount;
        if (flags & 0x01) ++finCount;
        if (flags & 0x04) ++rstCount;

        cout << ipv4(ip + 12) << ':' << srcPort
             << " -> " << ipv4(ip + 16) << ':' << dstPort
             << " | flags=";

        if (flags & 0x02) cout << "SYN ";
        if (flags & 0x10) cout << "ACK ";
        if (flags & 0x01) cout << "FIN ";
        if (flags & 0x04) cout << "RST ";
        if (flags & 0x08) cout << "PSH ";
        if (flags & 0x20) cout << "URG ";
        if (flags == 0) cout << "NONE";

        cout << " | captured=" << captured
             << " | original=" << original << '\n';
    }

    cout << "\n=== Summary ===\n"
         << "Packets processed: " << packets << '\n'
         << "TCP packets: " << tcpPackets << '\n'
         << "Malformed/truncated packets: " << malformed << '\n'
         << "Captured bytes (all packets): " << totalCapturedBytes << '\n'
         << "SYN flags: " << synCount << '\n'
         << "ACK flags: " << ackCount << '\n'
         << "FIN flags: " << finCount << '\n'
         << "RST flags: " << rstCount << '\n';

    return 0;
}
