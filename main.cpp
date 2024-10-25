#include <cstddef>
#include <net/ethernet.h>
#include <pcap.h>
#include <iostream>
#include <cstdio>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <sys/types.h>

class NetworkMonitor {
    private:
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program pf;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        // Get Ethernet header
        struct ether_header *eth_header = (struct ether_header *)packet;

        // Skip  non-IP packets
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
            return;
        }

        // Get IP header
        struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        // Get source and destination IP addresses
        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

        // Print packet info
        std::cout << "\nPacket captured:"
                << "\nSize: " << pkthdr->len << "bytes"
                << "\nSource: " << source_ip
                << "\nDestination: " << dest_ip
                << "\nProtocol: " << (unsigned int)ip_header->ip_p
                << std::endl;
    }

    public:
        NetworkMonitor() : handle(nullptr){}

        bool init(const char* interface) {
            // Get network address and mask of the interface
            if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
                std::cerr << "could not get netmask for device: " << errbuf << std::endl;
                net = 0;
                mask = 0;
            }

            // Open the interface for packet cpature
            handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
            if (handle == nullptr) {
                std::cerr << "Could not open device: " << errbuf << std::endl;
                return false;
            }

            return true;
        }

        void start_capture() {
            if (handle == nullptr) {
                std::cerr << "Device not initialized" << std::endl;
                return;
            }

            std::cout << "Starting packet capture... Press CTRL+C to stop." << std::endl;

            // Start packet capture
            pcap_loop(handle, 0, packet_handler, nullptr);
        }

        void cleanup() {
            if (handle != nullptr) {
                pcap_close(handle);
                handle = nullptr;
            }
        }

        ~NetworkMonitor() {
            cleanup();
        }
};

int main() {
    NetworkMonitor monitor;

    // List available network interfaces
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Available network interfaces:" << std::endl;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        std::cout << d->name << " - " << (d->description ? d->description : "No description available") << std::endl;
    }

    // Get interface from user
    std::string interface;
    std::cout << "\nEnter interface name: ";
    std::getline(std::cin, interface);

    // Initialize the monitor
    if (!monitor.init(interface.c_str())) {
        std::cerr << "Failed to initalize network monitor" << std::endl;
        return 1;
    }

    // Start capturing packets
    monitor.start_capture();

    pcap_freealldevs(alldevs);
    return 0;
}
