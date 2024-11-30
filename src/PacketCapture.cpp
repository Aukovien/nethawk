#include "PacketCapture.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <thread>
#include <arpa/inet.h>

PacketCapture::PacketCapture(QObject *parent) : QObject(parent), handle(nullptr), isPaused(false) {}

PacketCapture::~PacketCapture() {
    stopCapture();
}

void PacketCapture::startCapture(const QString &interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    handle = pcap_open_live(interface.toStdString().c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (!handle) {
        emit captureError(QString("Error opening device: %1").arg(errbuf));
        return;
    }

    // Start capture in a separate thread
    auto captureThread = [this]() {
        pcap_loop(handle, -1, packetHandler, reinterpret_cast<u_char*>(this));
    };
    std::thread(captureThread).detach();
}

void PacketCapture::stopCapture() {
    if (handle) {
        pcap_breakloop(handle);
        pcap_close(handle);
        handle = nullptr;
    }
}

void PacketCapture::pauseCapture() {
    isPaused = true;
}

void PacketCapture::resumeCapture() {
    isPaused = false;
}

void PacketCapture::packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    PacketCapture *capture = reinterpret_cast<PacketCapture*>(userData);
    
    if (capture->isPaused) return;

    // Basic packet parsing logic
    struct ip *ip_header = (struct ip*)(packet + 14); // Skip Ethernet header
    
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), destIP, INET_ADDRSTRLEN);

    PacketInfo info;
    info.sourceIP = sourceIP;
    info.destIP = destIP;
    info.size = pkthdr->len;
    info.timestamp = QDateTime::currentDateTime();

    // Determine protocol
    switch(ip_header->ip_p) {
        case IPPROTO_TCP: info.protocol = "TCP"; break;
        case IPPROTO_UDP: info.protocol = "UDP"; break;
        case IPPROTO_ICMP: info.protocol = "ICMP"; break;
        default: info.protocol = "Unknown"; break;
    }

    // Emit packet signal
    QMetaObject::invokeMethod(capture, [capture, info]() {
        capture->packetCaptured(info);
    }, Qt::QueuedConnection);
}
