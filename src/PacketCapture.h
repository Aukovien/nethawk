#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <QObject>
#include <QVector>
#include <QDateTime>
#include <pcap.h>

struct PacketInfo {
    QString sourceIP;
    QString destIP;
    QString protocol;
    int size;
    QDateTime timestamp;
};

class PacketCapture : public QObject {
    Q_OBJECT

public:
    explicit PacketCapture(QObject *parent = nullptr);
    ~PacketCapture();

    void startCapture(const QString &interface);
    void stopCapture();
    void pauseCapture();
    void resumeCapture();

signals:
    void packetCaptured(const PacketInfo &packet);
    void captureError(const QString &error);

private:
    pcap_t *handle;
    bool isPaused;
    static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
};

#endif