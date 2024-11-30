#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QComboBox>
#include <QPushButton>
#include "PacketCapture.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);

private slots:
    void onPacketCaptured(const PacketInfo &packet);
    void toggleCapture();
    void filterProtocol(int index);

private:
    PacketCapture *packetCapture;
    QTableWidget *packetTable;
    QComboBox *interfaceSelector;
    QComboBox *protocolFilter;  
    QPushButton *captureButton;

    void setupUI();
    void setupNetworkInterfaces();
    void applyDarkTheme();
};

#endif