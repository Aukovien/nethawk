#include "MainWindow.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QNetworkInterface>
#include <QApplication>
#include <QPalette>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setupUI();
    setupNetworkInterfaces();
    applyDarkTheme();

    packetCapture = new PacketCapture(this);
    connect(packetCapture, &PacketCapture::packetCaptured, 
            this, &MainWindow::onPacketCaptured);
}

void MainWindow::setupUI() {
    // Main widget and layout
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // Interface selector
    interfaceSelector = new QComboBox();
    mainLayout->addWidget(interfaceSelector);

    // Protocol filter
    protocolFilter = new QComboBox();
    protocolFilter->addItems({"All Protocols", "TCP", "UDP", "ICMP"});
    connect(protocolFilter, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &MainWindow::filterProtocol);
    mainLayout->addWidget(protocolFilter);

    // Packet table
    packetTable = new QTableWidget();
    packetTable->setColumnCount(5);
    packetTable->setHorizontalHeaderLabels({"Timestamp", "Source IP", "Destination IP", "Protocol", "Size"});
    packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    mainLayout->addWidget(packetTable);

    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    captureButton = new QPushButton("Start Capture");
    
    buttonLayout->addWidget(captureButton);
    
    mainLayout->addLayout(buttonLayout);

    // Connections
    connect(captureButton, &QPushButton::clicked, this, &MainWindow::toggleCapture);

    setCentralWidget(centralWidget);
    setWindowTitle("NetHawk - Network Monitor");
    resize(1000, 600);
}

void MainWindow::setupNetworkInterfaces() {
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface &interface : interfaces) {
        interfaceSelector->addItem(interface.name());
    }
}

void MainWindow::applyDarkTheme() {
    // Dark theme palette
    QPalette darkPalette;
    darkPalette.setColor(QPalette::Window, QColor(53, 53, 53));
    darkPalette.setColor(QPalette::WindowText, Qt::white);
    darkPalette.setColor(QPalette::Base, QColor(25, 25, 25));
    darkPalette.setColor(QPalette::AlternateBase, QColor(53, 53, 53));
    darkPalette.setColor(QPalette::ToolTipBase, Qt::white);
    darkPalette.setColor(QPalette::ToolTipText, Qt::white);
    darkPalette.setColor(QPalette::Text, Qt::white);
    darkPalette.setColor(QPalette::Button, QColor(53, 53, 53));
    darkPalette.setColor(QPalette::ButtonText, Qt::white);
    darkPalette.setColor(QPalette::BrightText, Qt::red);
    darkPalette.setColor(QPalette::Link, QColor(42, 130, 218));

    qApp->setPalette(darkPalette);
    qApp->setStyleSheet("QToolTip { color: #ffffff; background-color: #2a82da; border: 1px solid white; }");
}

void MainWindow::onPacketCaptured(const PacketInfo &packet) {
    int row = packetTable->rowCount();
    packetTable->insertRow(row);
    
    packetTable->setItem(row, 0, new QTableWidgetItem(packet.timestamp.toString("yyyy-MM-dd hh:mm:ss")));
    packetTable->setItem(row, 1, new QTableWidgetItem(packet.sourceIP));
    packetTable->setItem(row, 2, new QTableWidgetItem(packet.destIP));
    packetTable->setItem(row, 3, new QTableWidgetItem(packet.protocol));
    packetTable->setItem(row, 4, new QTableWidgetItem(QString::number(packet.size)));

    // Auto-scroll to bottom
    packetTable->scrollToBottom();
}

void MainWindow::toggleCapture() {
    if (captureButton->text() == "Start Capture") {
        // Start capture
        QString interface = interfaceSelector->currentText();
        packetCapture->startCapture(interface);
        captureButton->setText("Stop Capture");
    } else {
        // Stop capture
        packetCapture->stopCapture();
        captureButton->setText("Start Capture");
    }
}

void MainWindow::filterProtocol(int index) {
    QString selectedProtocol = protocolFilter->itemText(index);
    
    for (int row = 0; row < packetTable->rowCount(); ++row) {
        bool show = (selectedProtocol == "All Protocols" || 
                     packetTable->item(row, 3)->text() == selectedProtocol);
        packetTable->setRowHidden(row, show);
    }
}