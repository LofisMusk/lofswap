/********************************************************************************
** Form generated from reading UI file 'lofswap.ui'
**
** Created by: Qt User Interface Compiler version 6.9.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_LOFSWAP_H
#define UI_LOFSWAP_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_lofswap
{
public:
    QWidget *centralwidget;
    QVBoxLayout *mainLayout;
    QTabWidget *tabWidget;
    QWidget *sendTab;
    QVBoxLayout *sendLayout;
    QLineEdit *recipientEdit;
    QDoubleSpinBox *amountSpinBox;
    QPushButton *sendButton;
    QWidget *receiveTab;
    QVBoxLayout *receiveLayout;
    QPushButton *generateButton;
    QLineEdit *addressDisplay;
    QLabel *qrLabel;
    QWidget *txTab;
    QVBoxLayout *txLayout;
    QTextEdit *logOutput;
    QMenuBar *menubar;
    QMenu *menunigga;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *lofswap)
    {
        if (lofswap->objectName().isEmpty())
            lofswap->setObjectName("lofswap");
        lofswap->resize(673, 580);
        centralwidget = new QWidget(lofswap);
        centralwidget->setObjectName("centralwidget");
        mainLayout = new QVBoxLayout(centralwidget);
        mainLayout->setObjectName("mainLayout");
        tabWidget = new QTabWidget(centralwidget);
        tabWidget->setObjectName("tabWidget");
        sendTab = new QWidget();
        sendTab->setObjectName("sendTab");
        sendLayout = new QVBoxLayout(sendTab);
        sendLayout->setObjectName("sendLayout");
        recipientEdit = new QLineEdit(sendTab);
        recipientEdit->setObjectName("recipientEdit");

        sendLayout->addWidget(recipientEdit);

        amountSpinBox = new QDoubleSpinBox(sendTab);
        amountSpinBox->setObjectName("amountSpinBox");
        amountSpinBox->setDecimals(8);
        amountSpinBox->setMaximum(1000000.000000000000000);
        amountSpinBox->setValue(0.000000000000000);

        sendLayout->addWidget(amountSpinBox);

        sendButton = new QPushButton(sendTab);
        sendButton->setObjectName("sendButton");

        sendLayout->addWidget(sendButton);

        tabWidget->addTab(sendTab, QString());
        receiveTab = new QWidget();
        receiveTab->setObjectName("receiveTab");
        receiveLayout = new QVBoxLayout(receiveTab);
        receiveLayout->setObjectName("receiveLayout");
        generateButton = new QPushButton(receiveTab);
        generateButton->setObjectName("generateButton");

        receiveLayout->addWidget(generateButton);

        addressDisplay = new QLineEdit(receiveTab);
        addressDisplay->setObjectName("addressDisplay");
        addressDisplay->setReadOnly(true);

        receiveLayout->addWidget(addressDisplay);

        qrLabel = new QLabel(receiveTab);
        qrLabel->setObjectName("qrLabel");
        qrLabel->setAlignment(Qt::AlignmentFlag::AlignCenter);

        receiveLayout->addWidget(qrLabel);

        tabWidget->addTab(receiveTab, QString());
        txTab = new QWidget();
        txTab->setObjectName("txTab");
        txLayout = new QVBoxLayout(txTab);
        txLayout->setObjectName("txLayout");
        logOutput = new QTextEdit(txTab);
        logOutput->setObjectName("logOutput");
        logOutput->setReadOnly(true);

        txLayout->addWidget(logOutput);

        tabWidget->addTab(txTab, QString());

        mainLayout->addWidget(tabWidget);

        lofswap->setCentralWidget(centralwidget);
        menubar = new QMenuBar(lofswap);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 673, 21));
        menunigga = new QMenu(menubar);
        menunigga->setObjectName("menunigga");
        lofswap->setMenuBar(menubar);
        statusbar = new QStatusBar(lofswap);
        statusbar->setObjectName("statusbar");
        lofswap->setStatusBar(statusbar);

        menubar->addAction(menunigga->menuAction());

        retranslateUi(lofswap);

        tabWidget->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(lofswap);
    } // setupUi

    void retranslateUi(QMainWindow *lofswap)
    {
        lofswap->setWindowTitle(QCoreApplication::translate("lofswap", "Lofswap Wallet", nullptr));
        recipientEdit->setPlaceholderText(QCoreApplication::translate("lofswap", "Adres odbiorcy", nullptr));
        sendButton->setText(QCoreApplication::translate("lofswap", "Wy\305\233lij", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(sendTab), QCoreApplication::translate("lofswap", "Wy\305\233lij", nullptr));
        generateButton->setText(QCoreApplication::translate("lofswap", "Wygeneruj adres", nullptr));
        addressDisplay->setPlaceholderText(QCoreApplication::translate("lofswap", "Tw\303\263j adres", nullptr));
        qrLabel->setText(QCoreApplication::translate("lofswap", "(Tutaj b\304\231dzie kod QR)", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(receiveTab), QCoreApplication::translate("lofswap", "Odbierz", nullptr));
        logOutput->setPlaceholderText(QCoreApplication::translate("lofswap", "Logi transakcji", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(txTab), QCoreApplication::translate("lofswap", "Transakcje", nullptr));
        menunigga->setTitle(QCoreApplication::translate("lofswap", "nigga", nullptr));
    } // retranslateUi

};

namespace Ui {
    class lofswap: public Ui_lofswap {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_LOFSWAP_H
