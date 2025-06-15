#include "lofswap.h"
#include "ui_lofswap.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QMessageBox>

lofswap::lofswap(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::lofswap)
{
    ui->setupUi(this);

    connect(ui->generateButton, &QPushButton::clicked, this, &lofswap::on_generateButton_clicked);
    connect(ui->sendButton, &QPushButton::clicked, this, &lofswap::on_sendButton_clicked);

    // Opcjonalnie na start wyczyść dane
    ui->addressDisplay->setText("");
    ui->logOutput->append("Portfel uruchomiony.");
}

lofswap::~lofswap()
{
    delete ui;
}

void lofswap::on_generateButton_clicked()
{
    QString seed = QString::number(QDateTime::currentSecsSinceEpoch()) + "lofswap";
    QString hash = QCryptographicHash::hash(seed.toUtf8(), QCryptographicHash::Sha256).toHex();
    currentAddress = hash.left(32);  // uproszczony adres

    ui->addressDisplay->setText(currentAddress);
    ui->logOutput->append("✅ Wygenerowano adres: " + currentAddress);
}

void lofswap::on_sendButton_clicked()
{
    QString recipient = ui->recipientEdit->text();
    double amount = ui->amountSpinBox->value();

    if (currentAddress.isEmpty()) {
        QMessageBox::warning(this, "Brak adresu", "Najpierw wygeneruj adres portfela.");
        return;
    }

    if (recipient.isEmpty()) {
        QMessageBox::warning(this, "Brak odbiorcy", "Podaj adres odbiorcy.");
        return;
    }

    if (amount <= 0) {
        QMessageBox::warning(this, "Zła kwota", "Kwota musi być większa od zera.");
        return;
    }

    // TODO: tu dodamy logikę tworzenia i dodania transakcji do blockchaina
    QString log = QString("💸 Wysłano %1 tokenów do %2").arg(amount).arg(recipient);
    ui->logOutput->append(log);
}
