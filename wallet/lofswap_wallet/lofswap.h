#ifndef LOFSWAP_H
#define LOFSWAP_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class lofswap;
}
QT_END_NAMESPACE

class lofswap : public QMainWindow
{
    Q_OBJECT

    QString currentAddress;


public:
    lofswap(QWidget *parent = nullptr);
    ~lofswap();

private slots:
    void on_sendButton_clicked();
    void on_generateButton_clicked();

private:
    Ui::lofswap *ui;   
};
#endif // LOFSWAP_H

