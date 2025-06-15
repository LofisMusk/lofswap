#include "lofswap.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    lofswap w;
    w.show();
    return a.exec();
}
