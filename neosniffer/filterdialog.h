#ifndef FILTERDIALOG_H
#define FILTERDIALOG_H

#include <QDialog>

namespace Ui {
class FilterDialog;
}

class FilterDialog : public QDialog
{
    Q_OBJECT

public:
    explicit FilterDialog(QWidget *parent = nullptr);
    ~FilterDialog();

private:
    Ui::FilterDialog *ui;

signals:
    void sendFilterRule(QString rule);
};

#endif // FILTERDIALOG_H
