#include "filterdialog.h"
#include "ui_filterdialog.h"

FilterDialog::FilterDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::FilterDialog)
{
    ui->setupUi(this);
    connect(ui->okButton, &QPushButton::clicked, [=]() {
        emit sendFilterRule(ui->filterlineEdit->text());
        this->close();
    });
    connect(ui->cancelButton, &QPushButton::clicked, [=]() {
        emit sendFilterRule("");
        this->close();
    });
}

FilterDialog::~FilterDialog()
{
    delete ui;
}
