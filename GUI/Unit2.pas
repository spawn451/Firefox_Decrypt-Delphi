unit Unit2;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TPassword = class(TForm)
    Button1: TButton;
    Button2: TButton;
    Edit1: TEdit;
    Label1: TLabel;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);

  public
    FPassword: string;
    property Password: string read FPassword;
  end;

var
  Password: TPassword;

implementation

{$R *.dfm}

procedure TPassword.Button1Click(Sender: TObject);
begin
  FPassword := Edit1.Text;
  ModalResult := mrOK;
end;

procedure TPassword.Button2Click(Sender: TObject);
begin
  ModalResult := mrCancel;
end;

end.
