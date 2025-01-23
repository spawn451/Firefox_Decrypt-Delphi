program FirefoxDecrypt_vcl;

uses
  Vcl.Forms,
  Unit1 in 'Unit1.pas' {Form1},
  Vcl.Themes,
  Vcl.Styles,
  Unit2 in 'Unit2.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  TStyleManager.TrySetStyle('Windows11 Polar Dark');
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
