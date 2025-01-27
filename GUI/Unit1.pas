unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls,
  Vcl.StdCtrls,
  System.JSON, System.IOUtils, System.Win.Registry, System.Math, System.NetEncoding, Uni,
  SQLiteUniProvider, System.IniFiles, Vcl.Menus, Unit2;

type
  TOutputFormat = (ofHuman, ofJSON, ofCSV);

  TFirefoxProfile = record
    Name: string;
    Path: string;
  end;

  TFirefoxProfiles = array of TFirefoxProfile;

  TCredentialRecord = record
    URL: string;
    Username: string;
    Password: string;
    EncType: Integer;
  end;

  TCredentialArray = array of TCredentialRecord;

  { TFirefoxDecryptor }
  TFirefoxDecryptor = class
  private
    FProfilePath: string;
    FSQLiteConnection: TUniConnection;
    FProvider: TSQLiteUniProvider;
    FOutputFormat: TOutputFormat;

    function InitializeNSS: Boolean;
    function DecryptData(const EncryptedData: string): string;
    function LoadCredentialsFromJSON: TCredentialArray;
    procedure ShutdownNSS;
  public
    constructor Create;
    destructor Destroy; override;
    property ProfilePath: string read FProfilePath write FProfilePath;
    property OutputFormat: TOutputFormat read FOutputFormat write FOutputFormat;
  end;

  TForm1 = class(TForm)
    ListView1: TListView;
    Button1: TButton;
    ComboBox1: TComboBox;
    Label1: TLabel;
    PopupMenu1: TPopupMenu;
    SaveDialog1: TSaveDialog;
    procedure FormCreate(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure SaveasHumanReadable1Click(Sender: TObject);
    procedure SaveasJSON1Click(Sender: TObject);
    procedure SaveasCSV1Click(Sender: TObject);
  private
    FDecryptor: TFirefoxDecryptor;
    FProfiles: TFirefoxProfiles;
    procedure LoadProfiles;
    procedure DecryptAndDisplay;
    procedure SaveToFile(const Format: TOutputFormat);
    function GetCredentialsFromListView: TCredentialArray;

  public

  end;

var
  Form1: TForm1;

const
  NSS_INIT_READONLY = $0;
  PW_NONE = 0;
  PW_ENCRYPTED = 1;

type
  SECItemType = (siBuffer = 0, siClearDataBuffer = 1, siCipherDataBuffer = 2,
    siDERCertBuffer = 3, siEncodedCertBuffer = 4, siDERNameBuffer = 5,
    siEncodedNameBuffer = 6, siAsciiNameString = 7, siAsciiString = 8,
    siDEROID = 9, siUnsignedInteger = 10, siUTCTime = 11,
    siGeneralizedTime = 12);

  SECItem = record
    ItemType: SECItemType;
    Data: PByte;
    Len: Cardinal;
  end;

  PSECItem = ^SECItem;

type
  NSS_Init = function(configdir: PAnsiChar): Integer; cdecl;
  NSS_Shutdown = function: Integer; cdecl;
  PK11_GetInternalKeySlot = function: Pointer; cdecl;
  PK11SDR_Decrypt = function(const input: PSECItem; output: PSECItem;
    cx: Pointer): Integer; cdecl;
  PK11_CheckUserPassword = function(slot: Pointer; Password: PAnsiChar)
    : Integer; cdecl;
  PK11_NeedLogin = function(slot: Pointer): Integer; cdecl;

var
  NSSModule: HMODULE;
  NSS_InitFunc: NSS_Init;
  NSS_ShutdownFunc: NSS_Shutdown;
  PK11_GetInternalKeySlotFunc: PK11_GetInternalKeySlot;
  PK11SDR_DecryptFunc: PK11SDR_Decrypt;
  PK11_CheckUserPasswordFunc: PK11_CheckUserPassword;
  PK11_NeedLoginFunc: PK11_NeedLogin;

implementation

{$R *.dfm}

function TForm1.GetCredentialsFromListView: TCredentialArray;
var
  i: Integer;
begin
  SetLength(Result, ListView1.Items.Count);
  for i := 0 to ListView1.Items.Count - 1 do
  begin
    Result[i].URL := ListView1.Items[i].Caption;
    Result[i].Username := ListView1.Items[i].SubItems[0];
    Result[i].Password := ListView1.Items[i].SubItems[1];
    Result[i].EncType := PW_NONE; // Already decrypted
  end;
end;

function GetFirefoxProfiles: TFirefoxProfiles;
var
  IniFile: TIniFile;
  IniPath: string;
  Sections: TStringList;
  i: Integer;
  ProfilePath: string;
begin
  SetLength(Result, 0);
  IniPath := TPath.Combine(GetEnvironmentVariable('APPDATA'),
    'Mozilla\Firefox\profiles.ini');

  if not FileExists(IniPath) then
    Exit;

  Sections := TStringList.Create;
  IniFile := TIniFile.Create(IniPath);
  try
    IniFile.ReadSections(Sections);
    for i := 0 to Sections.Count - 1 do
    begin
      if Copy(Sections[i], 1, 7) = 'Profile' then
      begin
        ProfilePath := IniFile.ReadString(Sections[i], 'Path', '');
        if ProfilePath <> '' then
        begin
          SetLength(Result, Length(Result) + 1);
          Result[High(Result)].Name := ProfilePath;
          Result[High(Result)].Path := TPath.Combine(ExtractFilePath(IniPath),
            ProfilePath);
        end;
      end;
    end;
  finally
    IniFile.Free;
    Sections.Free;
  end;
end;

{ TFirefoxDecryptor }

constructor TFirefoxDecryptor.Create;
begin
  inherited;
  FProvider := TSQLiteUniProvider.Create(nil);
  FSQLiteConnection := TUniConnection.Create(nil);
  FSQLiteConnection.ProviderName := 'SQLite';
end;

destructor TFirefoxDecryptor.Destroy;
begin
  ShutdownNSS;
  FSQLiteConnection.Free;
  FProvider.Free;
  inherited;
end;

function TFirefoxDecryptor.InitializeNSS: Boolean;
const
  NSS_LIB_X64 = 'C:\Program Files\Mozilla Firefox\nss3.dll';
  NSS_LIB_X86 = 'C:\Program Files (x86)\Mozilla Firefox\nss3.dll';
var
  CurrentDir: string;
  NSS_LIB: string;
  FirefoxDir: string;
  NSSResult: Integer;
  KeySlot: Pointer;
  PasswordForm: TPassword;
begin
  Result := False;
  if SizeOf(Pointer) = 4 then
  begin
    NSS_LIB := NSS_LIB_X86;
    FirefoxDir := 'C:\Program Files (x86)\Mozilla Firefox';
  end
  else
  begin
    NSS_LIB := NSS_LIB_X64;
    FirefoxDir := 'C:\Program Files\Mozilla Firefox';
  end;
  CurrentDir := GetCurrentDir;
  SetCurrentDir(FirefoxDir);
  try
    NSSModule := LoadLibrary(PChar(NSS_LIB));
    if NSSModule = 0 then
      Exit;
    @NSS_InitFunc := GetProcAddress(NSSModule, 'NSS_Init');
    @NSS_ShutdownFunc := GetProcAddress(NSSModule, 'NSS_Shutdown');
    @PK11_GetInternalKeySlotFunc := GetProcAddress(NSSModule,
      'PK11_GetInternalKeySlot');
    @PK11SDR_DecryptFunc := GetProcAddress(NSSModule, 'PK11SDR_Decrypt');
    @PK11_CheckUserPasswordFunc := GetProcAddress(NSSModule,
      'PK11_CheckUserPassword');
    @PK11_NeedLoginFunc := GetProcAddress(NSSModule, 'PK11_NeedLogin');
    if not(Assigned(NSS_InitFunc) and Assigned(NSS_ShutdownFunc) and
      Assigned(PK11_GetInternalKeySlotFunc) and Assigned(PK11SDR_DecryptFunc)
      and Assigned(PK11_CheckUserPasswordFunc) and Assigned(PK11_NeedLoginFunc))
    then
      Exit;
    NSSResult := NSS_InitFunc(PAnsiChar(AnsiString('sql:' + FProfilePath)));
    if NSSResult <> 0 then
      Exit;
    KeySlot := PK11_GetInternalKeySlotFunc();
    if KeySlot = nil then
      Exit;

    // Try empty password first
    if PK11_CheckUserPasswordFunc(KeySlot, '') <> 0 then
    begin
      PasswordForm := TPassword.Create(nil);
      try
        if PasswordForm.ShowModal = mrOK then
        begin
          PasswordForm.FPassword := PasswordForm.Edit1.Text;
          if PK11_CheckUserPasswordFunc(KeySlot,
            PAnsiChar(AnsiString(PasswordForm.Password))) = 0 then
            Result := True
          else
            raise Exception.Create('Invalid master password');
        end;
      finally
        PasswordForm.Free;
      end;
      Exit;
    end;

    Result := True;
  finally
    SetCurrentDir(CurrentDir);
  end;
end;

procedure TForm1.SaveToFile(const Format: TOutputFormat);
var
  Credentials: TCredentialArray;
  Stream: TStreamWriter;
  JSONArray: TJSONArray;
  JSONObject: TJSONObject;
  i: Integer;
  S: string;
begin
  SaveDialog1.FileName := '';
  case Format of
    ofHuman:
      begin
        SaveDialog1.DefaultExt := 'txt';
        SaveDialog1.Filter := 'Text files (*.txt)|*.txt';
      end;
    ofJSON:
      begin
        SaveDialog1.DefaultExt := 'json';
        SaveDialog1.Filter := 'JSON files (*.json)|*.json';
      end;
    ofCSV:
      begin
        SaveDialog1.DefaultExt := 'csv';
        SaveDialog1.Filter := 'CSV files (*.csv)|*.csv';
      end;
  end;

  if not SaveDialog1.Execute then
    Exit;

  Credentials := GetCredentialsFromListView;

  try
    Stream := TStreamWriter.Create(SaveDialog1.FileName, False, TEncoding.UTF8);
    try
      case Format of
        ofHuman:
          begin
            for i := 0 to High(Credentials) do
            begin
              Stream.WriteLine('');
              Stream.WriteLine('Website:   ' + Credentials[i].URL);
              Stream.WriteLine('Username: ''' + Credentials[i].Username + '''');
              Stream.WriteLine('Password: ''' + Credentials[i].Password + '''');
            end;
          end;

        ofJSON:
          begin
            JSONArray := TJSONArray.Create;
            try
              for i := 0 to High(Credentials) do
              begin
                JSONObject := TJSONObject.Create;
                JSONObject.AddPair('url', Credentials[i].URL);
                JSONObject.AddPair('user', Credentials[i].Username);
                JSONObject.AddPair('password', Credentials[i].Password);
                JSONArray.AddElement(JSONObject);
              end;
              Stream.Write(JSONArray.Format(2));
            finally
              JSONArray.Free;
            end;
          end;

        ofCSV:
          begin
            Stream.WriteLine('url;username;password');
            for i := 0 to High(Credentials) do
            begin
              S := Credentials[i].URL + ';' + Credentials[i].Username + ';' +
                Credentials[i].Password;
              Stream.WriteLine(S);
            end;
          end;
      end;
      ShowMessage('File saved successfully!');
    finally
      Stream.Free;
    end;
  except
    on E: Exception do
      ShowMessage('Error saving file: ' + E.Message);
  end;
end;

procedure TFirefoxDecryptor.ShutdownNSS;
begin
  if Assigned(NSS_ShutdownFunc) then
    NSS_ShutdownFunc;

  if NSSModule <> 0 then
    FreeLibrary(NSSModule);
end;

function TFirefoxDecryptor.DecryptData(const EncryptedData: string): string;
var
  DecodedData: TBytes;
  InputItem, OutputItem: SECItem;
  DecryptResult: Integer;
begin
  Result := '';
  try

    DecodedData := TNetEncoding.Base64.DecodeStringToBytes(EncryptedData);

    InputItem.ItemType := siBuffer;
    InputItem.Data := @DecodedData[0];
    InputItem.Len := Length(DecodedData);

    OutputItem.ItemType := siBuffer;
    OutputItem.Data := nil;
    OutputItem.Len := 0;

    DecryptResult := PK11SDR_DecryptFunc(@InputItem, @OutputItem, nil);

    if DecryptResult = 0 then
      SetString(Result, PAnsiChar(OutputItem.Data), OutputItem.Len)
    else
      Result := '*** decryption failed ***';
  except
    Result := '*** decryption failed ***';
  end;
end;

function TFirefoxDecryptor.LoadCredentialsFromJSON: TCredentialArray;
var
  JSONFile: string;
  JSONString: string;
  JSONValue: TJSONValue;
  JSONArray: TJSONArray;
  i: Integer;
begin
  SetLength(Result, 0);
  JSONFile := TPath.Combine(FProfilePath, 'logins.json');

  if not FileExists(JSONFile) then
    Exit;

  try
    JSONString := TFile.ReadAllText(JSONFile);
    JSONValue := TJSONObject.ParseJSONValue(JSONString);
    if not Assigned(JSONValue) then
      Exit;

    try
      if not(JSONValue is TJSONObject) then
        Exit;

      JSONArray := TJSONObject(JSONValue).GetValue<TJSONArray>('logins');
      if not Assigned(JSONArray) then
        Exit;

      SetLength(Result, JSONArray.Count);
      for i := 0 to JSONArray.Count - 1 do
      begin
        with Result[i] do
        begin
          URL := JSONArray.Items[i].GetValue<string>('hostname');
          Username := JSONArray.Items[i].GetValue<string>('encryptedUsername');
          Password := JSONArray.Items[i].GetValue<string>('encryptedPassword');
          EncType := JSONArray.Items[i].GetValue<Integer>('encType');
        end;
      end;
    finally
      JSONValue.Free;
    end;
  except
    SetLength(Result, 0);
  end;
end;


{ TForm1 }

procedure TForm1.FormCreate(Sender: TObject);
begin
  FDecryptor := TFirefoxDecryptor.Create;
  LoadProfiles;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  FDecryptor.Free;
end;

procedure TForm1.LoadProfiles;
var
  i: Integer;
begin
  FProfiles := GetFirefoxProfiles;
  ComboBox1.Items.Clear;

  for i := 0 to High(FProfiles) do
    ComboBox1.Items.Add(FProfiles[i].Name);

  if ComboBox1.Items.Count > 0 then
  begin
    ComboBox1.ItemIndex := 0;
    FDecryptor.ProfilePath := FProfiles[0].Path;
  end;
end;

procedure TForm1.SaveasHumanReadable1Click(Sender: TObject);
begin
  SaveToFile(ofHuman);
end;

procedure TForm1.SaveasJSON1Click(Sender: TObject);
begin
  SaveToFile(ofJSON);
end;

procedure TForm1.SaveasCSV1Click(Sender: TObject);
begin
  SaveToFile(ofCSV);
end;

procedure TForm1.Button1Click(Sender: TObject);
begin
  if ComboBox1.ItemIndex >= 0 then
  begin
    FDecryptor.ProfilePath := FProfiles[ComboBox1.ItemIndex].Path;
    if FDecryptor.InitializeNSS then
      DecryptAndDisplay
    else
      ShowMessage
        ('Failed to initialize NSS. Please make sure Firefox is installed correctly.');
  end
  else
    ShowMessage('Please select a Firefox profile.');
end;

procedure TForm1.DecryptAndDisplay;
var
  Credentials, DecryptedCreds: TCredentialArray;
  i: Integer;
  Item: TListItem;
begin
  ListView1.Items.Clear;

  // Try JSON first, then SQLite
  Credentials := FDecryptor.LoadCredentialsFromJSON;

  SetLength(DecryptedCreds, Length(Credentials));

  // Decrypt credentials
  for i := 0 to Length(Credentials) - 1 do
  begin
    DecryptedCreds[i].URL := Credentials[i].URL;

    if Credentials[i].EncType = PW_ENCRYPTED then
    begin
      DecryptedCreds[i].Username := FDecryptor.DecryptData
        (Credentials[i].Username);
      DecryptedCreds[i].Password := FDecryptor.DecryptData
        (Credentials[i].Password);
    end
    else
    begin
      DecryptedCreds[i].Username := Credentials[i].Username;
      DecryptedCreds[i].Password := Credentials[i].Password;
    end;

    // Add to ListView
    Item := ListView1.Items.Add;
    Item.Caption := DecryptedCreds[i].URL;
    Item.SubItems.Add(DecryptedCreds[i].Username);
    Item.SubItems.Add(DecryptedCreds[i].Password);
  end;
end;

end.