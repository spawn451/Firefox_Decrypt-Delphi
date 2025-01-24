program FirefoxDecrypt_console;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.IOUtils,
  System.Win.Registry,
  System.Math,
  System.NetEncoding,
  Winapi.Windows,
  Uni,
  SQLiteUniProvider,
  System.IniFiles;

type
  TOutputFormat = (ofHuman, ofJSON, ofCSV);

type
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

    function GetFirefoxProfilePath: string;
    function InitializeNSS: Boolean;
    function DecryptData(const EncryptedData: string): string;
    function LoadCredentialsFromJSON: TCredentialArray;
    function LoadCredentialsFromSQLite: TCredentialArray;
    procedure ShutdownNSS;
    procedure OutputCredentials(const Credentials: TCredentialArray);
    procedure OutputHuman(const Credentials: TCredentialArray);
    procedure OutputJSON(const Credentials: TCredentialArray);
    procedure OutputCSV(const Credentials: TCredentialArray);

  public
    constructor Create;
    destructor Destroy; override;

    procedure DecryptPasswords;
    property ProfilePath: string read FProfilePath write FProfilePath;
    property OutputFormat: TOutputFormat read FOutputFormat write FOutputFormat;
  end;

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

  { TFirefoxDecryptor }

constructor TFirefoxDecryptor.Create;
begin
  inherited;
  FProvider := TSQLiteUniProvider.Create(nil);
  FSQLiteConnection := TUniConnection.Create(nil);
  FSQLiteConnection.ProviderName := 'SQLite';

  FProfilePath := GetFirefoxProfilePath;
  if not InitializeNSS then
    raise Exception.Create('Failed to initialize NSS library');
end;

destructor TFirefoxDecryptor.Destroy;
begin
  ShutdownNSS;
  FSQLiteConnection.Free;
  FProvider.Free;
  inherited;
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
  begin
    WriteLn('profiles.ini not found at: ', IniPath);
    Exit;
  end;

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

function SelectProfile: string;
var
  Profiles: TFirefoxProfiles;
  i, Choice: Integer;
  input: string;
begin
  Result := '';
  Profiles := GetFirefoxProfiles;

  if Length(Profiles) = 0 then
  begin
    WriteLn('No Firefox profiles found.');
    Exit;
  end;

  WriteLn('Select the Mozilla profile you wish to decrypt');
  for i := 0 to High(Profiles) do
    WriteLn(i + 1, ' -> ', Profiles[i].Name);

  while True do
  begin
    Write('Profile number (1-', Length(Profiles), '): ');
    ReadLn(input);
    if TryStrToInt(input, Choice) and (Choice >= 1) and
      (Choice <= Length(Profiles)) then
    begin
      Result := Profiles[Choice - 1].Path;
      Break;
    end;
    WriteLn('Invalid selection. Please try again.');
  end;
end;

function TFirefoxDecryptor.GetFirefoxProfilePath: string;
var
  SelectedProfile: string;
begin
  SelectedProfile := SelectProfile;
  if SelectedProfile = '' then
    raise Exception.Create('No profile selected or no profiles found.');
  Result := SelectedProfile;
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
  Password: string;
  MaxAttempts: Integer;
  Attempts: Integer;
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
    begin
      WriteLn('Error: Could not load NSS');
      Exit;
    end;

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
    begin
      WriteLn('Error: Could not load all required NSS functions');
      Exit;
    end;

    NSSResult := NSS_InitFunc(PAnsiChar(AnsiString('sql:' + FProfilePath)));
    if NSSResult <> 0 then
    begin
      WriteLn('Error: Failed to initialize NSS');
      Exit;
    end;

    KeySlot := PK11_GetInternalKeySlotFunc();
    if KeySlot = nil then
    begin
      WriteLn('Error: Could not get internal key slot');
      Exit;
    end;

    // Try empty password first
    if PK11_CheckUserPasswordFunc(KeySlot, '') <> 0 then
    begin
      WriteLn('Master password detected');
      MaxAttempts := 3;
      Attempts := 0;

      repeat
        Inc(Attempts);
        Write('Enter master password: ');
        ReadLn(Password);

        if PK11_CheckUserPasswordFunc(KeySlot, PAnsiChar(AnsiString(Password)
          )) = 0 then
        begin
          WriteLn('Password accepted');
          Result := True;
          Exit;
        end;

        WriteLn('Invalid password. ', MaxAttempts - Attempts,
          ' attempts remaining.');
      until Attempts >= MaxAttempts;

      WriteLn('Maximum password attempts exceeded.');
      Exit;
    end;

    Result := True;
  finally
    SetCurrentDir(CurrentDir);
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

    // Setup input item
    InputItem.ItemType := siBuffer;
    InputItem.Data := @DecodedData[0];
    InputItem.Len := Length(DecodedData);

    // Setup output item
    OutputItem.ItemType := siBuffer;
    OutputItem.Data := nil;
    OutputItem.Len := 0;

    DecryptResult := PK11SDR_DecryptFunc(@InputItem, @OutputItem, nil);

    if DecryptResult = 0 then
    begin
      SetString(Result, PAnsiChar(OutputItem.Data), OutputItem.Len);
    end
    else
      WriteLn('PK11SDR_Decrypt failed');
  except
    on E: Exception do
    begin
      WriteLn('Decryption error: ', E.Message);
      Result := '*** decryption failed ***';
    end;
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

function TFirefoxDecryptor.LoadCredentialsFromSQLite: TCredentialArray;
var
  Query: TUniQuery;
  RecordCount: Integer;
begin
  SetLength(Result, 0);

  if not FileExists(TPath.Combine(FProfilePath, 'signons.sqlite')) then
    Exit;

  FSQLiteConnection.Database := TPath.Combine(FProfilePath, 'signons.sqlite');

  try
    FSQLiteConnection.Connect;
    Query := TUniQuery.Create(nil);
    try
      Query.Connection := FSQLiteConnection;
      Query.SQL.Text :=
        'SELECT hostname, encryptedUsername, encryptedPassword, encType FROM moz_logins';
      Query.Open;

      RecordCount := Query.RecordCount;
      SetLength(Result, RecordCount);

      Query.First;
      while not Query.Eof do
      begin
        with Result[Query.RecNo - 1] do
        begin
          URL := Query.FieldByName('hostname').AsString;
          Username := Query.FieldByName('encryptedUsername').AsString;
          Password := Query.FieldByName('encryptedPassword').AsString;
          EncType := Query.FieldByName('encType').AsInteger;
        end;
        Query.Next;
      end;
    finally
      Query.Free;
    end;
  except
    SetLength(Result, 0);
  end;
end;

procedure TFirefoxDecryptor.OutputHuman(const Credentials: TCredentialArray);
var
  i: Integer;
begin
  for i := 0 to Length(Credentials) - 1 do
  begin
    WriteLn;
    WriteLn('Website:   ', Credentials[i].URL);
    WriteLn('Username: ''', Credentials[i].Username, '''');
    WriteLn('Password: ''', Credentials[i].Password, '''');
  end;
  WriteLn;
end;

procedure TFirefoxDecryptor.OutputJSON(const Credentials: TCredentialArray);
var
  JSONArray: TJSONArray;
  JSONObject: TJSONObject;
  i: Integer;
begin
  JSONArray := TJSONArray.Create;
  try
    for i := 0 to Length(Credentials) - 1 do
    begin
      JSONObject := TJSONObject.Create;
      JSONObject.AddPair('url', Credentials[i].URL);
      JSONObject.AddPair('user', Credentials[i].Username);
      JSONObject.AddPair('password', Credentials[i].Password);
      JSONArray.AddElement(JSONObject);
    end;
    WriteLn(JSONArray.Format(2));
  finally
    JSONArray.Free;
  end;
end;

procedure TFirefoxDecryptor.OutputCSV(const Credentials: TCredentialArray);
var
  i: Integer;
begin
  WriteLn('url;username;password');
  for i := 0 to Length(Credentials) - 1 do
    WriteLn(Format('%s;%s;%s', [Credentials[i].URL, Credentials[i].Username,
      Credentials[i].Password]));
end;

procedure TFirefoxDecryptor.OutputCredentials(const Credentials
  : TCredentialArray);
begin
  case FOutputFormat of
    ofHuman:
      OutputHuman(Credentials);
    ofJSON:
      OutputJSON(Credentials);
    ofCSV:
      OutputCSV(Credentials);
  end;
end;

procedure TFirefoxDecryptor.DecryptPasswords;
var
  Credentials, DecryptedCreds: TCredentialArray;
  i: Integer;
begin
  // Try JSON first, then SQLite
  Credentials := LoadCredentialsFromJSON;
  if Length(Credentials) = 0 then
    Credentials := LoadCredentialsFromSQLite;

  SetLength(DecryptedCreds, Length(Credentials));

  // Decrypt credentials
  for i := 0 to Length(Credentials) - 1 do
  begin
    DecryptedCreds[i].URL := Credentials[i].URL;

    if Credentials[i].EncType = PW_ENCRYPTED then
    begin
      DecryptedCreds[i].Username := DecryptData(Credentials[i].Username);
      DecryptedCreds[i].Password := DecryptData(Credentials[i].Password);
    end
    else
    begin
      DecryptedCreds[i].Username := Credentials[i].Username;
      DecryptedCreds[i].Password := Credentials[i].Password;
    end;
  end;

  OutputCredentials(DecryptedCreds);
end;

{ Main program }

procedure PrintUsage;
begin
  WriteLn('Firefox Password Decryptor');
  WriteLn('Usage: FirefoxDecrypt.exe [options]');
  WriteLn;
  WriteLn('Options:');
  WriteLn('  -f, --format FORMAT   Output format (human, json, csv)');
  WriteLn('  -p, --profile PATH    Firefox profile path');
  WriteLn('  -l, --list            List available profiles');
  WriteLn('  -c, --choice NUMBER   Profile to use (starts with 1)');
  WriteLn('  -h, --help            Show this help message');
  WriteLn;
end;

procedure ListProfiles;
var
  Profiles: TFirefoxProfiles;
  i: Integer;
begin
  Profiles := GetFirefoxProfiles;
  if Length(Profiles) = 0 then
  begin
    WriteLn('No Firefox profiles found.');
    Exit;
  end;

  WriteLn('Available Firefox profiles:');
  for i := 0 to High(Profiles) do
    WriteLn(i + 1, ' -> ', Profiles[i].Name);
end;

var
  Decryptor: TFirefoxDecryptor;
  i: Integer;
  Param, Value: string;
  ListOnly: Boolean;
  ProfileChoice: Integer;
  Profiles: TFirefoxProfiles;

begin
  try
    // Check for help flag first, before doing anything else
    for i := 1 to ParamCount do
    begin
      if (ParamStr(i) = '-h') or (ParamStr(i) = '--help') then
      begin
        PrintUsage;
        Exit;
      end;
    end;

    ListOnly := False;
    ProfileChoice := 0;

    Decryptor := TFirefoxDecryptor.Create;
    try
      // Parse other command line arguments
      i := 1;
      while i <= ParamCount do
      begin
        Param := ParamStr(i);

        if (Param = '-l') or (Param = '--list') then
        begin
          ListOnly := True;
        end
        else if (Param = '-c') or (Param = '--choice') then
        begin
          Inc(i);
          if i <= ParamCount then
            ProfileChoice := StrToIntDef(ParamStr(i), 0);
        end
        else if (Param = '-f') or (Param = '--format') then
        begin
          Inc(i);
          if i <= ParamCount then
          begin
            Value := LowerCase(ParamStr(i));
            if Value = 'json' then
              Decryptor.OutputFormat := ofJSON
            else if Value = 'csv' then
              Decryptor.OutputFormat := ofCSV
            else
              Decryptor.OutputFormat := ofHuman;
          end;
        end;

        Inc(i);
      end;

      if ListOnly then
      begin
        ListProfiles;
        Exit;
      end;

      // If profile choice specified, validate it
      if ProfileChoice > 0 then
      begin
        Profiles := GetFirefoxProfiles;
        if (ProfileChoice < 1) or (ProfileChoice > Length(Profiles)) then
        begin
          WriteLn('Invalid profile choice: ', ProfileChoice);
          WriteLn('Available profiles:');
          ListProfiles;
          Exit;
        end;
      end;

      // Decrypt and output passwords
      Decryptor.DecryptPasswords;

    finally
      Decryptor.Free;
    end;

  except
    on E: Exception do
    begin
      WriteLn('Error: ', E.Message);
      ExitCode := 1;
    end;
  end;

end.