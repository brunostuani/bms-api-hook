unit BmsIpcUtil;

interface
uses
   Windows;

{ ****************************************************************************

  BmsIpcUtil - Intercomunica��o entre processos
  Autor: Bruno Martins Stuani

 **************************************************************************** }

type
   TBmsIpcCallBack =                  // Formato do CallBack do IPC
      procedure( Buffer: Pointer;     // Ponteiro para os dados que ser�o passados
                 TamBuffer: Integer;  // Tamanho dos dados passados
                 Resposta: Pointer;   // Caso haja uma resposta, a mesma ser� passada aqui
                 TamResposta: Integer // Tamanho da resposta
                 ) stdcall;

   function BmsCriaSecaoIpc              // Inicializa uma se��o de comunica��o
            ( IdSecao: PChar;            // Identificador qualquer que identificar� uma se��o
              CallBack: TBmsIpcCallBack  // CallBack do IPC
              ): Boolean;

   function BmsDestroiSecaoIpc           // Finaliza uma se��o do IPC
            ( IdSecao: PChar             // Identificador que identifica a se��o
              ): Boolean;

   function BmsComunicaIpc              // Inicializa uma se��o de comunica��o
            ( IdSecao        : PChar;   // Identificador da se��o
              Buffer         : Pointer; // Ponteiro para o buffer a ser passado como par�metro
              Tamanho        : Integer; // Tamanho do buffer
              Resposta       : Pointer; // Ponteiro para uma resposta do CallBack
              TamResposta    : Integer  // Tamanho da resposta do CallBack
              ): Boolean;

implementation
uses
   BmsMemUtil;

// Devemos guardar em um espa�o compartilhado, as informa��es do IPC,
// que s�o o ponteiro do CallBack e o Handle do processo

type
   TIpcInfo = packed record
      CallBack: Cardinal;
      Processo: Cardinal;
   end;

   
{****************************************************************************

 BmsComunicaIpc - Inicializa uma se��o de comunica��o

    IdSecao     - Identificador da se��o
    Buffer      - Ponteiro para o buffer a ser passado como par�metro
    Tamanho     - Tamanho do buffer
    Resposta    - Ponteiro para onde dever� ser salva a resposta do CallBack
    TamResposta - Tamanho m�ximo alocado para a resposta

 **************************************************************************** }

function BmsComunicaIpc( IdSecao: PChar; Buffer: Pointer; Tamanho: Integer; Resposta: Pointer; TamResposta: Integer ): Boolean;
type
   // O processo interno do m�todo utilizado pela BmsApiHook � simples,
   // � criada uma Thread no contexto do processo que criou a Se��o,
   // e este Thread ir� executar as instru��es abaixo, que chama o CallBack
   // seguido de um RET.

   //  PUSH  $0
   //  PUSH  $0
   //  PUSH  Tamanho_Buffer
   //  PUSH  dword ptr Buffer
   //  CALL  CallBack
   //  CALL  ExitThread
   //  RET

   TExecCallBack = packed record
      Int3     : Byte;
      Push1    : Byte;
      TamResp  : Cardinal;
      Push2    : Byte;
      Resp     : Cardinal;
      Push3    : Byte;
      TamBuf   : Cardinal;
      Push4    : Byte;
      Buffer   : Cardinal;
      Call1    : Byte;
      CallBack : Cardinal;
      Push5    : Byte;
      ExitCode : Cardinal;
      Call2    : Byte;
      ExitThd  : Cardinal;
      Ret      : Byte;
   end;

var
   ExecCallBack: TExecCallBack; // Estrutura do CallBack da Thread
   hProcHand   : Cardinal;      // Handle do processo
   pIpcInfo    : ^TIpcInfo;     // Ponteiro para as informa��es sobre a se��o do IPC
   nMapHandle  : Cardinal;      // Handle do Mapeamento
   pMemRemota  : Pointer;       // Ponteiro para o CALL
   pRemBuffer  : Pointer;       // Ponteiro para o buffer, remoto
   pRespBuffer : Pointer;       // Ponteiro para a resposta do CallBack
   nAux        : Cardinal;      // Vari�vel auxiliar
   nThdId      : Cardinal;      // Variavel auxiliar
begin
   Result := False;

   // Primeiramente abrimos o mapeamento para pegar as informa��es da se��o
   nMapHandle := OpenFileMapping( FILE_MAP_ALL_ACCESS, False, PChar( 'BmsSecaoIPC_' + IdSecao ) );

   // Verifica se a se��o foi realmente criada
   if nMapHandle <> 0 then
   begin
      // Obtemos o ponteiro das informa��es da se��o
      pIpcInfo := MapViewOfFile( nMapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0 );

      hProcHand := OpenProcess( PROCESS_ALL_ACCESS, True, pIpcInfo^.Processo );

      // Alocaremos mem�ria no processo que criou a se��o do IPC
      pMemRemota  := AlocaMem( SizeOf( TExecCallBack ), hProcHand );
      pRemBuffer  := AlocaMem( Tamanho                , hProcHand );

      // Aloca um Buffer para a resposta do CallBack
      pRespBuffer := AlocaMem( TamResposta, hProcHand );

      // Preenchemos a estrutura que ser� executada no contexto
      // do processo que criou a se��o do IPC
      with ExecCallBack do
      begin
         Int3       := $90; // $CC para Debugar
                            // $90 para ignorar o Debug

         Push1      := $68;
         TamResp    := TamResposta;
         Push2      := $68;
         Resp       := Cardinal( pRespBuffer );
         Push3      := $68;
         TamBuf     := Tamanho;
         Push4      := $68;
         Buffer     := Cardinal( pRemBuffer );// p
         Call1      := $E8;
         CallBack   := pIpcInfo^.CallBack - Cardinal( pMemRemota ) - 26;
         Push5      := $68;
         ExitCode   := $00000000;
         Call2      := $E8;
         ExitThd    := Cardinal( GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'ExitThread' ) );
         ExitThd    := ExitThd - Cardinal( pMemRemota ) - 36;
         Ret        := $C3;
      end;

      // Copiamos a estrutura para a mem�ria alocada no outro processo
      if WriteProcessMemory( hProcHand, pMemRemota, @ExecCallBack, SizeOf( TExecCallBack ), nAux ) and
         WriteProcessMemory( hProcHand, pRemBuffer, Buffer, Tamanho, nAux ) then
      begin

         // Ok, mem�ria copiada. Agora criaremos a Thread no outro processo
         nThdId := 0;

         if bWinNT then
            nAux := CreateRemoteThread( hProcHand, nil, 0, pMemRemota, nil, 0, nThdId )
         else
            nAux := BmsCreateRemoteThread9x( pIpcInfo^.Processo, pMemRemota, nil, 0, nThdId );

         if Resposta <> nil then
         begin
            // Caso deva aguardar uma resposta do CallBack, devemos esperar at�
            // que a Thread seja executada at� o fim.
            WaitForSingleObject( nAux, INFINITE );

            // L� a resposta do que o CallBack forneceu
            ReadProcessMemory( hProcHand, pRespBuffer, Resposta, TamResposta, nAux );
         end;

         // Se chegou at� aqui, n�o ocorreram erros.
         Result := True;
      end;
   end;

end;

{****************************************************************************

 BmsCriaSecaoIpc - Inicializa uma se��o de comunica��o

    IdSecao  - Identificador para a se��o
    CallBack - Procedure de CallBack para esta se��o

 **************************************************************************** }

function BmsCriaSecaoIpc( IdSecao: PChar; CallBack: TBmsIpcCallBack ): Boolean;
var
   fMapHandle: Cardinal;  // Handle do Mapeamento
   pIpcInfo  : ^TIpcInfo; // Ponteiro do local alocado
begin
   // Cria o mapeamento inicial necess�rio
   fMapHandle := CreateFileMapping( $FFFFFFFF, nil, PAGE_READWRITE, 0, SizeOf( Pointer ), PChar( 'BmsSecaoIPC_' + IdSecao ) );

   // Obtemos o ponteiro do espa�o alocado
   pIpcInfo := MapViewOfFile( fMapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0 );

   // Agora escrevemos as informa��es do IPC na mem�ria
   pIpcInfo^.CallBack := Cardinal( @CallBack );
   pIpcInfo^.Processo := GetCurrentProcessId;

   // Tudo OK at� aqui. Resultado verdadeiro
   Result := True;
end;

{****************************************************************************

 BmsDestroiSecaoIpc - Termina uma se��o de IPC

    IdSecao  - Identificador da se��o

 **************************************************************************** }

function BmsDestroiSecaoIpc( IdSecao: PChar ): Boolean;
var
   fMapHandle: Cardinal;  // Handle do Mapeamento
begin
   Result := True;

   try
      // Abre o mapeamento inicial necess�rio
      fMapHandle := OpenFileMapping( FILE_MAP_ALL_ACCESS, False, PChar( 'BmsSecaoIPC_' + IdSecao ) );

      // Fecha o mapeamento
      CloseHandle( fMapHandle );
   except
      Result := False;
   end;
end;

end.
