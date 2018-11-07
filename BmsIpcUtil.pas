unit BmsIpcUtil;

interface
uses
   Windows;

{ ****************************************************************************

  BmsIpcUtil - Intercomunicação entre processos
  Autor: Bruno Martins Stuani

 **************************************************************************** }

type
   TBmsIpcCallBack =                  // Formato do CallBack do IPC
      procedure( Buffer: Pointer;     // Ponteiro para os dados que serão passados
                 TamBuffer: Integer;  // Tamanho dos dados passados
                 Resposta: Pointer;   // Caso haja uma resposta, a mesma será passada aqui
                 TamResposta: Integer // Tamanho da resposta
                 ) stdcall;

   function BmsCriaSecaoIpc              // Inicializa uma seção de comunicação
            ( IdSecao: PChar;            // Identificador qualquer que identificará uma seção
              CallBack: TBmsIpcCallBack  // CallBack do IPC
              ): Boolean;

   function BmsDestroiSecaoIpc           // Finaliza uma seção do IPC
            ( IdSecao: PChar             // Identificador que identifica a seção
              ): Boolean;

   function BmsComunicaIpc              // Inicializa uma seção de comunicação
            ( IdSecao        : PChar;   // Identificador da seção
              Buffer         : Pointer; // Ponteiro para o buffer a ser passado como parâmetro
              Tamanho        : Integer; // Tamanho do buffer
              Resposta       : Pointer; // Ponteiro para uma resposta do CallBack
              TamResposta    : Integer  // Tamanho da resposta do CallBack
              ): Boolean;

implementation
uses
   BmsMemUtil;

// Devemos guardar em um espaço compartilhado, as informações do IPC,
// que são o ponteiro do CallBack e o Handle do processo

type
   TIpcInfo = packed record
      CallBack: Cardinal;
      Processo: Cardinal;
   end;

   
{****************************************************************************

 BmsComunicaIpc - Inicializa uma seção de comunicação

    IdSecao     - Identificador da seção
    Buffer      - Ponteiro para o buffer a ser passado como parâmetro
    Tamanho     - Tamanho do buffer
    Resposta    - Ponteiro para onde deverá ser salva a resposta do CallBack
    TamResposta - Tamanho máximo alocado para a resposta

 **************************************************************************** }

function BmsComunicaIpc( IdSecao: PChar; Buffer: Pointer; Tamanho: Integer; Resposta: Pointer; TamResposta: Integer ): Boolean;
type
   // O processo interno do método utilizado pela BmsApiHook é simples,
   // é criada uma Thread no contexto do processo que criou a Seção,
   // e este Thread irá executar as instruções abaixo, que chama o CallBack
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
   pIpcInfo    : ^TIpcInfo;     // Ponteiro para as informações sobre a seção do IPC
   nMapHandle  : Cardinal;      // Handle do Mapeamento
   pMemRemota  : Pointer;       // Ponteiro para o CALL
   pRemBuffer  : Pointer;       // Ponteiro para o buffer, remoto
   pRespBuffer : Pointer;       // Ponteiro para a resposta do CallBack
   nAux        : Cardinal;      // Variável auxiliar
   nThdId      : Cardinal;      // Variavel auxiliar
begin
   Result := False;

   // Primeiramente abrimos o mapeamento para pegar as informações da seção
   nMapHandle := OpenFileMapping( FILE_MAP_ALL_ACCESS, False, PChar( 'BmsSecaoIPC_' + IdSecao ) );

   // Verifica se a seção foi realmente criada
   if nMapHandle <> 0 then
   begin
      // Obtemos o ponteiro das informações da seção
      pIpcInfo := MapViewOfFile( nMapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0 );

      hProcHand := OpenProcess( PROCESS_ALL_ACCESS, True, pIpcInfo^.Processo );

      // Alocaremos memória no processo que criou a seção do IPC
      pMemRemota  := AlocaMem( SizeOf( TExecCallBack ), hProcHand );
      pRemBuffer  := AlocaMem( Tamanho                , hProcHand );

      // Aloca um Buffer para a resposta do CallBack
      pRespBuffer := AlocaMem( TamResposta, hProcHand );

      // Preenchemos a estrutura que será executada no contexto
      // do processo que criou a seção do IPC
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

      // Copiamos a estrutura para a memória alocada no outro processo
      if WriteProcessMemory( hProcHand, pMemRemota, @ExecCallBack, SizeOf( TExecCallBack ), nAux ) and
         WriteProcessMemory( hProcHand, pRemBuffer, Buffer, Tamanho, nAux ) then
      begin

         // Ok, memória copiada. Agora criaremos a Thread no outro processo
         nThdId := 0;

         if bWinNT then
            nAux := CreateRemoteThread( hProcHand, nil, 0, pMemRemota, nil, 0, nThdId )
         else
            nAux := BmsCreateRemoteThread9x( pIpcInfo^.Processo, pMemRemota, nil, 0, nThdId );

         if Resposta <> nil then
         begin
            // Caso deva aguardar uma resposta do CallBack, devemos esperar até
            // que a Thread seja executada até o fim.
            WaitForSingleObject( nAux, INFINITE );

            // Lê a resposta do que o CallBack forneceu
            ReadProcessMemory( hProcHand, pRespBuffer, Resposta, TamResposta, nAux );
         end;

         // Se chegou até aqui, não ocorreram erros.
         Result := True;
      end;
   end;

end;

{****************************************************************************

 BmsCriaSecaoIpc - Inicializa uma seção de comunicação

    IdSecao  - Identificador para a seção
    CallBack - Procedure de CallBack para esta seção

 **************************************************************************** }

function BmsCriaSecaoIpc( IdSecao: PChar; CallBack: TBmsIpcCallBack ): Boolean;
var
   fMapHandle: Cardinal;  // Handle do Mapeamento
   pIpcInfo  : ^TIpcInfo; // Ponteiro do local alocado
begin
   // Cria o mapeamento inicial necessário
   fMapHandle := CreateFileMapping( $FFFFFFFF, nil, PAGE_READWRITE, 0, SizeOf( Pointer ), PChar( 'BmsSecaoIPC_' + IdSecao ) );

   // Obtemos o ponteiro do espaço alocado
   pIpcInfo := MapViewOfFile( fMapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0 );

   // Agora escrevemos as informações do IPC na memória
   pIpcInfo^.CallBack := Cardinal( @CallBack );
   pIpcInfo^.Processo := GetCurrentProcessId;

   // Tudo OK até aqui. Resultado verdadeiro
   Result := True;
end;

{****************************************************************************

 BmsDestroiSecaoIpc - Termina uma seção de IPC

    IdSecao  - Identificador da seção

 **************************************************************************** }

function BmsDestroiSecaoIpc( IdSecao: PChar ): Boolean;
var
   fMapHandle: Cardinal;  // Handle do Mapeamento
begin
   Result := True;

   try
      // Abre o mapeamento inicial necessário
      fMapHandle := OpenFileMapping( FILE_MAP_ALL_ACCESS, False, PChar( 'BmsSecaoIPC_' + IdSecao ) );

      // Fecha o mapeamento
      CloseHandle( fMapHandle );
   except
      Result := False;
   end;
end;

end.
