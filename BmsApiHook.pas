unit BmsApiHook;

interface
uses
   Windows, SysUtils, tlHelp32;

{ ****************************************************************************

  BmsApiHook - Biblioteca para API Hooking
  Autor: Bruno Martins Stuani

 **************************************************************************** }

   function BmsHookApi             // Função que tratará de hookar a API
            ( sModule  : PChar;    // DLL ao qual pertece esta API. Exemplo: "user32.dll"
              sAPI     : PChar;    // API da DLL à hookar. Exemplo: "MessageBoxW" (Caso-sensitivo)
              pCallBack: Pointer;  // Ponteiro para a função do CallBack.
          out pNextProc: Pointer   // Ponteiro para a funçaõ de PróximoHook
              ): Boolean;

   function BmsUnHookApi           // Função que tratará de remover o Hook da API
            ( sModule  : PChar;    // DLL ao qual pertece esta API. Exemplo: "user32.dll"
              sAPI     : PChar;    // API da DLL à hookar. Exemplo: "MessageBoxW" (Caso-sensitivo)
          var pNextProc: Pointer   // Ponteiro para a funçaõ de PróximoHook
              ): Boolean;

   function BmsHookCode            // Função que tratará de hookar o Pointer
            ( pCode    : Pointer;  // Endereço onde será colocado o JMP
              pCallBack: Pointer;  // Ponteiro para a função do CallBack.
          out pNextProc: Pointer   // Ponteiro para a funçaõ de PróximoHook
              ): Boolean;

   function BmsUnHookCode          // Função que tratará de DEShookar o Pointer
            ( pCode    : Pointer;  // Endereço base de onde foi instalado o Hook
          var pNextProc: Pointer   // Ponteiro para a funçaõ de PróximoHook
              ): Boolean;

   function BmsRemoteLoadLibrary             // Função que mapeia uma DLL em um outro processo
            ( hProcessId  : Cardinal;        // Handle do processo alvo
              sDLL        : string           // DLL que será mapeada
              ): Boolean;

   function BmsRemoteUnLoadLibrary       // Função que remove uma DLL de um outro processo
            ( hProcessId : Cardinal;     // Handle do processo alvo
              sDLL       : String        // DLL que será mapeada
              ): Boolean;

   function BmsCreateProcess            // Inicia um novo processo com a DLL já incluída
            ( lpApplicationName       : pchar;
              lpCommandLine           : pchar;
              lpProcessAttributes,
              lpThreadAttributes      : PSecurityAttributes;
              bInheritHandles         : boolean;
              dwCreationFlags         : longword;
              lpEnvironment           : pointer;
              lpCurrentDirectory      : pchar;
              const lpStartupInfo     : TStartupInfo;
              var lpProcessInformation: TProcessInformation;
              sDLL                    : string
              ): Boolean;

   function BmsGetProcessID    // Retorna o ID de um determinado processo
            ( Exename: string  // Processo (exemplo: firefox.exe)
              ): Cardinal;

   const
      // Flag utilizada no lugar do ID do Processo, quando for Injetar/Desinjetar uma DLL
      TODOS_PROCESSOS = $FFFFFFFF;

implementation
uses
   BmsMemUtil, BmsAsmUtil;

var
   aFirstBytes          : array [1..15] of Byte; // Primeiros bytes da função original
   fMapHandle           : Cardinal;              // Handle do Mapeamento SystemWide
   pHooksEmUsoCnt       : PInteger;              // Variavel que mantém uma contagem dos Callbacks que estão em uso
   pLoadLibraryExW      : Pointer;               // Ponteiro para a LoadLibrary
   pLoadLibraryA        : Pointer;               // Ponteiro para a LoadLibrary
   pFreeLibrary         : Pointer;               // Ponteiro para a FreeLibrary
   pGetModuleHandleA    : Pointer;               // Ponteiro para a GetModuleHandle
   pInterlockedDecrement: Pointer;               // Ponteiro para a InterlockedDecrement
   pInterlockedIncrement: Pointer;               // Ponteiro para a InterlockedIncrement
   pSleep               : Pointer;               // Ponteiro para a Sleep
   pGetCurrentProcessID : Pointer;               // Ponteiro para a GetCurrentProcessID

   aListaHooks: array of record                  // Lista de funções Hookadas para Deshooká-las automaticamente
                   sDLL: string;
                   sAPI: string;
                   pEndereco: Pointer;
                   pNextProc: Pointer;
                end;

   // Hooks globais. São utilizados somente quando a BmsRemoteLoadLibrary
   // é chamada com a flag TODOS_PROCESSOS
   CreateProcessA_np: function( lpApplicationName: PAnsiChar; lpCommandLine: PAnsiChar; lpProcessAttributes, lpThreadAttributes: PSecurityAttributes; bInheritHandles: BOOL; dwCreationFlags: DWORD; lpEnvironment: Pointer; lpCurrentDirectory: PAnsiChar; const lpStartupInfo: TStartupInfo; var lpProcessInformation: TProcessInformation): BOOL; stdcall;
   CreateProcessW_np: function( lpApplicationName: PWideChar; lpCommandLine: PWideChar; lpProcessAttributes, lpThreadAttributes: PSecurityAttributes; bInheritHandles: BOOL; dwCreationFlags: DWORD; lpEnvironment: Pointer; lpCurrentDirectory: PWideChar; const lpStartupInfo: TStartupInfo; var lpProcessInformation: TProcessInformation): BOOL; stdcall;

   // Hook da LoadLibraryExW. Utilizado para renovar os Hooks assim que a DLL for recarregada
   bHookedLoadLib   : Boolean = False;
   LoadLibraryA_np  : function( lpLibFileName: PAnsiChar): HMODULE; stdcall;
   FreeLibrary_np   : function( hLibModule: HMODULE ): BOOL; stdcall;

{****************************************************************************

 BmsGetProcessID - Retorna o ID de um determinado processo

    ExeName  - Nome do executável para retornar o ID

 **************************************************************************** }

function BmsGetProcessID( ExeName: string ): Cardinal;
var
   ProcEntry32: TProcessEntry32; // Estrutura de processos
   hProcSnap  : THandle;         // Handle do SnapShot
begin
   // Inicia o resultado como 0
   Result := 0;

   // Cria o SnapShot dos processos
   hProcSnap := CreateToolHelp32SnapShot( TH32CS_SNAPPROCESS, 0 );

   // Caso tenha criado com sucesso
   if hProcSnap <> INVALID_HANDLE_VALUE then
   begin

      // Informa o Sistema Operacional, qual versão da API utilizar
      ProcEntry32.dwSize := SizeOf(ProcessEntry32);

      // Inicia a enumeração dos processos
      if Process32First(hProcSnap, ProcEntry32) then

         repeat
            // Repete a verificação abaixo até que finalize a enumeração
            if pos( LowerCase( Exename ), LowerCase( ProcEntry32.szExeFile ) ) <> 0 then
               // Verifica se existe [ExeName] dentro do executável atual
               result := ProcEntry32.th32ProcessID;

         until not Process32Next(hProcSnap, ProcEntry32);

      // Fecha o Handle   
      CloseHandle(hProcSnap);
   end;
end;

{****************************************************************************

 getBytesInstComp - Retorna a quantidade de bytes em função de instruções
                    completas, em um montante cuja capacidade seja >=
                    o tamanho de um JMP de 6 bytes

    pEndereco - Endereço de onde deve se verificar os bytes

 **************************************************************************** }

function getBytesInstComp( pEndereco: Pointer ): Integer;
begin
   Result := 0;

   // Enquanto não varrer os primeiros bytes completos
   // que possam caber em um espaço igual ao espaço ocupado
   // por um TJmpCode
   while Result < SizeOf( TJmpCode ) do

      // Incrementa no resultado o tamanho da instrução correspondente
      // ao ponteiro atual
      Inc( Result, InstructionSize( Pointer( Cardinal( pEndereco ) + Cardinal( Result ) ) ) );
end;

{****************************************************************************

 TransfereFuncao - Transfere uma parte de código de um local para o outro
                   fazendo todas as realocações se necessário, possibilitando
                   assim a execução do código no novo local

    pBuffer  - Endereço do buffer à copiar
    pOrigem  - Origem original do buffer (usado para recalcular os JMPs/CALLs
    pDestino - Destino do bloco (para onde deve copiar)
    nTamanho - Quantidade de bytes à copiar

 **************************************************************************** }

function TransfereFuncao( pBuffer: Pointer; pOrigem: Pointer; pDestino: Pointer; nTamanho: Cardinal ): Boolean;
var
   pAtual        : Pointer; // Ponteiro para o local atual da pesquisa
   pEnderecoMudar: Pointer; // Armazena o local onde deve haver o Patch
   nNovoEndereco : Cardinal;
   nProcHandle   : Cardinal;
   nEscrito      : Cardinal;
begin
   Result := False;

   // Abre o processo para escrita/leitura
   nProcHandle := GetCurrentProcess;

   // Se não abriu, então sai
   if nProcHandle = 0 then
      Exit;

   try
      // Verifica se os parametros foram passados corretamente
      if ( pBuffer = nil ) or ( pDestino = nil ) or ( nTamanho = 0 ) then
         Exit;

      // Copia a função de um lugar para o outro
      if not WriteProcessMemory( nProcHandle, pDestino, pBuffer, nTamanho, nEscrito ) then
         Exit;

      // Atribui pAtual como o pDestino
      pAtual := pDestino;

      // Varre até que chegue a [nTamanho] bytes lidos
      while Cardinal( pAtual ) - Cardinal( pDestino ) <= nTamanho do
      begin
         pEnderecoMudar := nil;

         // Se encontrar um prefixo de segmento de JMP
         // incrementa um em pAtual.
         if PByte( pAtual )^ = $64 then
            Inc( Integer( pAtual ), 1 );

         case PByte( pAtual )^ of
            $0F: // JMP condicional e relativo, prefixo de 2 bytes
                 // Quando começa por $0F, é seguido de um outro identificador
                 // que vai de $80 à $8F (que são as condições)
               if PByte( Pointer( Cardinal( pAtual ) + 1 ) )^ in [ $80..$8F ] then
                  pEnderecoMudar := Pointer( Cardinal( pAtual ) + 2 );

            $E9, // JMP não condicional e relativo, prefixo de 1 byte
            $E8: // CALL relativo. Prefixo de 1 byte
               pEnderecoMudar := Pointer( Cardinal( pAtual ) + 1 );
         end;

         // Verifica se encontrou algum CALL ou JMP relativo
         // que deva ser alterado
         if pEnderecoMudar <> nil then
         begin
            // A distancia que está depois do prefixo deve ser o que tinha antes +
            // a diferença do entry point da função Nova e da Antiga

            nNovoEndereco := PCardinal( pEnderecoMudar )^ + Cardinal( pOrigem ) - Cardinal( pDestino );

            if not WriteProcessMemory( nProcHandle, pEnderecoMudar, @nNovoEndereco, SizeOf( Cardinal ), nEscrito ) then
               Exit;
         end;

         // Incrementa pATUAL com a quantidade de uma instrução completas
         Inc( Integer( pAtual ), InstructionSize( pAtual ) );
      end;
                                  
      Result := True;
   finally
      CloseHandle( nProcHandle );
   end;
end;

{ ****************************************************************************

 _BmsRemoteLoadLibrary - Carrega/Descarrega uma DLL no contexto de outro
                         processo

    hProcessID    - ID do processo remoto
    sDLL          - DLL que será carregada
    bCarrega      - Caso verdadeiro a DLL é carregada, caso contrário ela é
                    descarregada
    bNovoProcesso - Informa se a instalação da DLL está sendo feito em um novo
                    processo. Pois caso esteja, o tratamento dos comandos
                    a serem executados devem ser diferentes.

 **************************************************************************** }

function _BmsRemoteLoadLibrary( hProcessId: Cardinal; sDLL: string; bCarrega: Boolean; bNovoProcesso: Boolean; bAguardaThread: Boolean ): Boolean;

type
   TThdInfo = packed record
      ThdHandle: Cardinal;           // Handle da Thread
      ThdID    : Cardinal;           // ID da Thread
   end;

   TSleepInfinito = packed record
      nPUSH     : Byte;              // Dá um PUSH em INFINITE
      nInfinite : Cardinal;          // $FFFFFFFF
      nCALL     : Byte;              // Chama a API Sleep
      nDistSleep: Cardinal;          // [distancia da API]
   end;

   TLoadLibraryStruct = packed record
      nPUSH  : Byte;                 // Dá um PUSH na string da DLL
      pEndDLL: Cardinal;             // [endereço da DLL]
      nCALL  : Byte;                 // Chama a API LoadLibrary
      nDistLL: Cardinal;             // [distancia da API]
      nParaEx: array [0..1] of Byte; // Loop infinito
   end;

   TUnLoadLibraryStruct = packed record
      nPUSH_DLL: Byte;               // Dá um PUSH na string da DLL
      pEnd_DLL : Cardinal;           // [endereço da DLL]
      nCALL_GMH: Byte;               // Chama a API GetModuleHandle
      nDist_GMH: Cardinal;           // [distancia da API]
      nPush_EAX: Byte;               // Da um PUSH no Handle da DLL
      nCALL_FL : Byte;               // Chama a API FreeLibrary
      nDIST_FL : Cardinal;           // [distancia da API]
      nParaEx: array [0..1] of Byte; // JMP SHORT -2 (fica num loop infinito)
   end;

var
   hProcess  : Cardinal;             // Handle do processo
   hThHandle : Cardinal;             // Handle da thread principal do processo
   hThID     : Cardinal;             // ID da thread principal do processo
   AsmCarrega: TLoadLibraryStruct;   // Estrutura do código que deve ser executado
   AsmDescarr: TUnLoadLibraryStruct; // Estrutura do código que deve ser executado
   nBytes    : Cardinal;             // Auxiliar para a API WriteProcessMemory
   pCodEntry : Pointer;              // Ponto de entrada da nova procedure
   nLoadLib  : Cardinal;             // Endereço da API LoadLibrary
   pEndDLL   : Cardinal;             // Ponteiro do endereço da DLL no outro processo
   nTamAcao  : Integer;              // Tamanho da LoadLibrary ou da rotina FreeLibrary
   pUsarStruc: Pointer;              // Depende da ação, este recebe tanto a estrutura Load como a UnLoad
   nThResulta: Cardinal;             // Resultado da Thread, no caso do WinNT
   siDorme   : TSleepInfinito;       // Ajuda a não finalizar a thread
begin
   Result := False;

   // Se não passou o ID do processo ou a DLL então sai
   if ( hProcessId = 0 ) or ( sDLL = '' ) then
      Exit;

   // Retorna o Handle do processo
   hProcess := OpenProcess( PROCESS_ALL_ACCESS, True, hProcessId );

   // Alocamos espaço no outro processo para o armazenamento da string da DLL
   pEndDLL := Cardinal( AlocaMem( Length( sDLL ), hProcess ) );

   AsmCarrega.pEndDLL  := pEndDLL;
   AsmDescarr.pEnd_DLL := pEndDLL;

   if pEndDLL <> 0 then
   begin

      // Copiamos o nome da DLL para o processo
      if not bWinNT then
         CopyMemory( Pointer( pEndDLL ), @sDLL[1], Length( sDLL ) )
      else if not WriteProcessMemory( hProcess, Pointer( pEndDLL ), @sDLL[1], Length( sDLL ), nBytes ) then
         Exit;

      AsmCarrega.nPUSH     := $68; // PUSH
      AsmCarrega.nCALL     := $E8; // CALL
      AsmDescarr.nPUSH_DLL := $68; // PUSH
      AsmDescarr.nCALL_GMH := $E8; // CALL
      AsmDescarr.nCALL_FL  := $E8; // CALL
      AsmDescarr.nPush_EAX := $50; // PUSH EAX

      // Alocamos memória para a rotina LoadLibrary
      if bCarrega then
         pCodEntry := AlocaMem( SizeOf( AsmCarrega ) + SizeOf( siDorme ), hProcess )
      else
         pCodEntry := AlocaMem( SizeOf( AsmDescarr ), hProcess );

      // Se não alocou então sai
      if pCodEntry <> nil then
      begin

         if bCarrega then
         begin
            // Calculamos um CALL Relativo
            nLoadLib := Cardinal( pLoadLibraryA );
            AsmCarrega.nDistLL := nLoadLib - Cardinal( pCodEntry ) - SizeOf( Cardinal ) - 6;

            pUsarStruc := @AsmCarrega;
            nTamAcao   := SizeOf( AsmCarrega )
         end
         else
         begin
            // Calculamos um CALL Relativo
            nLoadLib := Cardinal( pFreeLibrary );
            AsmDescarr.nDIST_FL := nLoadLib - Cardinal( pCodEntry ) - SizeOf( Cardinal ) - 12;

            nLoadLib := Cardinal( pGetModuleHandleA );
            AsmDescarr.nDist_GMH := nLoadLib - Cardinal( pCodEntry ) - SizeOf( Cardinal ) - 6;

            pUsarStruc := @AsmDescarr;
            nTamAcao   := SizeOf( AsmDescarr )
         end;

         // Agora copiamos o conteúdo da nova rotina para o outro processo

         if not bNovoProcesso then
         begin
            // Se estamos no WinNT, o código final será um {RET 4}
            // para indicar que finalizou a execução da Thread

            AsmCarrega.nParaEx[0] := $C2; // RET
            AsmCarrega.nParaEx[1] := $04; // 4

            AsmDescarr.nParaEx[0] := $C2;
            AsmDescarr.nParaEx[1] := $04;
         end
         else
         begin
            // Caso contrário iremos inutilizar os 2 ultimos bytes

            AsmCarrega.nParaEx[0] := $90; // NOP
            AsmCarrega.nParaEx[1] := $90;
         end;

         // Finalmente escreve o conteúdo da Load ou UnLoad no outro processo
         if not WriteProcessMemory( hProcess, pCodEntry, pUsarStruc, nTamAcao, nBytes ) then
            Exit;

         if bNovoProcesso then
         begin
            // Se estivermos instalando em um processo criado pela BmsCreateProcess
            // ou pelo Hook de instalação no Sistema Operacional, a Thread
            // que criaremos para instalar a DLL passará a ser a principal,
            // logo, não poderá ser finalizada. Faremos com que ela execute
            // um SLEEP infinito, fazendo com que a Thread durma para semrpe ;-)

            nLoadLib := Cardinal( pSleep );

            siDorme.nPUSH      := $68;
            siDorme.nInfinite  := INFINITE;
            siDorme.nCALL      := $E8;
            siDorme.nDistSleep := nLoadLib - Cardinal( pCodEntry ) - SizeOf( Cardinal ) - 18;

            // Escreve o comando do Sleep no contexto do novo processo
            if not WriteProcessMemory( hProcess, Pointer( Cardinal( pCodEntry ) + SizeOf( AsmCarrega ) ), @siDorme, SizeOf( siDorme ), nBytes ) then
               Exit;
         end;

         if not bWinNT then
            hThHandle := BmsCreateRemoteThread9x( hProcessId, pCodEntry, nil, 0, hThID )
         else
            hThHandle := CreateRemoteThread( hProcess, nil, 0, pCodEntry, nil, 0, hThID );

         // Se estamos instalando a DLL em um processo já ativo, iremos esperar
         // a finalização da nova Thread. Caso contrário, a thread irá executar
         // aquele SLEEP infinito, então não devemos aguardar a finalização
         // da mesma.

         if not bNovoProcesso then
         begin
            // Aguarda até a finalização da execução da mesma
            if bAguardaThread then
            begin
               WaitForSingleObject( hThHandle, 5000{Infinite} );

               // Se não ocorreram erros, retorna Verdadeiro
               Result := GetExitCodeThread( hThHandle, nThResulta );
            end
            else
               Result := True;

            // Fecha o Handle da Thread
            CloseHandle( hThHandle );
         end
         else
            Result := True;
      end;
   end;
end;

{ ****************************************************************************

 FreeLibrary_cb - Este é um CallBack para a API FreeLibrary.
                  Ela vai encarregar de remover o Hook antes que a DLL seja
                  realmente liberada da memória. Evitando qualquer problema de
                  memória por parte da seção de Descarrego da DLL

 **************************************************************************** }

function FreeLibrary_cb(hLibModule: HMODULE): BOOL; stdcall;
var
   nAux: Integer;
begin
   // Pesquisa pelas APIs hookadas, para saber se alguma delas faz parte da biblioteca
   for nAux := 0 to Length( aListaHooks ) - 1 do
   begin
      with aListaHooks[ nAux ] do
      begin
         // Verifica se o nome da DLL bate com a DLL passada como parâmetro
         if GetModuleHandle( PChar( sDLL ) ) = hLibModule then
            // Se sim, então remove o Hook!
            BmsUnHookCode( GetProcAddress( hLibModule, PChar( sAPI ) ), pNextProc );
      end;
   end;

   // Chama a API original
   Result := FreeLibrary_np( hLibModule );
end;

{ ****************************************************************************

 LoadLibraryExW_cb - Este é um CallBack para a API LoadLibraryExW.
                     Ela vai encarregar de renovar o Hook caso a biblioteca seja
                     Descarregada e recarregada logo em seguida.

 **************************************************************************** }

function LoadLibraryA_cb(lpLibFileName: PAnsiChar): HMODULE; stdcall;
var
   nAux: Integer;
   bTinha: Boolean;
begin
//   bTinha := GetModuleHandle( lpLibFileName ) <> 0;

   // Chama a API original
   Result := LoadLibraryA_np( lpLibFileName );

   if {( not bTinha ) and }( Result <> 0 ) then
      // E pesquisa pelas APIs hookadas, para saber se alguma delas faz parte da biblioteca carregada
      for nAux := 0 to Length( aListaHooks ) - 1 do
      begin
         with aListaHooks[ nAux ] do
         begin
            // Verifica se o nome da DLL bate com a DLL passada como parâmetro
            if Pos( LowerCase( sDLL ), LowerCase( lpLibFileName ) ) <> 0 then
               // Se sim, então instala o Hook!
               BmsHookCode( GetProcAddress( Result, PChar( sAPI ) ), pEndereco, pNextProc );
         end;
      end;
end;

{ ****************************************************************************

 CreateProcessA_cb - Este é um CallBack para a API CreateProcessA.
                     Este CallBack entra em ação quando a API CreateProcess
                     é chamada. O trabalho dela é instalar o Hook como se
                     estivesse chamando a BmsCreateProcess, com a DLL passada
                     como parâmetro

 **************************************************************************** }

type
   TCaminhoDLL = string[ 255 ];

function CreateProcessA_cb(lpApplicationName: PAnsiChar; lpCommandLine: PAnsiChar; lpProcessAttributes, lpThreadAttributes: PSecurityAttributes; bInheritHandles: BOOL; dwCreationFlags: DWORD; lpEnvironment: Pointer; lpCurrentDirectory: PAnsiChar; const lpStartupInfo: TStartupInfo; var lpProcessInformation: TProcessInformation): BOOL; stdcall;
var
   fMapHand : Cardinal;
   pLocalDLL: ^TCaminhoDLL;
   fFlag    : Cardinal;
begin
   // Abre o mapeamento da BmsApiHook
   fMapHand := OpenFileMapping( FILE_MAP_ALL_ACCESS, False, 'BmsApiHook_HookGlobal1' );

   // Pega o endereço do local da DLL, conforme o mapeamento feito pelo executável
   pLocalDLL := MapViewOfFile( fMapHand, FILE_MAP_ALL_ACCESS, 0, 0, 0 );

   fFlag := dwCreationFlags;

   if ( fMapHand <> 0 ) and ( pLocalDLL <> nil ) then
      fFlag := dwCreationFlags or CREATE_SUSPENDED;

   // Chama a API original, adicionando a flag CREATE_SUSPENDED para que possamos
   // instalar a DLL antes da execução da Thread principal
   Result := CreateProcessA_np( lpApplicationName, lpCommandLine, lpProcessAttributes,
                                lpThreadAttributes, bInheritHandles, fFlag, lpEnvironment,
                                lpCurrentDirectory, lpStartupInfo, lpProcessInformation );

   if ( fMapHand <> 0 ) and ( pLocalDLL <> nil ) then
   begin
      if ( pLocalDLL^ <> 'aguarda' ) then
         // Instala a DLL no contexto do novo processo
         _BmsRemoteLoadLibrary( lpProcessInformation.dwProcessId, pLocalDLL^, True, True, True );

      // Reinicia a exeucução da Thread
      ResumeThread( lpProcessInformation.hThread );

      // Remove o mapeamento
      UnmapViewOfFile( pLocalDLL );

      // e finalmente fecha o Handle
      CloseHandle( fMapHand );
   end;
end;

{ ****************************************************************************

 CreateProcessW_cb - Este é um CallBack para a API CreateProcessW.
                     Este CallBack entra em ação quando a API CreateProcess
                     é chamada. O trabalho dela é instalar o Hook como se
                     estivesse chamando a BmsCreateProcess, com a DLL passada
                     como parâmetro

 **************************************************************************** }

function CreateProcessW_cb(lpApplicationName: PWideChar; lpCommandLine: PWideChar; lpProcessAttributes, lpThreadAttributes: PSecurityAttributes; bInheritHandles: BOOL; dwCreationFlags: DWORD; lpEnvironment: Pointer; lpCurrentDirectory: PWideChar; const lpStartupInfo: TStartupInfo; var lpProcessInformation: TProcessInformation): BOOL; stdcall;
var
   fMapHand : Cardinal;
   pLocalDLL: ^TCaminhoDLL;
   fFlag    : Cardinal;
begin
   // Abre o mapeamento da BmsApiHook
   fMapHand := OpenFileMapping( FILE_MAP_ALL_ACCESS, False, 'BmsApiHook_HookGlobal1' );

   // Pega o endereço do local da DLL, conforme o mapeamento feito pelo executável
   pLocalDLL := MapViewOfFile( fMapHand, FILE_MAP_ALL_ACCESS, 0, 0, 0 );

   fFlag := dwCreationFlags;

   if ( fMapHand <> 0 ) and ( pLocalDLL <> nil ) then
      fFlag := dwCreationFlags or CREATE_SUSPENDED;

   // Chama a API original, adicionando a flag CREATE_SUSPENDED para que possamos
   // instalar a DLL antes da execução da Thread principal
   Result := CreateProcessW_np( lpApplicationName, lpCommandLine, lpProcessAttributes,
                                lpThreadAttributes, bInheritHandles, fFlag, lpEnvironment,
                                lpCurrentDirectory, lpStartupInfo, lpProcessInformation );

   if ( fMapHand <> 0 ) and ( pLocalDLL <> nil ) then
   begin
      if pLocalDLL^ <> 'aguarda' then
         // Instala a DLL no contexto do novo processo
         _BmsRemoteLoadLibrary( lpProcessInformation.dwProcessId, pLocalDLL^, True, True, True );

      // Reinicia a exeucução da Thread
      ResumeThread( lpProcessInformation.hThread );

      // Remove o mapeamento
      UnmapViewOfFile( pLocalDLL );

      // e finalmente fecha o Handle
      CloseHandle( fMapHand );
   end;
end;

{ ****************************************************************************

 BmsRemoteLoadLibrary - Carrega uma DLL em um outro processo

    hProcessID - ID do processo remoto
    sDLL       - DLL que será carregada

    Caso a flag TODOS_PROCESSOS seja utilizada no primeiro parâmetro,
    a DLL será carregada do contexto de todos os processos abertos e
    em todos os processos que virão a abrir

 **************************************************************************** }

function BmsRemoteLoadLibrary( hProcessId: Cardinal; sDLL: string ): Boolean;
var
   ProcEntry32: TProcessEntry32;  // Record de informações do processo
   hProcSnap  : THandle;          // Handle do SnapShot
   pFileMap   : ^TCaminhoDll;     // Ponteiro do mapeamento da DLL
begin
   if hProcessId <> TODOS_PROCESSOS then
      // Se a ordem foi desinstalar em apenas um processo, que assim seja ;)
      Result := _BmsRemoteLoadLibrary( hProcessId, sDLL, True, False, True )
   else
   begin
      // Caso contrário vamos instalar em todos os processos abertos
      Result := True;

      // Primeiramente vamos setar uma Flag para indicar a DLL que devemos
      // instalar um hook na API CreateProcess, de dentro das DLLs
      fMapHandle := CreateFileMapping( $FFFFFFFF, nil, PAGE_READWRITE, 0, Length( sDLL ) + 1, 'BmsApiHook_HookGlobal1' );

      // Obtemos o ponteiro do espaço alocado
      pFileMap := MapViewOfFile( fMapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0 );

      // Escrevemos o nome da DLL dentro desse espaço
      pFileMap^ := sDLL;

      // Cria o SnapShot dos processos
      hProcSnap := CreateToolHelp32SnapShot( TH32CS_SNAPPROCESS, 0 );

      // Caso tenha criado com sucesso
      if hProcSnap <> INVALID_HANDLE_VALUE then
      begin

         // Informa o sistema operacional, a versão da ProcessEntry32
         // a ser utilizada
         ProcEntry32.dwSize := SizeOf(ProcessEntry32);

         // Dá o passo inicial na busca entre os processos
         if Process32First(hProcSnap, ProcEntry32) then
         begin
            repeat

               // Instala a DLL no contexto do processo encontrado
               _BmsRemoteLoadLibrary( ProcEntry32.th32ProcessID, sDLL, True, False, False );

            // até que não encontre mais processos
            until not Process32Next( hProcSnap, ProcEntry32 );

            // finalmente fecha o handle
            CloseHandle(hProcSnap);
         end;
      end;
   end;
end;

{ ****************************************************************************

 BmsRemoteUnLoadLibrary - Descarrega uma DLL de um outro processo

    hProcessID - ID do processo remoto
    sDLL       - DLL que será descarregada

    Caso a flag TODOS_PROCESSOS seja utilizada no primeiro parâmetro,
    a DLL será descarregada do contexto de todos os processos abertos.

    A função já prevê se a DLL poderá ou não ser descarregada de todos
    os processos. Caso o processo X não esteja em condições para descarregar,
    a função retorna False e a DLL não será descarregada de nenhum processo. 

 **************************************************************************** }

function BmsRemoteUnLoadLibrary( hProcessId: Cardinal; sDLL: string ): Boolean;
var
   ProcEntry32: TProcessEntry32;   // Record de informações do processo
   hProcSnap  : THandle;           // Handle do SnapShot
   hProcIDs   : array of Cardinal; // Array dos IDs que serão removidos
   nAux       : Integer;           // Variável de controle
   pLocalDLL  : ^TCaminhoDLL;      // Ponteiro para o caminho global da DLL
   fMapHand   : Cardinal;          // handle do mapeamento
begin

   if hProcessId <> TODOS_PROCESSOS then
      // Se a ordem foi desinstalar em apenas um processo, que assim seja ;)
      Result := _BmsRemoteLoadLibrary( hProcessId, sDLL, False, False, True )
   else
   begin
      // Verifica se pode remover as DLLs de todo o sistema, com sucesso
      if pHooksEmUsoCnt^ <> 0 then
      begin
         Result := False;
         Exit;
      end;

      // Caso contrário vamos instalar em todos os processos abertos
      Result := True;

      // Cria o SnapShot dos processos
      hProcSnap := CreateToolHelp32SnapShot( TH32CS_SNAPPROCESS, 0 );

      // Caso tenha criado com sucesso
      if hProcSnap <> INVALID_HANDLE_VALUE then
      begin

         // Abre o mapeamento da BmsApiHook
         fMapHand := OpenFileMapping( FILE_MAP_ALL_ACCESS, False, 'BmsApiHook_HookGlobal1' );

         // Pega o endereço do local da DLL, conforme o mapeamento feito pelo executável
         pLocalDLL := MapViewOfFile( fMapHand, FILE_MAP_ALL_ACCESS, 0, 0, 0 );

         // Aqui devemos inutilizar o Hook do CreateProcess das DLLs, para
         // que não tenhamos problemas ao desinstalar as DLLs.
         pLocalDLL^ := 'aguarda';

         // Informa o sistema operacional, a versão da ProcessEntry32
         // a ser utilizada
         ProcEntry32.dwSize := SizeOf(ProcessEntry32);

         // Dá o passo inicial na busca entre os processos
         if Process32First( hProcSnap, ProcEntry32 ) then
         begin

            repeat

               // Adiciona o ID à matriz
               SetLength( hProcIds, Length( hProcIds ) + 1 );
               hProcIDs[ Length( hProcIds ) - 1 ] := ProcEntry32.th32ProcessID;

            // até que não encontre mais processos
            until not Process32Next(hProcSnap, ProcEntry32);

            // finalmente fecha o handle
            CloseHandle(hProcSnap);
         end;

         for nAux := 0 to Length( hProcIds ) - 1 do
             _BmsRemoteLoadLibrary( hProcIds[ nAux ], sDLL, False, False, False );

      end;
   end;
end;

{ ****************************************************************************

 BmsCreateProcess - Cria um novo processo com uma DLL já carregada

    sDLL - Path da DLL

 **************************************************************************** }

function _BmsCreateProcess( lpApplicationName: pchar; lpCommandLine: pchar; lpProcessAttributes, lpThreadAttributes: PSecurityAttributes; bInheritHandles: boolean; dwCreationFlags: longword; lpEnvironment: pointer; lpCurrentDirectory: pchar; const lpStartupInfo: TStartupInfo; var lpProcessInformation: TProcessInformation; sDLL: string ): boolean;
begin
   // Inicia o resultado como falso
   Result := False;

   // Cria o novo processo com a flag CREATE_SUSPENDED para que possamos
   // instalar o Hook antes mesmo da execução da Thread principal
   if CreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags or CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) then
   begin
      // Instala a DLL no contexto do novo processo
      Result := _BmsRemoteLoadLibrary( lpProcessInformation.dwProcessId, sDLL, True, True, True );

      // Continua a execução da thread principal do outro processo
      ResumeThread( lpProcessInformation.hThread );
   end;
end;

{ ****************************************************************************

 BmsCreateProcess - Cria um novo processo com uma DLL já carregada

    sDLL - Path da DLL
  _____
 |Idéa |___________________________________________________________________
 |                                                                         |
 | Salvar os 5 primeiros bytes do EntryPoint, Colocar um JMP no EntryPoint |
 | que aponta para a NovaProcedure. A NovaProcedure executa um LoadLibrary |
 | e em seguida copia os 5 bytes devolta para o EntryPoint e faz um JMP    |
 | para o EntryPoint. Easy ;)                                              |
 |_________________________________________________________________________|

 **************************************************************************** }

function BmsCreateProcess( lpApplicationName: pchar; lpCommandLine: pchar; lpProcessAttributes, lpThreadAttributes: PSecurityAttributes; bInheritHandles: boolean; dwCreationFlags: longword; lpEnvironment: pointer; lpCurrentDirectory: pchar; const lpStartupInfo: TStartupInfo; var lpProcessInformation: TProcessInformation; sDLL: string ): boolean;
type
   // Estrutura para carregar a DLL
   TLoadLibraryStruct = packed record
      nPushDLL : Byte;
      nLocalDLL: Cardinal;
      nCallLL  : Byte;
      nDistLL  : Cardinal;
      nJmpEP   : Byte;
      nDistEP  : Cardinal;
   end;

var
   pDll     : Pointer;             // Endereço da DLL no outro processo
   llStruct : TLoadLibraryStruct;  // Estrutura do LoadLibrary
   pLlStruct: Pointer;             // Local da estrutura no outro processo
   ThdContex: CONTEXT;             // Contexto da thread
   nAux     : Cardinal;            // Variável auxiliar

   function getEntryPoint(exename: pchar): pointer; stdcall;
   var
      handlef: cardinal;
      IDH    : TImageDosHeader;
      INH    : TImageNtHeaders;
      read   : cardinal;
   begin
      result  := nil;
      handlef := CreateFileA( exename, GENERIC_READ, 0, nil, OPEN_EXISTING, 0, 0 );
   
      if handlef > 0 then
      begin
         SetFilePointer( handlef, 0, nil, FILE_BEGIN );
   
         if ReadFile( handlef, IDH, sizeof( IDH ), read, nil) and
            ( read = sizeof( IDH ) ) and ( IDH.e_magic = IMAGE_DOS_SIGNATURE ) then
         begin
            SetFilePointer( handlef, IDH._lfanew, nil, FILE_BEGIN );
   
            if ReadFile( handlef, INH, sizeof( INH ), read, nil ) and
               ( read = sizeof( INH ) ) and ( INH.Signature = IMAGE_NT_SIGNATURE ) then
            begin
               result := pointer(INH.OptionalHeader.AddressOfEntryPoint+INH.OptionalHeader.ImageBase);
            end;
         end;
   
         CloseHandle(handlef);
      end;
   end;

begin
   // Inicia o resultado como falso
   Result := False;

   // Cria o novo processo com a flag CREATE_SUSPENDED para que possamos
   // instalar o Hook antes mesmo da execução da Thread principal
   if CreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags or CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) then
   begin
      // Pega o contexto da Thread
      ThdContex.ContextFlags := CONTEXT_CONTROL or CONTEXT_INTEGER;

      GetThreadContext( lpProcessInformation.hThread, thdContex );

      // Aloca memória para a DLL
      pDll := AlocaMem( Length( sDLL ) + 1, lpProcessInformation.hProcess );

      // Copia a string da DLL para o outro processo
      WriteProcessMemory( lpProcessInformation.hProcess, pDll, PChar( sDLL ), Length( sDLL ), nAux );

      // Aloca memória para a procedure que carrega a DLL
      pllStruct := AlocaMem( SizeOf( TLoadLibraryStruct ), lpProcessInformation.hProcess );

      // Preenche a estrutura
      llStruct.nPushDLL  := $68;
      llStruct.nLocalDLL := Cardinal( pDll );
      llStruct.nCallLL   := $E8;
      llStruct.nDistLL   := Cardinal( pLoadLibraryA );
      llStruct.nDistLL   := llStruct.nDistLL - Cardinal( pLlStruct ) - 10;
      llStruct.nJmpEP    := $E9;

      if bWinNT then
      begin
         if lpApplicationName <> nil then
            llStruct.nDistEP := Cardinal( GetEntryPoint( lpApplicationName ) ) - Cardinal( pLlStruct ) - 15
         else
            llStruct.nDistEP := Cardinal( GetEntryPoint( lpCommandLine ) ) - Cardinal( pLlStruct ) - 15;
      end
      else
         llStruct.nDistEP := ThdContex.Eip - Cardinal( pLlStruct ) - 15;

      // Copia a estrutura da nova procedure para o outro processo
      WriteProcessMemory( lpProcessInformation.hProcess, pllStruct, @llStruct, SizeOf( TLoadLibraryStruct ), nAux );

      ThdContex.Eip := Cardinal( pLlStruct );
      SetThreadContext( lpProcessInformation.hThread, thdContex );

      // Continua a execução da thread principal do outro processo
      // para carregar a DLL antes de entrar no EntryPoint
      ResumeThread( lpProcessInformation.hThread );

      Result := True;
   end;
end;

{****************************************************************************

 ReGuiarThreads - Verifica as threads do processo pra saber se elas
                  não estavam executando a função que recebeu o Hook.
                  Caso estavam, reguia a mesma para a NextFunc.

    nRangeInicial \ A função vai verificar se a thread está entre o
    nRangeFinal   / nRangeInicial e o nRangeFinal
    pNextFunc     - Ponteiro para a NextFunc

 **************************************************************************** }

var
   nThreadHandles: array of Cardinal;

procedure ReGuiarThreads( nRangeInicial: Cardinal = 0; nRangeFinal: Cardinal = 0; pNextFunc: Pointer = nil );
var
   ThreadEntry32: TThreadEntry32; // Estrutura de threads
   hThreadSnap  : THandle;        // Handle do SnapShot
   nProcessoAtu : Cardinal;       // ID do processo atual
   thdContext   : TContext;       // Context da Thread
   nThreadHand  : Cardinal;       // Handle da Thread
begin

   // Verifica pra saber se a função foi chamada somente para dar Resume
   if pNextFunc <> nil then
   begin
      // Se sim, da resume em todas
      while Length( nThreadHandles ) <> 0 do
      begin
         nThreadHand := nThreadHandles[ High( nThreadHandles ) ];

         // O Contexto vai servir para alterar o EIP
         thdContext.ContextFlags := CONTEXT_CONTROL or CONTEXT_INTEGER;

         // Pega o contexto
         GetThreadContext( nThreadHand, thdContext );

         // Estava! Agora guia a mesma para o NextFunc
         thdContext.Eip := Cardinal( pNextFunc ) + ( thdContext.Eip - nRangeInicial );

         // Seta devolta o contexto da mesma
         SetThreadContext( nThreadHand, thdContext );

         // Resume nela!
         ResumeThread( nThreadHand );

         SetLength( nThreadHandles, Length( nThreadHandles ) - 1 );
      end;
   end
   else
   begin
      // Pega o valor do processo atual
      nProcessoAtu := GetCurrentProcessId;

      // Cria o SnapShot das threads
      hThreadSnap := CreateToolHelp32SnapShot( TH32CS_SNAPTHREAD, 0 );

      // Caso tenha criado com sucesso
      if hThreadSnap <> INVALID_HANDLE_VALUE then
      begin

         // Informa o Sistema Operacional, qual versão da API utilizar
         ThreadEntry32.dwSize := SizeOf(ThreadEntry32);

         // Inicia a enumeração dos processos
         if Thread32First(hThreadSnap, ThreadEntry32) then

            repeat
               // Verifica se a thread pertence ao processo atual
               if ThreadEntry32.th32OwnerProcessID = nProcessoAtu then
               begin
                  // Devemos primeiro verificar se o EIP da thread está
                  // entre o Range passado como parâmetro.

                  if ThreadEntry32.th32ThreadID <> GetCurrentThreadId then
                  begin
                     // Obtemos o Handle da Thread pelo seu ID
                     nThreadHand := BmsOpenThread( PROCESS_ALL_ACCESS, True, ThreadEntry32.th32ThreadID );

                     // Se pegou com sucesso
                     if nThreadHand <> 0 then
                     begin
                        // Suspende a execução dela
                        SuspendThread( nThreadHand );

                        // O Contexto vai servir para alterar o EIP
                        thdContext.ContextFlags := CONTEXT_CONTROL or CONTEXT_INTEGER;

                        // Pega o contexto da thread
                        if GetThreadContext( nThreadHand, thdContext ) then
                        begin

                           // Verifica se está entre o Range
                           if ( thdContext.Eip >= nRangeInicial ) and
                              ( thdContext.Eip <= nRangeFinal   ) then
                           begin
                              // Adiciona na lista das threads que devem voltar a ser executadas
                              SetLength( nThreadHandles, Length( nThreadHandles ) + 1 );
                              nThreadHandles[ High( nThreadHandles ) ] := nThreadHand;

                              // Chamar a mesma função preenchendo o pNextFunc para
                              // resumir as threads.
                           end
                           else
                              // Resume ela denovo
                              ResumeThread( nThreadHand );
                        end
                        else
                           // Resume ela denovo
                           ResumeThread( nThreadHand );
                     end;

                     // Fecha o Handle aberto da Thread
                     CloseHandle( nThreadHand );
                  end;
               end;

            until not Thread32Next(hThreadSnap, ThreadEntry32);

         // Fecha o Handle
         CloseHandle(hThreadSnap);
      end;
   end;
end;

{ ****************************************************************************

 RemoveJump - Remove o JMP de um determinado endereço, desaloca
              o NextHook e copia os bytes originais de volta ao local.

    pAddress  - Endereço onde deveria estar o JMP

 **************************************************************************** }

function RemoveJump( pAddress: Pointer; var pNextProc: Pointer ): Boolean;
var
   pNextFuncAtual: Pointer;
   pBackToExecut : Pointer;
   nTamNextFunc  : Integer;
   nBytesCopiados: Integer;
   pControleHook : Pointer;
   pIntegridade9x: Pointer;
begin
   Result := False;

   // Se for win9x e o endereço > $80000000, devemos obeter acesso a escrita
   // porque o Windows bloqueia.
   if ( not bWinNT ) and ( Cardinal( pAddress ) > $80000000 ) then
      ObterAcessoEscrita9x( Cardinal( pAddress ), SizeOf( TJmpCode ) * 2 )
   else if bWinNT then
      VirtualProtect( pAddress, SizeOf( TJmpCode ) * 2, PAGE_EXECUTE_READWRITE, nil );

   // Verifica se foi instalado o Hook
   if ( pAddress  <> nil ) and
      ( pNextProc <> nil ) and
      ( PByte( pAddress )^ = $64 ) and
      ( PByte( Cardinal( pAddress ) + 1 )^ = $E9 ) then
   begin

      // Verifica as threads que estão executando o código a ser hookada
      ReGuiarThreads( Cardinal( @pAddress ), Cardinal( @pAddress ) + 6, nil );

      // pControleHook recebe o ponteiro do Controle de Hook (uma das páginas
      // que deve ser desalocada)

      pControleHook := PPointer( Cardinal( pAddress ) + 2 )^;
      pControleHook :=  Pointer( Cardinal( pAddress ) + Cardinal( pControleHook ) + 6 );

      // Se estivermos no win9x, e a API estiver na área de memória compartilhada
      // o verdadeiro controle de hook estará armazenado dentro da sub-rotina que
      // verifica integridade do processo.

      pIntegridade9x := nil;
      
      if ( not bWinNT ) and ( Cardinal( pAddress ) > $80000000 ) then
      begin
         pIntegridade9x := pControleHook;

         pControleHook := PPointer( Cardinal( pControleHook ) + 15 )^;
         pControleHook := Pointer( Cardinal( pIntegridade9x ) + Cardinal( pControleHook ) + 19 );
      end;

      // Até agora temos as páginas que deverão ser desalocadas:
      //  - pControleHook
      //  - pIntegridade9x (só se for <> nil)
      //  - pNextProc

      // Então devemos pegar os bytes originais que estão na pNextProc,
      // e copiar devolta ao endereço real.

      pNextFuncAtual := pNextProc;
      nTamNextFunc   := SizeOfFunction( pNextProc );

      // Varre a NextFunc
      while Integer( pNextFuncAtual ) - Integer( pNextProc ) <= nTamNextFunc do
      begin
         // Verifica se é um JMP relativo, com o prefixo $64
         if ( PByte( pNextFuncAtual )^                 = $64 ) and
            ( PByte( Cardinal( pNextFuncAtual ) + 1 )^ = $E9 ) then
         begin
            // Agora verifica se aponta para o local desejado

            nBytesCopiados := Integer( pNextFuncAtual ) - Integer( pNextProc );
            pBackToExecut  := Pointer( ( Cardinal( pAddress ) + Cardinal( nBytesCopiados ) ) - ( Cardinal( pNextProc ) + Cardinal( nBytesCopiados ) ) - 6 );

            if PPointer( Cardinal( pNextFuncAtual ) + 2 )^ = pBackToExecut then
            begin
               // OK, agora temos todos os dados de que precisamos:

               // PAddress       - Endereço de onde está o Hook
               // PbaseCallback  - Endereço do CallBack
               // PBaseNextFunc  - Endereço da NextHook
               // nBytesCopiados - Quantidade total Bytes copiados

               // Então primeiramente copiamos os bytes originais, de onde vieram
               // usando a função TransfereFunção, pois poderia haver algum CALL
               // ou JMP relativo entre os bytes copiados

               if not TransfereFuncao( pNextProc, pNextProc, pAddress, nBytesCopiados ) then
                  Exit;

               // Enquanto nós estamos Deshookando, pode ser que o NextProc seja
               // executado dentro do CallBack, mas nesse momento o NextProc já
               // foi liberado da memória, então executaremos o próprio pAddress
               pNextProc := pAddress;

               // Agora desaloca a página de controle de Hooks
               VirtualFree( pControleHook, SizeOfFunction( pControleHook ), MEM_DECOMMIT );

               // Se a página de integridade foi alocada, desaloca
               if pIntegridade9x <> nil then
                  VirtualFree( pIntegridade9x, SizeOfFunction( pIntegridade9x ), MEM_DECOMMIT );

               // Desaloca também a NextProc
               VirtualFree( pNextProc, nTamNextFunc, MEM_DECOMMIT );

               // Prontinho, podemos sair agora
               Result := True;

               // Ok, agoras as threads podem voltar
               ReGuiarThreads( Cardinal( @pAddress ), Cardinal( @pAddress ) + 6, pAddress );

               Exit;
            end;
         end;

         Inc( Integer( pNextFuncAtual ), InstructionSize( pNextFuncAtual ) );
      end;
   end;
end;

{****************************************************************************

 InstalaJump         - Instala o Hook em um determinado endereço
                       e retorna True se não ocorreu nenhum erro.

    pAddress         - Ponteiro onde deve ser instalado o hook
    pJumpTo          - Ponteiro para o CallBack
    pBackToExecution - Ponteiro para o NextHook

 **************************************************************************** }


{ ** PARA FAZER ********************** PARA FAZER ************ PARA FAZER ******
********************************************************************************

Atualmente estou usando Interlocked Inc/Decrement para uma variável Global,
para uma contagem única de todos os CallBacks, utilizando o método ESP Hack.

Porém isto não é viável, devemos fazer o Interlocked Inc/Decrement para
uma variável alocada no próprio espaço da rotina que "Incrementa" o contador.

---> Assim teremos uma variável de controle para cada CallBack. <---

Possibilitando:
 -> Unhook seguro
      ( para isso devemos fazer um WHILE para deshookar assim que o contador chegar
        a ZERO. Dessa maneira teremos certeza de que quando for Deshookar, o
        Callback NUNCA estará executando, evitando qualquer erro );
 -> Consequentemente, o método de remoção remota de DLL ficará 100% seguro,
    sempre!


Idéia de como fazer:
 -> Quando criar o Hook, alocar 6 bytes: 4 para um Integer e o 5º,6º para dois Booleans.
      - O Integer vai ser o contador
      - O 1º Boolean indica se Iniciou a remoção do Hook
      - O 2º Boolean indica o momento em que o CallBack pode ser removido com sucesso.
      - Zerar todos os 6 Bytes

 -> Quando remover o Hook
      - alterar o 1º Boolean para Verdadeiro
      - Aguardar até que o 2º Boolean seja Verdadeiro
      - Neste momento o CallBack já está protegido, não tem ninguém executando
        e ninguém vai executá-lo. Portanto já podemos remover o Hook com sucesso!!!!

 -> Quando cair na rotina de Incrementação da variável
    (sempre Depois da chamada da API e Antes do CallBack)
      - Verificar se o Primeiro boolean é True.
        - Caso seja, não deixa cair no CallBack, chama o NextHook direto e ja sai da rotina
          (dessa maneira o Contador tende a decrementar sempre e não cairá mais no CallBack)
      - Incrementa o Contador, faz as alterações no ESP e já chama o CallBack.

 -> Quando cair na rotina de Decrementação da variável
    (sempre Depois do Callback e antes de qualquer outra coisa)
      - Decrementar normalmente
      - Depois de decrementado verificar se o contador está zerado
        - Caso esteja, verificar o 1º Boolean
          - Se for Verdadeiro, quer dizer que o CallBack não está mais sendo
            executado, e nem vai ser executado.
              - Altera o 2º Boolean para TRUE

                ( a rotina de remoção de Hook vai estar
                  aguardando até que este 2º boolean se torne Verdadeiro para
                  continuar a Remoção do Hook. )



********************************************************************************
**** PARA FAZER ********************** PARA FAZER ************ PARA FAZER ****** }



function InstalaJump( pAddress: Pointer; pJumpTo: Pointer; out pBackToExecution: Pointer ): Boolean;
type
   // Quando estamos no Win9x, e o código está na área de memória compartilhada
   // devemos antes de executar o CallBack, verificar se estamos no processo
   // correto, caso contrário o CallBack não existirá, então devemos executar
   // o NextHook ao invéz do CallBack. A estrutura a baixo contém as instruções
   // para tal verificação.
   
   TIntegridadeWin9x = packed record
      PUSH_EAX : Byte;     // 50     PUSH EAX
      CALL_GCPI: Byte;     // E8     CALL [kernel32.GetCurrentProcessID]
      K32_GCPI : Cardinal;
      CMP_EAX  : Byte;     // 3D     CMP EAX, [ID do processo]
      ID_PROC  : Cardinal;
      POP_EAX  : Byte;     // 58     POP EAX
      JNZ      : Byte;     // 75     JNZ +$06
      JNZ_06   : Byte;     // 06
      JMP_NH   : Byte;     // E9     JMP [CallBack]
      CALLBACK : Cardinal;
      JMP_CB   : Byte;     // E9     JMP [NextHook]
      NEXTHOOK : Cardinal;
      RET      : Byte;     // C3     RET
   end;

   // Para sabermos quantos CallBacks dos Hooks estão em uso, devemos incrementar
   // uma variável antes de chamar o CallBack, e decrementar depois de chamar
   // o CallBack. Esta estrutura é usada para este fim.

   TIncHooksEmUso = packed record
      PUSH_EDI : Byte;     // 57            PUSH EDI
      PUSH_EAX : Byte;     // 50            PUSH EAX
      PUSH_ECX : Byte;     // 51            PUSH ECX

      MOVECXESP: array
       [0..3] of Byte;     // 8B 4C 24 0C   MOV ECX, [ESP + 12]

      MOV_EAX2 : Byte;     // B8            MOV EAX, Endereco
      ENDSLVESP: Cardinal;
      MOVEAXECX: array
       [0..1] of Byte;     // 89 08         MOV [EAX], ecx

      MOV_EDI  : Byte;     // BF            MOV EDI, [Decrementa]
      END_DEC  : Cardinal;
      MOV_EAX1 : Byte;     // A1            MOV EAX, [PHooksEmUsoCNT]
      END_PCNT1: Cardinal;
      PUSH_EAX1: Byte;     // 50            PUSH EAX
      CALL_II  : Byte;     // E8            CALL InterlockedIncrement
      INCR     : Cardinal;
      MOVESPEDI: Cardinal; // 89 7C 24 10   MOV [ESP + 12], EDI
      POP_ECX  : Byte;     // 59            POP ECX
      POP_EAX  : Byte;     // 58            POP EAX
      POP_EDI  : Byte;     // 5F            POP EDI
      JMP_CB   : Byte;     // E9            JMP [CallBack]
      CALLBACK : Cardinal;
      RET      : Byte;     // C3            RET
   end;

   TDecHooksEmUso = packed record
      PUSH_EAX : Byte;     // 50            PUSH EAX
      MOV_EAX  : Byte;     // A1            MOV EAX, [PHooksEmUsoCNT]
      END_PCNT : Cardinal;
      PUSH_EAX2: Byte;     // 50            PUSH EAX
      CALL_ID  : Byte;     // E8            CALL InterlockedDecrement
      DECR     : Cardinal;
      POP_EAX  : Byte;     // 58            POP EAX
      PUSH     : Byte;     // 68            PUSH [EnderecoRetorno]
      ENDRET   : Cardinal;
      RET      : Byte;     // C3            RET
   end;

var
   JmpCode         : TJmpCode;
   nAux            : Cardinal;
   nBytesToCopy    : Integer;
   bC3             : Byte;
   nProc           : Cardinal;
   aVerificaByte   : array[ 0 .. SizeOf( TJmpCode ) ] of Byte;
   IntegridadeWin9x: TIntegridadeWin9x;
   pIntegridade9x  : Pointer;
   IncHooksEmUso   : TIncHooksEmUso;
   pIncHooksEmUso  : Pointer;
   DecHooksEmUso   : TDecHooksEmUso;
   pDecHooksEmUso  : Pointer;
begin
   Result := False;

   // Abre o processo para Leitura/Escrita
   nProc := OpenProcess( PROCESS_ALL_ACCESS, False, GetCurrentProcessId );

   // Verifica se há um $C2 ou $C3 (ret) nos SizeOf( TJmpCode ) primeiros
   // bytes de pAddress. Se haver então sai porque não há espaço o suficiente
   // pra armazenar um JMP de 6 bytes lá.
   if not ReadProcessMemory( nProc, pAddress, @aVerificaByte, SizeOf( TJmpCode ), nAux ) then
      Exit;

   nAux := 0;

   while nAux <= SizeOf( TJmpCode ) do
   begin
      if aVerificaByte[ nAux ] in [ $c2, $c3 ] then
         Exit;

      Inc( nAux, InstructionSize( Pointer( Cardinal( pAddress ) + nAux ) ) );
   end;

   // Calcula a quantidade de instruções *completas* até completar o tamanho de um JMP.
   nBytesToCopy := getBytesInstComp( pAddress );

   // Lê as instruções completas, e salva em aFirstBytes.
   if not ReadProcessMemory( nProc, pAddress, @aFirstBytes, nBytesToCopy, nAux ) then
      Exit;

   // Neste bloco preenchemos o conteúdo de Controle de Hooks, para sabermos
   // quantos CallBacks estão sendo executados no momento em que quisermos.
   // Sempre que executar um CallBack, a variável pHooksEmUsoCNT é incrementada
   // Então alteraremos o Stack para quando encontrar o RET do CallBack, pule
   // para nossa função que irá Decrementar a variável

   pDecHooksEmUso := AlocaMem( SizeOf( TDecHooksEmUso ), GetCurrentProcess );

   with DecHooksEmUso do
   begin
      PUSH_EAX  := $50;
      MOV_EAX   := $A1;
      END_PCNT  := Cardinal( @pHooksEmUsoCnt );
      PUSH_EAX2 := $50;
      CALL_ID   := $E8;
      DECR      := Cardinal( pInterlockedDecrement );
      DECR      := DECR - Cardinal( pDecHooksEmUso ) - 12;
      POP_EAX   := $58;
      PUSH      := $68;
      ENDRET    := $00000000;
      RET       := $C3;
   end;

   if not WriteProcessMemory( nProc, pDecHooksEmUso, @DecHooksEmUso, SizeOf( TDecHooksEmUso ), nAux ) then
      Exit;

   pIncHooksEmUso := AlocaMem( SizeOf( TIncHooksEmUso ), GetCurrentProcess );

   with IncHooksEmUso do
   begin
      PUSH_EDI  := $57;
      PUSH_EAX  := $50;
      PUSH_ECX  := $51;
      PUSH_ECX  := $51;

      // Esse bloco vai alterar diretamente a procedure que decrementa
      // o pHooksEmUsoCNT para que dê um PUSH no primeiro item do Stack
      // atual. Assim quando encontrar um RET vai voltar para o endereço
      // que realmente chamou a API.

      MOVECXESP[0] := $8B;
      MOVECXESP[1] := $4C;
      MOVECXESP[2] := $24;
      MOVECXESP[3] := $0C;
      MOV_EAX2     := $B8;
      ENDSLVESP    := Cardinal( pDecHooksEmUso ) + 14;
      MOVEAXECX[0] := $89;
      MOVEAXECX[1] := $08;

      MOV_EDI   := $BF;
      END_DEC   := Cardinal( pDecHooksEmUso );
      MOV_EAX1  := $A1;
      END_PCNT1 := Cardinal( @pHooksEmUsoCnt );
      PUSH_EAX1 := $50;
      CALL_II   := $E8;
      INCR      := Cardinal( pInterlockedIncrement );
      INCR      := IncHooksEmUso.INCR - Cardinal( pIncHooksEmUso ) - 30;
      MOVESPEDI := $0C247C89;
      POP_ECX   := $59;
      POP_EAX   := $58;
      POP_EDI   := $5F;
      JMP_CB    := $E9;
      CALLBACK  := Cardinal( pJumpTo ) - Cardinal( pIncHooksEmUso ) - 42;
      RET       := $C3;
   end;

   if not WriteProcessMemory( nProc, pIncHooksEmUso, @IncHooksEmUso, SizeOf( TIncHooksEmUso ), nAux ) then
      Exit;

   // Se estamos no win9x e o código estiver na área de memória compartilhada
   // temos que alocar uma outra procedure que verifica o GetCurrentProcessID
   // para que o hook não tenha efeito em outros processos.

   // Evita Warning de que pIntegridadex não foi nicializada
   pIntegridade9x := nil;

   if not bWinNT and ( Cardinal( pAddress ) > $80000000 ) then
   begin
      pIntegridade9x := AlocaMem( SizeOf( TIntegridadeWin9x ), GetCurrentProcess );

      with IntegridadeWin9x do
      begin
         PUSH_EAX  := $50;
         CALL_GCPI := $E8;
         K32_GCPI  := Cardinal( pGetCurrentProcessID );
         K32_GCPI  := IntegridadeWin9x.K32_GCPI - Cardinal( pIntegridade9x ) - 6;
         CMP_EAX   := $3D;
         ID_PROC   := GetCurrentProcessId;
         POP_EAX   := $58;
         JNZ       := $75;
         JNZ_06    := $05;
         JMP_NH    := $E9;
         CALLBACK  := Cardinal( pIncHooksEmUso ) - Cardinal( pIntegridade9x ) - 19;
         JMP_CB    := $E9;
         NEXTHOOK  := 000;
         RET       := $C3;
      end;
      
      // Calcula a distância do JMP
      JmpCode.nDistancia := Cardinal( pIntegridade9x ) - Cardinal( pAddress ) - 6;
   end
   else// if bWinNT then
      // Calcula a distância do JMP
      JmpCode.nDistancia := Cardinal( pIncHooksEmUso ) - Cardinal( pAddress ) - 6;

   // Preenche o resto do Record com Opcodes/Prefixos
   JmpCode.bCALL    := $64;
   JmpCode.bPrefixo := $E9;

   // Se for win9x e o endereço > $80000000, devemos obeter acesso a escrita
   // porque o Windows bloqueia.
   if ( not bWinNT ) and ( Cardinal( pAddress ) > $80000000 ) then
      ObterAcessoEscrita9x( Cardinal( pAddress ), nBytesToCopy )
   else if bWinNT then
      VirtualProtect( pAddress, SizeOf( TJmpCode ) * 2, PAGE_EXECUTE_READWRITE, nil );

   // Verifica as threads que estão executando o código a ser hookada
//   ReGuiarThreads( Cardinal( @pAddress ), Cardinal( @pAddress ) + 6, nil );

   // Escreve o JMP no ponteiro indicado em pAddress. Esse JMP tem como
   // destino, o Controle de Hooks
   if not WriteProcessMemory( nProc, pAddress, @JmpCode, SizeOf( TJmpCode ), nAux ) then
      Exit;

   // Ok, agoras as threads podem voltar
//   ReGuiarThreads( Cardinal( @pAddress ), Cardinal( @pAddress ) + 6, pBackToExecution );

   // Aloca um espaço para o "NEXT HOOK". Next Hook faz a chamada para a API
   // original. Lembra dos primeiros bytes copiados? Esta alocação vai executá-los
   // e em seguida mudar a execução para a API original + alguns bytes,
   // esses "alguns bytes" são os bytes necessários para o JMP.
   // Isso evita que caia num StackOverflow. Esta técnica é chamada de Extended
   // Code Overwrite
   pBackToExecution := AlocaMem( nBytesToCopy + SizeOf( TJmpCode ) + 1, GetCurrentProcess );

   // Se não conseguiu alocar por alguma causa desconhecida, sai.
   if pBackToExecution = nil then
      Exit;

   if not bWinNT and ( Cardinal( pAddress ) > $80000000 ) then
   begin
      // Calcula a distância do NextHook
      IntegridadeWin9x.NEXTHOOK := Cardinal( pBackToExecution ) - Cardinal( pIntegridade9x ) - 24;

      if not WriteProcessMemory( nProc, pIntegridade9x, @IntegridadeWin9x, SizeOf( TIntegridadeWin9x ), nAux ) then
         Exit;
   end;

   // Calcula o endereço que deve apontar o JMP que pula para a API
   // original + alguns bytes
   JmpCode.nDistancia := ( Cardinal( pAddress         ) + Cardinal( nBytesToCopy ) ) -
                         ( Cardinal( pBackToExecution ) + Cardinal( nBytesToCopy ) ) - 6;

   // $C3 é um RET, que indica um FIM da função.
   bC3 := $C3;

   // Escreve no "Next hook" as primeiras instruções válidas da API original.
   if not TransfereFuncao( @aFirstBytes, pAddress, pBackToExecution, nBytesToCopy ) then
      Exit;

   // Escreve o JMP que aponta para a API original + alguns bytes
   if not WriteProcessMemory( nProc, Pointer( Cardinal( pbackToExecution ) + Cardinal( nBytesToCopy ) ),
                              @JmpCode, SizeOf( TJmpCode ), nAux ) then
      Exit;

   // Escreve um RET no fim da função. Também vai ser usado para identificar
   // o fim da procedure quando for desinstalar o hook.
   if not WriteProcessMemory( nProc, Pointer( Cardinal( pbackToExecution ) + Cardinal( nBytesToCopy ) + SizeOf( TJmpCode ) ),
                              @bC3, SizeOf( Byte ), nAux ) then
      Exit;

   CloseHandle( nProc );

   Result := True;
end;


{ ****************************************************************************

 BmsHookCode - Instala o Hook em um endereço qualquer

    pAddress  - Ponteiro onde deve ser instalado o hook
    pCallBack - Ponteiro para o CallBack
    pNextProc - Ponteiro para o NextHook

 **************************************************************************** }

function BmsHookCode( pCode: Pointer; pCallBack: Pointer; out pNextProc: Pointer ): Boolean;
begin
   Result := InstalaJump( pCode, pCallBack, pNextProc );

   // Temos que salvar os dados para deshookar a função
   // quando o programa for fechado para não prejudicar as
   // APIs originais

   if Result then
   begin
      SetLength( aListaHooks, Length( aListaHooks ) + 1 );

      aListaHooks[ High( aListaHooks ) ].pNextProc := pNextProc;
      aListaHooks[ High( aListaHooks ) ].pEndereco := pCode;
   end;

end;

{ ****************************************************************************

 BmsUnHookCode - Remove o Hook de um determinado endereço

    pCode - Ponteiro onde deve ser desinstalado o hook

 **************************************************************************** }

function BmsUnHookCode( pCode: Pointer; var pNextProc: Pointer ): Boolean;
var
   nAux : Integer;
   nAux2: Integer;
begin
   Result := RemoveJump( pCode, pNextProc );

   if Result then
   begin
      // Se foi necessário adicionar o ponteiro nas funções que
      // precisam ser deshookadas por falta do programador,
      // remove a mesma da lista.

      for nAux := 0 to Length( aListaHooks ) - 1 do
      begin
         if ( aListaHooks[ nAux ].pEndereco = pCode ) and
            ( aListaHooks[ nAux ].pNextProc = pNextProc ) then
         begin
            for nAux2 := nAux to High( aListaHooks ) - 1 do
               aListaHooks[ nAux2 ] := aListaHooks[ nAux2 + 1 ];

            SetLength( aListaHooks, Length( aListaHooks ) - 1 );
            Break;
         end;
      end;
   end;
end;

{ ****************************************************************************

 BmsHookApi - Instala o Hook em uma API qualquer

    sModule   - Nome da DLL da API
    sAPI      - API para instalar o Hook
    pCallback - Ponteiro para o CallBack
    pNextProc - Ponteiro para o NextProc

 **************************************************************************** }

 { ** PARA FAZER ********************** PARA FAZER ************ PARA FAZER ******
********************************************************************************

Atualmente, a DLL é carregada caso a mesma não tenha sido carregada ainda,
no momento de instalar o Hook. Porém não há necessidades pois se o processo nao
precisar da DLL, ela nunca vai carregar, o que pode ocasionar muitos erros.

Então, verificar se a DLL já foi carregada. Se ainda não foi, salva todos os
dados do Hook, instala um Hook na LoadLibrary, e caso a DLL seja a mesma, instala
o hook.

********************************************************************************
**** PARA FAZER ********************** PARA FAZER ************ PARA FAZER ****** }

function BmsHookApi( sModule: PChar; sAPI: PChar; pCallBack: Pointer; out pNextProc: Pointer): Boolean;
var
   hModule  : Cardinal;
   pEndereco: Pointer;
begin
   hModule := GetModuleHandle( sModule );
   Result  := True;

   if hModule = 0 then
      hModule := LoadLibrary( sModule );

   // Se o módulo já estiver carregado então instala o Hook imediatamente
   // Caso contrário, o CallBack do LoadLibrary vai instalá-lo.

   if hModule <> 0 then
   begin
      pEndereco := GetProcAddress( hModule, sAPI );
      Result    := InstalaJump( pEndereco, pCallBack, pNextProc );

      // Temos que salvar os dados para deshookar a função
      // quando o programa for fechado para não prejudicar as
      // APIs originais.

      SetLength( aListaHooks, Length( aListaHooks ) + 1 );

      aListaHooks[ High( aListaHooks ) ].sDLL      := sModule;
      aListaHooks[ High( aListaHooks ) ].sAPI      := sAPI;
      aListaHooks[ High( aListaHooks ) ].pEndereco := pEndereco;
      aListaHooks[ High( aListaHooks ) ].pNextProc := pNextProc;
   end;
end;

{ ****************************************************************************

 BmsUnHookApi - Desinstala o Hook de uma determinada API

    sModule   - Nome da DLL da API
    sAPI      - API para desinstalar o Hook
    pCallBack - Ponteiro para o CallBack
    pNextProc - Ponteiro para o NextProc

 **************************************************************************** }

function BmsUnHookApi( sModule: PChar; sAPI: PChar; var pNextProc: Pointer ): Boolean;
var
   hModule  : Cardinal;
   pEndereco: Pointer;
   nAux     : Integer;
   nAux2    : Integer;
begin
   hModule := GetModuleHandle( sModule );
   Result  := True;

   if hModule <> 0 then
   begin
      pEndereco := GetProcAddress( hModule, sAPI );
      Result    := RemoveJump( pEndereco, pNextProc );
   end;

   // Se foi necessário adicionar o ponteiro nas funções que
   // precisam ser deshookadas por falta do programador,
   // remove a mesma da lista.

   for nAux := 0 to Length( aListaHooks ) - 1 do
      if ( aListaHooks[ nAux ].pNextProc = pNextProc ) then
      begin
         for nAux2 := nAux to High( aListaHooks ) - 1 do
            aListaHooks[ nAux2 ] := aListaHooks[ nAux2 + 1 ];

         SetLength( aListaHooks, Length( aListaHooks ) - 1 );
         Break;
      end;
end;

var
   nHandle: Cardinal = 0;
   bZerarCont: Boolean;

initialization

   // Atribue a variável de contagem de Hooks que estão em uso
   // e verifica se a variavel já existia. Caso ela não exista, criamos e zeramos

   pLoadLibraryA         := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'LoadLibraryA' );
   pLoadLibraryExW       := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'LoadLibraryExW' );
   pFreeLibrary          := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'FreeLibrary' );
   pGetModuleHandleA     := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'GetModuleHandleA' );
   pSleep                := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'Sleep' );
   pInterlockedDecrement := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'InterlockedDecrement' );
   pInterlockedIncrement := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'InterlockedIncrement' );
   pGetCurrentProcessID  := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'GetCurrentProcessId' );

   nHandle        := CreateFileMapping( $FFFFFFFF, nil, PAGE_READWRITE, 0, SizeOf( ULong ), 'BmsApiHook_HooksEmUsoCnt' );
   bZerarCont     := GetLastError <> ERROR_ALREADY_EXISTS;
   pHooksEmUsoCnt := MapViewOfFile( nHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0 );

   if not bZerarCont then
      pHooksEmUsoCnt^ := 0;

   // Se for winNT, setar privilégios de Debug para poder escrever em processos
   // de sistema (SYSTEM)
   if bWinNT then
      GetDebugPrivs;

   // Instalamos um Hook na API LoadLibraryExW para que, toda vez que uma DLL
   // for carregada, verificaremos se alguma API pertence aquela DLL, para
   // renovermos o Hook. Essa API é chamada internamente por todas as LoadLibraries
//   BmsHookCode( pLoadLibraryA, @LoadLibraryA_cb, @LoadLibraryA_np );
//   BmsHookCode( pFreeLibrary , @FreeLibrary_cb , @FreeLibrary_np  );

   // Verificamos se devemos instalar um Hook global, mas apenas se estivermos
   // no winNT, pois no win9x devemos instalar o hook apenas uma vez, já que
   // a API CreateProcess está compartilhada

   if IsLibrary then
   begin
      // Tentaremos abrir o FileMapping
      nHandle := OpenFileMapping( FILE_MAP_ALL_ACCESS, False, 'BmsApiHook_HookGlobal1' );

      // verifica se existe, caso exista, instala o Hook
      if nHandle <> 0 then
      begin
         // Instala o Hook na API CreateProcessA e CreateProcessW
         BmsHookApi( 'kernel32.dll', 'CreateProcessA', @CreateProcessA_cb, @CreateProcessA_np );
         BmsHookApi( 'kernel32.dll', 'CreateProcessW', @CreateProcessW_cb, @CreateProcessW_np );

         // Fecha o Handle previamente aberto
         CloseHandle( nHandle );
      end;
   end;

finalization

   // Quando finalizar, deve desinstalar automaticamente os hooks
   // préviamente instalados

   while Length( aListaHooks ) <> 0 do
   begin
      RemoveJump( aListaHooks[ High( aListaHooks ) ].pEndereco,
                  aListaHooks[ High( aListaHooks ) ].pNextProc );
                  
      SetLength( aListaHooks, Length( aListaHooks ) - 1 );
   end;

   // E fechar todos os Handles

   if nHandle <> 0 then
      CloseHandle( nHandle );

   if fMapHandle <> 0 then
      CloseHandle( fMapHandle );

   UnmapViewOfFile( pHooksEmUsoCnt );
end.
