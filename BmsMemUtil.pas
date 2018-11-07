unit BmsMemUtil;

interface
uses
   Windows, SysUtils, PsApi;

{ ****************************************************************************

  BmsMemUtil - Utilidades compartilhadas
  Autor: Bruno Martins Stuani

 **************************************************************************** }

  // Bah, "Symbol 'index' is specific to a platform" t� me enchendo, hehe}
  {$Warnings off}

   procedure ObterAcessoEscrita9x            // Obtem acesso a escrita na mem�ria compartilhada do win9x
             ( nEnderecoBase: Dword;         // Endere�o base da mem�ria
               nTamanho: DWORD               // Quantidade de bytes para obter acesso
               );

   function BmsOpenThread                    // Obt�m o Handle de uma Thread, pela sua ID
            ( dwAccess: DWORD;               // Acesso ao objeto Thread (proces_all_access)
              bInherithandle: LongBool;      // Herdar Handle?
              dwTID: DWORD                   // ID da Thread
              ): Cardinal;

   function AlocaMem                         // Aloca mem�ria em um outro processo
            ( nTamanho: Integer;             // Quantidade de bytes � alocar
              HProcesso: Cardinal            // Handle do processo
              ): Pointer;

   function LiberaMem                        // Libera mem�ria alocada em outro processo
            ( pEndereco: Pointer;            // Endere�o da mem�ria
              nTamanho: Integer;             // Quantidade de bytes
              HProcesso: Cardinal            // Handle do processo
              ): Boolean;

   function BmsCreateRemoteThread9x          // Cria uma thread remota, independente do S.O.
            ( dwProcessId: Cardinal;         // ID do processo
              lpStartAddress: Pointer;       // Ponteiro para os parametros
              lpParameter: Pointer;          // Par�metros
              dwCreationFlag: DWORD;         // Flags de cria��o
              var dwThreadID: Cardinal       // Variaval que recebe o ID da thread
              ): Cardinal;

   function DLLCarregada                     // Verifica se uma determinada DLL est� carregada
            ( sDLL: string                   // Nome da DLL
              ): Boolean;

   procedure GetDebugPrivs;  // Obt�m privil�gios de Debug

   procedure VxDCall;                   // Permite chamar uma fun��o de um VXD, no win9x
             external kernel32 index 1; // Ela � exportada pela kernel como indice 1

   var
      bWinNT: Boolean; // Indica se estamos em um Windows baseado no kernel do NT
   
implementation

{****************************************************************************

 DLLCarregada - Retorna Verdadeiro se a DLL passada como par�metro est�
                carregada no processo atual

    sDLL - M�dulo utilizado na pesquisa

 **************************************************************************** }

function DLLCarregada( sDLL: string ): Boolean;
var
   hMods    : array[0..1024] of HMODULE;     // Array contendo os m�dulos
   szModName: array [0..max_path] of Char;   // String para captura do nome do m�dulo
   hProcess : THandle;                       // Handle do processo
   cbNeeded : DWORD;                         // Vari�vel auxiliar
   nAux     : Integer;                       // Vari�vel auxiliar
begin
   // Pega o Handle do processo ativo
   hProcess := GetCurrentProcess;

   // Inicia a enumera��o dos m�dulos
   if EnumProcessModules( hProcess, @hMods[0], sizeof(hMods), cbNeeded ) then

      // Passa por todos os m�dulos
      for nAux := 0 to cbNeeded div sizeof( HMODULE ) do

         // Pega o nome do m�dulo
         if GetModuleFileNameEx( hProcess, hMods[nAux], szModName, sizeof(szModName)) <> 0 then

            // E compara com o m�dulo passado como par�metro
            if Pos( LowerCase( sDLL ), LowerCase( szModName ) ) <> 0 then
            begin

               // Se for igual, retorna verdadeiro!
               Result := True;
               Break;
            end;
end;

{****************************************************************************

 WinNT - Retorna Verdadeiro se kernel do sistema operacional for
         baseado em Windows NT

 **************************************************************************** }

function winNT: boolean;
var
   VerInfo: TOsversionInfo; // Informa��es do Sistema Operacional
begin
   // Informa o Sistema Operaciona qual vers�o da API ele deve utilizar
   VerInfo.dwOSVersionInfoSize := SizeOf( VerInfo );

   // Obt�m a vers�o
   GetVersionEx( VerInfo );

   // Resultado verdadeiro caso a plataforma seja NT
   Result := VerInfo.dwPlatformId = VER_PLATFORM_WIN32_NT;
end;

{****************************************************************************

 GetDebugPrivs - Carrega privil�gios de Debug para poder escrever em processos
                 do sistema operacional, em sistemas NT

 **************************************************************************** }

procedure GetDebugPrivs;
const
   // Query que o SO deve executar para obter privil�gio de Debug
   SE_DEBUG_NAME = 'SeDebugPrivilege';
var
   hToken: THandle;          // Handle do Token
   tkp   : TTokenPrivileges; // Privil�gio
   retval: dword;            // Retorno
begin
   // Inicializa a transa��o para ajuste de privil�gio e execu��o da query
   if OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or  TOKEN_QUERY, hToken ) then
   begin

      // Inicia a query de ajuste de privil�gio
      LookupPrivilegeValue( nil, SE_DEBUG_NAME, tkp.Privileges[0].Luid );

      // Quantas queries vai executar
      tkp.PrivilegeCount := 1;

      // Indica que a query � de ajuste de privil�gio
      tkp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;

      // Finalmente executa a query
      AdjustTokenPrivileges( hToken, false, tkp, 0, nil, retval );
   end;
end;

{****************************************************************************

 BmsOpenThread - Abre uma determinada thread e retorna o Handle dela
                 Essa fun��o funciona em todos os windows (ao contr�rio da
                 OpenThread exportada pela Kernel.

    dwAccess       - Modo de acesso ao handle da Thread
    bInheritHandle - Herdar handles
    dwTID          - ID da Thread

 **************************************************************************** }

function BmsOpenThread( dwAccess: DWORD; bInherithandle: LongBool; dwTID: DWORD ): Cardinal;
var
   pOpenProcess: Pointer;
   OpenThread  : Pointer;
   pTDB        : Pointer;
   dObsfucator : DWORD;

   OpenThreadNT: function( dwAccess: DWORD; bInherithandle: LongBool; dwTID: DWORD ): Cardinal; stdcall;
begin

   // Se estivermos no Windows NT, aproveita a OpenThread
   // exportada pelo Kernel, caso contr�rio utilizaremos nossa pr�pria
   // fun��o.

   if bWinNT then
   begin
      // Como a unit WINDOWS n�o tem o cabe�alho para a OpenThread
      // temos que pegar o endere�o dela diretamente da Kernel32.dll

      OpenThreadNT := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'OpenThread' );

      // E finalmente chamamos a OpenThread como resultado
      Result := OpenThreadNT( dwAccess, bInherithandle, dwTID );
   end
   else
   begin
      // colocamos o ID de nosso processo em dObsfucator
      dObsfucator := GetCurrentProcessID;

      // Aqui calculamos o Obfuscator
      asm
         MOV  EAX, FS:[030h]
         XOR  EAX, dObsfucator;
         MOV  dObsfucator, EAX
      end;

      // pega o ThreadDataBase da thread passada como parametro
      pTDB := Pointer( dwTID xor dObsfucator );

      // Verifica se � um ponteiro v�lido
      if IsBadReadPtr( pTDB, 4 ) then
         Result := 0
      else
      begin
         // Pega o endere�o da OpenProcess
         pOpenProcess := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'OpenProcess' );

         // A verifica��o abaixo � somente para evitar e arrumar
         // erros do compilador. Ent�o verifica se o inicio da OpenProcess
         // tem um PUSH [endere�o]. Caso seja verdadeiro, pega o endere�o
         // que ele d� o PUSH e atribue novamente em pOpenProcess.
         // Esse � o EntryPoint real da OpenProcess

         if PByte( pOpenProcess )^ = $68 then
            pOpenProcess := PPointer( Pointer( Cardinal( pOpenProcess ) + 1 ) )^;

         // No come�o da OpenProcess, tem um CALL para a fun��o que retorna o
         // ProcessDataBase e move o resultado em EAX. Depois ele verifica
         // se o conte�do de EAX � um objeto do tipo "Processo de Kernel".
         // Se chamarmos a OpenProcess diretamente essa verificas
         // vai falhar pois estamos trabalhando com ThreadDataBase e nao
         // ProcessDataBase. Ent�o somamos 24 bytes ao EntryPoint da API para
         // pular essas verifica��es.

         OpenThread := Pointer( Cardinal( pOpenProcess ) + $24 );

         // Aqui finalmente chamamos a OpenProcess sem verifica�es e movemos
         // para o EAX, o ThreadDataBase antes de chamar a OpenProcess porque
         // no EAX era para conter o ProcessDataBase, mas agora deve conter o
         // ThreadDataBase

         asm
            PUSH    dwAccess
            PUSH    bInherithandle
            PUSH    dwTID
            MOV     EAX, pTDB
            call    OpenThread

            // Retorna o resultado da OpenThread
            MOV     Result, EAX
         end;
      end;
   end;
end;

{****************************************************************************

 BmsCreateRemoteThread9x - Emula��o do CreateRemoteThread que funciona nas
                           vers�es 9x do Windows.

    Parametros s�o os mesmos da CreateRemoteThread

 **************************************************************************** }

function BmsCreateRemoteThread9x( dwProcessId: Cardinal; lpStartAddress: Pointer; lpParameter: Pointer; dwCreationFlag: DWORD; var dwThreadID: Cardinal): Cardinal;
type

   // Dentro da DebugActiveProcess temos que localizar uma "assinatura" para
   // sabermos onde est� a fun��o interna do Windows. Essa estrutura � usada
   // para essa localiza��o.

   TPushInterno = packed record
      nPush: Byte;     // $68
      nPara: Cardinal; // $FFFFF000
   end;

var
   pPDB: Pointer;             // Ponteiro para o ProcessDataBase
   pTDB: Pointer;             // Ponteiro para o ThreadDataBase
   fFlags: DWORD;             // Flags utilizada internamente pela IcrThread
   StackSize: Integer;        // Tamanho m�ximo do Stack
   dObsfucator: Cardinal;     // Obsfucador
   dbgActiveProc: Pointer;    // Endere�o da API DebugActiveProcess
   nDist: Cardinal;           // Utlizada no calculo de Dist�ncia Relativa
   piEstrutura: TPushInterno; // Estrutura para a "assinatura digital"
   pPesquisa: Pointer;        // Ponteiro para a pesquisa na mem�ria

   IcrThread: function(pPDB: Pointer; dwStackSize: DWORD; lpStartAddress: Pointer;
                       lpParameter: Pointer; Flags: DWORD): Pointer; stdcall;

begin
   // Seta a Flag com o valor inicial
   fFlags := 8;

   // colocamos o ID de nosso processo em dObsfucator
   dObsfucator := GetCurrentProcessID;

   // Aqui calculamos o Obfuscator
   asm
      MOV  EAX, FS:[030h]
      XOR  EAX, dObsfucator;
      MOV  dObsfucator, EAX
   end;

   // Retorna o ProcessDataBase do processo remoto
   pPDB := Pointer( dwProcessId xor dObsfucator );

   // StackSize padr�o
   StackSize := -$3000;

   // O Windows possui internamente uma fun��o que cria uma Thread remota.
   // A API DebugActiveProcess possui uma chamada para essa fun��o. Ent�o vamos
   // abrir a DebugActiveProcess e pegar esse local
   dbgActiveProc := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'DebugActiveProcess' );

   // Se o primeiro byte for $68, ent�o estamos dentro do Debuger, logo
   // a primeira instru��o da DebugActiveProcess vai ser um PUSH para o endere�o
   // real da mesma. Ent�o pegaremos o local que � atribu�do o PUSH
   if PByte( DbgActiveProc )^ = $68 then
      dbgActiveProc := PPointer( Cardinal( dbgActiveProc ) + $1 )^;

   // A partir daqui temos que pesquisar pela sequ�ncia 68 00 0F FF FF
   // que servir� como um ponto de refer�ncia para a Chamada da fun��o interna
   pPesquisa := dbgActiveProc;

   // Atribui os valores da pesquisa
   piEstrutura.nPush := $68;
   piEstrutura.nPara := $FFFFF000;

   // Pesquisa byte a byte
   while not CompareMem( pPesquisa, @piEstrutura, SizeOf( TPushInterno ) ) do
      Inc( Integer( pPesquisa ) );

   // Depois de ter localizado, sabemos que a fun��o est� a 7 bytes p/ frente
   Inc( Integer( pPesquisa ), 7 );
   dbgActiveProc := pPesquisa;

   // Como tudo � feito via CALL relativo, temos que calcular a dist�ncia do Call
   nDist := Cardinal( DbgActiveProc^ );

   // Agora atribu�mos o InternalCreateRemoteThread com os c�lculos da dist�ncia
   @IcrThread := Pointer( Cardinal( DbgActiveProc ) - ( $FFFFFFFF - nDist ) + 3 );

   // Ela nos retorna o ThreadDataBase da Thread
   pTDB := IcrThread( pPDB, StackSize, lpStartAddress, lpParameter, fFlags );

   // a partir dela temos o ID, que � calculado efetuando o XOR com o Obsfucator
   dwThreadId := Cardinal( pTDB ) xor dObsfucator;

   // E sucessivamente, o Handle da mesma
   Result := BmsOpenThread(PROCESS_ALL_ACCESS, False, dwThreadId);
end;

{****************************************************************************

 ObterAcessoEscrita9x - O Windows 9x bloqueia acesso a escrita na �rea
                        de mem�ria compartilhada. Essa fun��o desbloqueia
                        essa �rea e permite que seja escrito qualquer coisa
                        l�.

    nEnderecoBase - Endere�o para desbloquear
    nTamanho      - Quantidade de bytes para desbloquear

 **************************************************************************** }

procedure ObterAcessoEscrita9x( nEnderecoBase: Dword; nTamanho: DWORD );
var
   Endereco: DWord;
begin
   // Incrementa 4096 bytes em nTamanho. 4096 � o tamanho m�ximo de uma
   // p�gina, ent�o calculamos quantas p�ginas cabem em nTAMANHO

   Inc( nTamanho, 4096 );
   nTamanho := nTamanho      shr 12;
   Endereco := nEnderecoBase shr 12;

   // Chama a VxdCALL exportado pela Kernel, passando os par�metros
   // PC_SHARE, PC_USER e PC_WRITEABLE para tornar a p�gina "escrev�vel"
   // e chama a fun��o _PageModifyPermission
   asm
      push    $20000000 or $00020000 or $00040000
      push    0
      push    nTamanho
      push    Endereco
      push    $00001000D
      call    VxDCall
   end;
end;

{****************************************************************************

 LiberaMem - Lebera mem�ria alocada pela AlocaMem em outro processo

    pEndereco - Endere�o para liberar
    nTamanho  - Quantidade de bytes para liberar
    hProcesso - Processo ao qual a mem�ria ser� liberada

 **************************************************************************** }

function LiberaMem( pEndereco: Pointer; nTamanho: Integer; HProcesso: Cardinal ): Boolean;
begin
   if bWinNT then
      // Se for kernel do NT, libera diretamente no outro processo
      Result := VirtualFreeEx( hProcesso, pEndereco, nTamanho, MEM_DECOMMIT ) <> nil
   else
      // caso contr�rio libera mem�ria na �rea de mem�ria compartilhada
      Result := VirtualFree( pEndereco, nTamanho, MEM_DECOMMIT or $8000000 );
end;

{****************************************************************************

 AlocaMem - Aloca mem�ria em outro processo e retorna o ponteiro
            base da mem�ria alocada.

    nTamanho  - Quantidade de bytes para alocar
    hProcesso - Processo ao qual a mem�ria ser� alocada

 **************************************************************************** }

function AlocaMem( nTamanho: Integer; HProcesso: Cardinal ): Pointer;
begin
   if bWinNT then
      // Se for kernel do NT, aloca diretamente no outro processo
      Result := VirtualAllocEx( hProcesso, nil, nTamanho, MEM_COMMIT, PAGE_READWRITE )
   else
      // caso contr�rio aloca mem�ria na �rea de mem�ria compartilhada
      Result := VirtualAlloc( nil, nTamanho, MEM_COMMIT or $8000000, PAGE_READWRITE );
end;

initialization
   // Verifica o tipo do kernel
   bWinNT := winNT;
end.
