unit BmsMemUtil;

interface
uses
   Windows, SysUtils, PsApi;

{ ****************************************************************************

  BmsMemUtil - Utilidades compartilhadas
  Autor: Bruno Martins Stuani

 **************************************************************************** }

  // Bah, "Symbol 'index' is specific to a platform" tá me enchendo, hehe}
  {$Warnings off}

   procedure ObterAcessoEscrita9x            // Obtem acesso a escrita na memória compartilhada do win9x
             ( nEnderecoBase: Dword;         // Endereço base da memória
               nTamanho: DWORD               // Quantidade de bytes para obter acesso
               );

   function BmsOpenThread                    // Obtém o Handle de uma Thread, pela sua ID
            ( dwAccess: DWORD;               // Acesso ao objeto Thread (proces_all_access)
              bInherithandle: LongBool;      // Herdar Handle?
              dwTID: DWORD                   // ID da Thread
              ): Cardinal;

   function AlocaMem                         // Aloca memória em um outro processo
            ( nTamanho: Integer;             // Quantidade de bytes à alocar
              HProcesso: Cardinal            // Handle do processo
              ): Pointer;

   function LiberaMem                        // Libera memória alocada em outro processo
            ( pEndereco: Pointer;            // Endereço da memória
              nTamanho: Integer;             // Quantidade de bytes
              HProcesso: Cardinal            // Handle do processo
              ): Boolean;

   function BmsCreateRemoteThread9x          // Cria uma thread remota, independente do S.O.
            ( dwProcessId: Cardinal;         // ID do processo
              lpStartAddress: Pointer;       // Ponteiro para os parametros
              lpParameter: Pointer;          // Parâmetros
              dwCreationFlag: DWORD;         // Flags de criação
              var dwThreadID: Cardinal       // Variaval que recebe o ID da thread
              ): Cardinal;

   function DLLCarregada                     // Verifica se uma determinada DLL está carregada
            ( sDLL: string                   // Nome da DLL
              ): Boolean;

   procedure GetDebugPrivs;  // Obtém privilégios de Debug

   procedure VxDCall;                   // Permite chamar uma função de um VXD, no win9x
             external kernel32 index 1; // Ela é exportada pela kernel como indice 1

   var
      bWinNT: Boolean; // Indica se estamos em um Windows baseado no kernel do NT
   
implementation

{****************************************************************************

 DLLCarregada - Retorna Verdadeiro se a DLL passada como parâmetro está
                carregada no processo atual

    sDLL - Módulo utilizado na pesquisa

 **************************************************************************** }

function DLLCarregada( sDLL: string ): Boolean;
var
   hMods    : array[0..1024] of HMODULE;     // Array contendo os módulos
   szModName: array [0..max_path] of Char;   // String para captura do nome do módulo
   hProcess : THandle;                       // Handle do processo
   cbNeeded : DWORD;                         // Variável auxiliar
   nAux     : Integer;                       // Variável auxiliar
begin
   // Pega o Handle do processo ativo
   hProcess := GetCurrentProcess;

   // Inicia a enumeração dos módulos
   if EnumProcessModules( hProcess, @hMods[0], sizeof(hMods), cbNeeded ) then

      // Passa por todos os módulos
      for nAux := 0 to cbNeeded div sizeof( HMODULE ) do

         // Pega o nome do módulo
         if GetModuleFileNameEx( hProcess, hMods[nAux], szModName, sizeof(szModName)) <> 0 then

            // E compara com o módulo passado como parâmetro
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
   VerInfo: TOsversionInfo; // Informações do Sistema Operacional
begin
   // Informa o Sistema Operaciona qual versão da API ele deve utilizar
   VerInfo.dwOSVersionInfoSize := SizeOf( VerInfo );

   // Obtém a versão
   GetVersionEx( VerInfo );

   // Resultado verdadeiro caso a plataforma seja NT
   Result := VerInfo.dwPlatformId = VER_PLATFORM_WIN32_NT;
end;

{****************************************************************************

 GetDebugPrivs - Carrega privilégios de Debug para poder escrever em processos
                 do sistema operacional, em sistemas NT

 **************************************************************************** }

procedure GetDebugPrivs;
const
   // Query que o SO deve executar para obter privilégio de Debug
   SE_DEBUG_NAME = 'SeDebugPrivilege';
var
   hToken: THandle;          // Handle do Token
   tkp   : TTokenPrivileges; // Privilégio
   retval: dword;            // Retorno
begin
   // Inicializa a transação para ajuste de privilégio e execução da query
   if OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or  TOKEN_QUERY, hToken ) then
   begin

      // Inicia a query de ajuste de privilégio
      LookupPrivilegeValue( nil, SE_DEBUG_NAME, tkp.Privileges[0].Luid );

      // Quantas queries vai executar
      tkp.PrivilegeCount := 1;

      // Indica que a query é de ajuste de privilégio
      tkp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;

      // Finalmente executa a query
      AdjustTokenPrivileges( hToken, false, tkp, 0, nil, retval );
   end;
end;

{****************************************************************************

 BmsOpenThread - Abre uma determinada thread e retorna o Handle dela
                 Essa função funciona em todos os windows (ao contrário da
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
   // exportada pelo Kernel, caso contrário utilizaremos nossa própria
   // função.

   if bWinNT then
   begin
      // Como a unit WINDOWS não tem o cabeçalho para a OpenThread
      // temos que pegar o endereço dela diretamente da Kernel32.dll

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

      // Verifica se é um ponteiro válido
      if IsBadReadPtr( pTDB, 4 ) then
         Result := 0
      else
      begin
         // Pega o endereço da OpenProcess
         pOpenProcess := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'OpenProcess' );

         // A verificação abaixo é somente para evitar e arrumar
         // erros do compilador. Então verifica se o inicio da OpenProcess
         // tem um PUSH [endereço]. Caso seja verdadeiro, pega o endereço
         // que ele dá o PUSH e atribue novamente em pOpenProcess.
         // Esse é o EntryPoint real da OpenProcess

         if PByte( pOpenProcess )^ = $68 then
            pOpenProcess := PPointer( Pointer( Cardinal( pOpenProcess ) + 1 ) )^;

         // No começo da OpenProcess, tem um CALL para a função que retorna o
         // ProcessDataBase e move o resultado em EAX. Depois ele verifica
         // se o conteúdo de EAX é um objeto do tipo "Processo de Kernel".
         // Se chamarmos a OpenProcess diretamente essa verificas
         // vai falhar pois estamos trabalhando com ThreadDataBase e nao
         // ProcessDataBase. Então somamos 24 bytes ao EntryPoint da API para
         // pular essas verificações.

         OpenThread := Pointer( Cardinal( pOpenProcess ) + $24 );

         // Aqui finalmente chamamos a OpenProcess sem verificaões e movemos
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

 BmsCreateRemoteThread9x - Emulação do CreateRemoteThread que funciona nas
                           versões 9x do Windows.

    Parametros são os mesmos da CreateRemoteThread

 **************************************************************************** }

function BmsCreateRemoteThread9x( dwProcessId: Cardinal; lpStartAddress: Pointer; lpParameter: Pointer; dwCreationFlag: DWORD; var dwThreadID: Cardinal): Cardinal;
type

   // Dentro da DebugActiveProcess temos que localizar uma "assinatura" para
   // sabermos onde está a função interna do Windows. Essa estrutura é usada
   // para essa localização.

   TPushInterno = packed record
      nPush: Byte;     // $68
      nPara: Cardinal; // $FFFFF000
   end;

var
   pPDB: Pointer;             // Ponteiro para o ProcessDataBase
   pTDB: Pointer;             // Ponteiro para o ThreadDataBase
   fFlags: DWORD;             // Flags utilizada internamente pela IcrThread
   StackSize: Integer;        // Tamanho máximo do Stack
   dObsfucator: Cardinal;     // Obsfucador
   dbgActiveProc: Pointer;    // Endereço da API DebugActiveProcess
   nDist: Cardinal;           // Utlizada no calculo de Distância Relativa
   piEstrutura: TPushInterno; // Estrutura para a "assinatura digital"
   pPesquisa: Pointer;        // Ponteiro para a pesquisa na memória

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

   // StackSize padrão
   StackSize := -$3000;

   // O Windows possui internamente uma função que cria uma Thread remota.
   // A API DebugActiveProcess possui uma chamada para essa função. Então vamos
   // abrir a DebugActiveProcess e pegar esse local
   dbgActiveProc := GetProcAddress( GetModuleHandle( 'kernel32.dll' ), 'DebugActiveProcess' );

   // Se o primeiro byte for $68, então estamos dentro do Debuger, logo
   // a primeira instrução da DebugActiveProcess vai ser um PUSH para o endereço
   // real da mesma. Então pegaremos o local que é atribuído o PUSH
   if PByte( DbgActiveProc )^ = $68 then
      dbgActiveProc := PPointer( Cardinal( dbgActiveProc ) + $1 )^;

   // A partir daqui temos que pesquisar pela sequência 68 00 0F FF FF
   // que servirá como um ponto de referência para a Chamada da função interna
   pPesquisa := dbgActiveProc;

   // Atribui os valores da pesquisa
   piEstrutura.nPush := $68;
   piEstrutura.nPara := $FFFFF000;

   // Pesquisa byte a byte
   while not CompareMem( pPesquisa, @piEstrutura, SizeOf( TPushInterno ) ) do
      Inc( Integer( pPesquisa ) );

   // Depois de ter localizado, sabemos que a função está a 7 bytes p/ frente
   Inc( Integer( pPesquisa ), 7 );
   dbgActiveProc := pPesquisa;

   // Como tudo é feito via CALL relativo, temos que calcular a distância do Call
   nDist := Cardinal( DbgActiveProc^ );

   // Agora atribuímos o InternalCreateRemoteThread com os cálculos da distância
   @IcrThread := Pointer( Cardinal( DbgActiveProc ) - ( $FFFFFFFF - nDist ) + 3 );

   // Ela nos retorna o ThreadDataBase da Thread
   pTDB := IcrThread( pPDB, StackSize, lpStartAddress, lpParameter, fFlags );

   // a partir dela temos o ID, que é calculado efetuando o XOR com o Obsfucator
   dwThreadId := Cardinal( pTDB ) xor dObsfucator;

   // E sucessivamente, o Handle da mesma
   Result := BmsOpenThread(PROCESS_ALL_ACCESS, False, dwThreadId);
end;

{****************************************************************************

 ObterAcessoEscrita9x - O Windows 9x bloqueia acesso a escrita na área
                        de memória compartilhada. Essa função desbloqueia
                        essa área e permite que seja escrito qualquer coisa
                        lá.

    nEnderecoBase - Endereço para desbloquear
    nTamanho      - Quantidade de bytes para desbloquear

 **************************************************************************** }

procedure ObterAcessoEscrita9x( nEnderecoBase: Dword; nTamanho: DWORD );
var
   Endereco: DWord;
begin
   // Incrementa 4096 bytes em nTamanho. 4096 é o tamanho máximo de uma
   // página, então calculamos quantas páginas cabem em nTAMANHO

   Inc( nTamanho, 4096 );
   nTamanho := nTamanho      shr 12;
   Endereco := nEnderecoBase shr 12;

   // Chama a VxdCALL exportado pela Kernel, passando os parâmetros
   // PC_SHARE, PC_USER e PC_WRITEABLE para tornar a página "escrevível"
   // e chama a função _PageModifyPermission
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

 LiberaMem - Lebera memória alocada pela AlocaMem em outro processo

    pEndereco - Endereço para liberar
    nTamanho  - Quantidade de bytes para liberar
    hProcesso - Processo ao qual a memória será liberada

 **************************************************************************** }

function LiberaMem( pEndereco: Pointer; nTamanho: Integer; HProcesso: Cardinal ): Boolean;
begin
   if bWinNT then
      // Se for kernel do NT, libera diretamente no outro processo
      Result := VirtualFreeEx( hProcesso, pEndereco, nTamanho, MEM_DECOMMIT ) <> nil
   else
      // caso contrário libera memória na área de memória compartilhada
      Result := VirtualFree( pEndereco, nTamanho, MEM_DECOMMIT or $8000000 );
end;

{****************************************************************************

 AlocaMem - Aloca memória em outro processo e retorna o ponteiro
            base da memória alocada.

    nTamanho  - Quantidade de bytes para alocar
    hProcesso - Processo ao qual a memória será alocada

 **************************************************************************** }

function AlocaMem( nTamanho: Integer; HProcesso: Cardinal ): Pointer;
begin
   if bWinNT then
      // Se for kernel do NT, aloca diretamente no outro processo
      Result := VirtualAllocEx( hProcesso, nil, nTamanho, MEM_COMMIT, PAGE_READWRITE )
   else
      // caso contrário aloca memória na área de memória compartilhada
      Result := VirtualAlloc( nil, nTamanho, MEM_COMMIT or $8000000, PAGE_READWRITE );
end;

initialization
   // Verifica o tipo do kernel
   bWinNT := winNT;
end.
