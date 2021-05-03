```
________                 ___.    .__                 _________  __
\______ \    ____   __ __\_ |__  |  |    ____       /   _____/_/  |_ _____  _______
 |    |  \  /  _ \ |  |  \| __ \ |  |  _/ __ \      \_____  \ \   __\\__  \ \_  __ \
 |    `   \(  <_> )|  |  /| \_\ \|  |__\  ___/      /        \ |  |   / __ \_|  | \/
/_______  / \____/ |____/ |___  /|____/ \___  >    /_______  / |__|  (____  /|__|
        \/                    \/            \/             \/             \/
Windows 8.1 IE/Firefox RCE -> Sandbox Escape -> SYSTEM EoP Exploit Chain

                            ______________
                            | Remote PAC | 
                            |____________|  
                                   ^
                                   | HTTPS
_______________  RPC/ALPC   _______________   RPC/ALPC   _______________
| firefox.exe | ----------> | svchost.exe | -----------> | spoolsv.exe |
|_____________|             |_____________| <----------- |_____________|
                                   |          RPC/Pipe
                                   |
               _______________     | 
               | malware.exe | <---| Execute impersonating NT AUTHORY\SYSTEM
               |_____________|

~

Usage

To run this exploit chain, download the full release/folder structure to an
unpatched Windows 8.1 x64 machine and load either of these two .html files
while connected to the internet:
- CVE-2019-17026\Forrest_Orr_CVE-2019-17026_64-bit.html - via Firefox v65-69
  64-bit.
- CVE-2020-0674\Forrest_Orr_CVE-2020-0674_64-bit.html - via Internet Explorer
  11 64-bit (Enhanced Protected Mode enabled).
  
The initial RCE may be run through either IE or FF, and will result in the
execution of a cmd.exe process to your user session with NT AUTHORY\SYSTEM
privileges.

The individual exploits have been successfully tested in the following context:
- CVE-2020-0674 - IE8 64-bit and WPAD on Windows 7 x64, IE11 64-bit and WPAD
  on Windows 8.1 x64.
- CVE-2019-17026 - Firefox 65-69 (64-bit) on Windows 7, 8.1 and 10.

Note that while the individual exploits themselves may work on multiple
versions of Windows, the full chain will only work on Windows 8.1, and the
reason is as follows: this chain utilizes 2 RPC clients (executed in the form
of shellcode) whose IDL/interface details are invalid on Windows 7. Both of
these shellcodes are essential for the exploit chain to move beyond the
compromised browser process and as a result the chain will not work (although
the individual CVE will independent of one another). Furthermore, when it comes
to Windows 10, significant security enhancements over the past few years have
rendered various aspects of this exploit chain infeasible (although not
objectively impossible) within the scope of this project. Specifically, Windows
10 has a hardened Control Flow Guard exploit mitigation which prevents the RIP
hijack technique (itself a CFG bypass on Windows 8.1) in CVE-2020-0674,
rendering it useless. Furthermore, the introduction of heavy WPAD service
sandboxing on recent versions of Windows 10 render the use of CVE-2020-0674
(even in the event that a more sophisticated CFG were implemented for it)
infeasible for the sandbox escape component of the exploit chain via WPAD.

~

Overview

The Darkhotel APT group (believed to originate from South Korea) launched a
campaign againt Chinee and Japanese business executives and government officials
through a combination of spear phishing and hacking of luxury hotel networks in
early 2020, taking advantage of Microsoft's decision to discontinue support for
Windows 7. The exploits they used (CVE-2020-0674 and CVE-2019-17026, together
dubbed "Double Star") were slight 0day variations of old/existing exploits from
2019: specifically UAF bugs in the legacy JavaScript engine (jscript.dll) and
aliasing bugs in the Firefox IonMonkey engine.

What made the use of these 0day interesting went beyond their ability to achieve
RCE through the Internet Explorer and Firefox web browsers: CVE-2020-0674 in 
particular (a UAF in the legacy jscript.dll engine) is exploitable in any process
in which legacy JS code can be executed via jscript.dll. In late 2017, Google
Project Zero released a blog post entitled "aPAColypse now: Exploiting Windows 10
in a Local Network with WPAD/PAC and JScript"
https://googleprojectzero.blogspot.com/2017/12/apacolypse-now-exploiting-windows-10-in_18.html

This research brought to light a very interesting attack vector which (at the
time) affected all versions of Windows from 7 onward: the WPAD service (or
"WinHTTP Web Proxy Auto-Discovery Service") contains an ancient functionality
for updating proxy configurations via a "PAC" file. Any user which can speak
to the WPAD service (running within a LOCAL SERVICE svchost.exe process) over
RPC can coerce it into downloading a "PAC" file from a remote URL containing JS
code which is responsible for setting the correct proxy configuration for a user
supplied URL. Most notably, due to the highly antiquated/legacy nature of these
PAC files they were often expected to be written in old versions of JavaScript
which called for use of the legacy jscript.dll engine to parse. This opened up
an attack vector wherein any process (regardless of limited user privileges or
even sandboxing) could connect to the local WPAD service over ALPC and coerce it
into downloading a malicious PAC file containing a jscript.dll exploit from a
remote URL. This would result in code execution in the context of LOCAL SERVICE.

Darkhotel took this concept and used it as their sandbox escape after they
obtained RCE via Firefox or Internet Explorer. The next step in their attack
chain is unclear: it appears that they somehow elevated their privileges from
LOCAL SERVICE to SYSTEM and proceeded to execute their malware from this context.
In all of the analysis of the Darkhotel Double Star attack chain, I was not able
to find a detailed explanation of how they achieved this, however it is safe to
assume that their technique need not have been a 0day exploit. Processes launched
by the LOCAL SERVICE account are provided with the SeImpersonate privilege by 
default (a sensitive privilege which allows its owner to impersonate the security
context of any user whose token they can obtain/forge, or who connects to their
processes via an RPC client (both named pipes and ALPC have APIs which provide
impersonation functionality).

When adapting my own variation of the Double Star exploit chain, my initial
plan was to utilize a Rotten Potato style attack to escalate my privileges from
LOCAL SERVICE to SYSTEM. However, Rotten Potato (which utilizes a port binding
in conjunction with a coerced connection/NTLM authentication from the SYSTEM
account to generate a security context it then impersonates) had recently had
its most popular method to coerce network authentication from the SYSTEM account
patched by Microsoft, and I settled on a more robust/modern technique recently
publicized by itm4n instead:
https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

This technique combined an old RPC primitive popular among Red Teamers for TGT
harvesting in environments with unconstrained delegation enabled (aka the
"Printer Bug") with an impersonation/Rotten Potato style attack adapted for
local privilege escalation. 


~

CVE-2020-0674

This is a 64-bit adaptation of CVE-2020-0674 which can exploit both IE8/11
64-bit as well as the WPAD service on Windows 7 and 8.1 x64. It has bypasses
for DEP, ASLR, and CFG. It uses dynamic ROP chain creation for its RIP
hijack and stack pivot. Notably, this exploit does not contain bypasses for
Windows Exploit Guard or EMET 5.5 and does not work on IE11 or WPAD in
Windows 10.

The UAF is a result of two untracked variables passed to a comparator for the
Array.sort method, which can then be used to reference VAR structs within
allocated GcBlock regions which can subsequently be freed via garbage
collection. Control of the memory of VAR structs with active JS var
references in the runtime script is then used for arbitrary read (via BSTR)
and addrof primitives.

Ultimately the exploit aims to use KERNEL32.DLL!VirtualProtect to disable DEP
on a user defined shellcode stored within a BSTR on the heap. This is achieved
through use of NTDLL.DLL!NtContinue, an artificial stack (built on the heap)
and a dynamically resolved stack pivot ROP gadget.

NTDLL.DLL!NtContinue --------------------> RIP = <MSVCRT.DLL!0x00019baf> | MOV RSP, R11; RET
                                           RCX = Shellcode address
                                           RDX = Shellcode size
                                           R8 = 0x40
                                           R9 = Leaked address of BSTR to hold out param    
                                           RSP = Real stack pointer             
                                           R11 = Artificial stack
|-----------------------------|            ^
| 2MB stack space (heap)      |            |
|-----------------------------|            |
| Heap header/BSTR len align  |            |
|-----------------------------|            |
| KERNEL32.DLL!VirtualProtect | <----------|
|-----------------------------|
| Shellcode return address    ]
|-----------------------------|   

The logic flow is:
1. A fake object with a fake vtable is constructed containing the address
   of NTDLL.DLL!NtContinue as its "typeof" method pointer. This primitive
   is used for RIP hijack in conjunction with a pointer to a specially
   crafted CONTEXT structure in RCX as its parameter. 
2. NtContinue changes RIP to a stack pivot gadget and sets up the parameters
   to KERNEL32.DLL!VirtualProtect.
3. The address of VirtualProtect is the first return address to be
   consumed on the new (artificial) stack after the stack pivot.
4. VirtualProtect disables DEP on the shellcode region and returns to that
   same (now +RWX) shellcode address stored as the second return address on
   the pivoted stack.
   
Notably, the stack pivot was needed here due to the presence of CFG on
Windows 8.1, which prevents NtContinue from being used to change RSP to an
address which falls outside the stack start/end addresses specified in the
TEB. On Windows 7 this is a non-issue. Furthermore, it required a leak of RSP
to be planted in the CONTEXT structure so that NtContinue would consider its
new RSP valid.

The exploit will not work on Windows 10 due to enhanced protection by CFG:
Windows 10 has blacklisted NTDLL.DLL!NtContinue to CFG by default.

~

CVE-2019-17026

x

~

Payloads

x

~

Credits

maxspl0it     - for writing the initial analysis and PoC for CVE-2019-17026
                with a focus on the Linux OS, and for writing the initial
                analysis and PoC for CVE-2020-0674 with a focus on IE8/11 on
                Windows 7 x64.
            
0vercl0k      - for documenting IonMonkey internals in relation to aliasing and
                the GVN.

HackSys Team  - for tips on the WPAD service and low level JS debugging.

itm4n         - for the original research on combining the RPC printer bug with
                named pipe impersonation.

```