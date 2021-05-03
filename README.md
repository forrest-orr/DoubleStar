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
- CVE-2019-17026 - Firefox 65-69 (64-bit) on Windows 7, 8.1 and 10 x64.

Note that while the individual exploits themselves may work on multiple
versions of Windows, the full chain will only work on Windows 8.1.

~

Overview

The Darkhotel APT group (believed to originate from South Korea) launched a
campaign againt Chinese and Japanese business executives and government officials
through a combination of spear phishing and hacking of luxury hotel networks in
early 2020. The exploits they used (CVE-2020-0674 and CVE-2019-17026, together
dubbed "Double Star") were slight 0day variations of old/existing exploits from
2019: specifically UAF bugs in the legacy JavaScript engine (jscript.dll) and
aliasing bugs in the Firefox IonMonkey engine.

What made the use of these 0day interesting went beyond their ability to achieve
RCE through the Internet Explorer and Firefox web browsers: CVE-2020-0674 in 
particular (a UAF in the legacy jscript.dll engine) is exploitable in any process
in which legacy JS code can be executed via jscript.dll. In late 2017, Google
Project Zero released a blog post entitled "aPAColypse now: Exploiting Windows 10
in a Local Network with WPAD/PAC and JScript" https://googleprojectzero.blogspot.com/2017/12/apacolypse-now-exploiting-windows-10-in_18.html

This research brought to light a very interesting attack vector which (at the
time) affected all versions of Windows from 7 onward: the WPAD service (or
"WinHTTP Web Proxy Auto-Discovery Service") contains an ancient functionality
for updating proxy configurations via a "PAC" file. Any user which can speak
to the WPAD service (running within an svchost.exe process as LOCAL SERVICE) over
RPC can coerce it into downloading a PAC file from a remote URL containing JS
code which is responsible for setting the correct proxy configuration for a user
supplied URL. Most notably, the legacy jscript.dll engine is used to parse these
PAC files. This opened up an attack vector wherein any process (regardless of
limited user privileges or even sandboxing) could connect to the local WPAD
service over ALPC and coerce it into downloading a malicious PAC file containing
a jscript.dll exploit from a remote URL. This would result in code execution in
the context of LOCAL SERVICE.

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
processes via an RPC client - both named pipes and ALPC have APIs which provide
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

This technique combined an old RPC interface popular among Red Teamers for TGT
harvesting in environments with unconstrained delegation enabled (aka the
"Printer Bug") with an impersonation/Rotten Potato style attack adapted for
local privilege escalation. 

Additionally, rather than targeting Windows 7, I decided to focus on Windows 8.1
due to the challenge presented by its enhanced security mitigations such as
non-deterministic LFH, high entropy ASLR and Control Flow Guard (CFG).

~

CVE-2020-0674

Malicious PAC file containing CVE-2020-0674 UAF exploit - downloaded into
the WPAD service svchost.exe (LOCAL SERVICE) via RPC trigger. Contains
stage three shellcode (Spool Potato EoP). This exploit may serve a dual purpose
as an initial RCE attack vector through IE11 64-bit aas well.

_______________  RPC   _______________  CVE-2020-0674   ________________
| firefox.exe | -----> | svchost.exe | ---------------> | Spool Potato |
|_____________|        |_____________|                  | shellcode    |
                                                        |______________|
~

CVE-2019-17026

Firefox 64-bit IonMonkey JIT/Type Confusion RCE. Represents the initial attack
vector when a user visits an infected web page with a vulnerable version of
Firefox. This component contains a stage one (egg hunter) and stage two (WPAD
sandbox escape) shellcode, the latter of which is only effective on Windows 8.1
due to hardcoded RPC IDL interface details for WPAD.

_______________  JIT spray   ______________  DEP bypass   _______________________
| firefox.exe | -----------> | Egg hunter | ------------> | WPAD sandbox escape |
|_____________|              | shellcode  |               | shellcode (heap)    |
                             |____________|               |_____________________|

~

Payloads

This exploit chain has three shellcode payloads, found within this repository
under Payloads\Compiled\JS in their JavaScript encoded shellcode form:
- Stage one: egg hunter shellcode (ASM).
- Stage two: WPAD sandbox escape shellcode (C DLL, sRDI to shellcode).
- Stage three: Spool Potato privilege escalation shellcode (C DLL, sRDI to
  shellcode).

When IE is used as the initial RCE attack vector, only the stage two and three
shellcodes are needed. When FF is used as the initial RCE attack vector, all
three are used.

I've also included several additional shellcodes for testing purposes (a
MessageBoxA and WinExec shellcode). Note when using these that in the case of
Firefox CVE-2019-17026, the shellcode should be represented as a Uint8Array
prefixed by the following egg QWORD: 0x8877665544332211. In the case of
CVE-2020-0674, the shellcode should be represented as a DWORD array.

Also note that when using a WinExec or MessageBoxA payload in conjunction with
Firefox CVE-2019-17026, you must adjust the sandbox content level in the
"about:config" down to 2 first. 

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