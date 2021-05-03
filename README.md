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

To run this exploit chain, download the full repo/folder structure to an
unpatched Windows 8.1 x64 machine and load either of these two .html
files while connected to the internet:
- CVE-2019-17026\Forrest_Orr_CVE-2019-17026_64-bit.html - via Firefox v65-69
  64-bit.
- CVE-2020-0674\Forrest_Orr_CVE-2020-0674_64-bit.html - via Internet Explorer
  11 64-bit (Enhanced Protected Mode enabled).
  
The initial RCE may be run through either IE or FF, and will result in the
execution of a cmd.exe process to your user session with NT AUTHORY\SYSTEM
privileges.

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
time) affected all versions of Windows from 7 onward. 


~

CVE-2020-0674

x

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