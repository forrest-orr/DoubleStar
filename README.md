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

x

~

Overview

x

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