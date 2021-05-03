```
________                 ___.    .__                 _________  __
\______ \    ____   __ __\_ |__  |  |    ____       /   _____/_/  |_ _____  _______
 |    |  \  /  _ \ |  |  \| __ \ |  |  _/ __ \      \_____  \ \   __\\__  \ \_  __ \
 |    `   \(  <_> )|  |  /| \_\ \|  |__\  ___/      /        \ |  |   / __ \_|  | \/
/_______  / \____/ |____/ |___  /|____/ \___  >    /_______  / |__|  (____  /|__|
        \/                    \/            \/             \/             \/
Windows 7/8.1 IE/Firefox RCE -> Sandbox Escape -> SYSTEM EoP Exploit Chain

                        ______________
                        | Remote PAC |
                        |____________|
                               ^
                               | HTTPS
_______________   RPC   _______________   RPC   _______________
| firefox.exe | ------> | svchost.exe | ------> | spoolsv.exe |
|_____________|         |_____________| <------ |_____________|
                               |          Pipe
                               |
           _______________     |
           | malware.exe | <---| Execute impersonating NT AUTHORY\SYSTEM
           |_____________|

~

Component

Final stage three shellcode designed to escalate privileges from LOCAL SERVICE
within the WPAD service to SYSTEM via the RPC print spooler bug.

_______________  CVE-2020-0674   __________________________  RPC   _______________
| svchost.exe | ---------------> | Spool Potato shellcode | -----> | spoolsv.exe |
|_____________|                  |________________________| <----- |_____________|
                                               |             Pipe
                                               |
                           _______________     |
                           | malware.exe | <---| Execute impersonating NT AUTHORY\SYSTEM
                           |_____________|

~

Overview

This source is designed to be compiled as a DLL and converted to a
shellcode prior to being planted into CVE-2020-0674 to be run via UAF
as a stage three shellcode to complete the exploit chain. It is utilizing
a combination of two techniques: the RPC printer bug (which allows an
arbitrary user/machine to request authentication via RPC named pipe to the
spoolss RPC endpoint of an arbitrary machine) and a potato-style impersonation
attack. 

Fundamentally, this shellcode is abusing the fact that the WPAD service is
running as LOCAL SERVICE, which is granted the (normally restricted)
SeImpersonate privilege by default. This privilege allows the WPAD process
to impersonate the security context of any RPC/named pipe client that connects
to it.

Additional information on the technique and its details can be found here:
https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

~

Credits

itm4n - for the original research on combining the RPC printer bug with named pipe
        impersonation.
```