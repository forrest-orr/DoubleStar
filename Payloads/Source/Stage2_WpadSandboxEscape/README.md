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

Component

WPAD sandbox escape (stage two shellcode) - WPAD RPC client to inject malicious PAC
JS file into svchost.exe (LOCAL SERVICE).


_______________  JIT spray   ______________  DEP bypass   _______________________
| firefox.exe | -----------> | Egg hunter | ------------> | WPAD sandbox escape |
|_____________|              | shellcode  |               | shellcode (heap)    |
                             |____________|               |_____________________|
~

Overview

This component of the chain will be compiled as a DLL and converted into a shellcode
prior to being encoded in JS and planted into one of the live Firefox or Internet
Explorer RCE. It is designed to initiate an RPC connection to the WPAD service within
svchost.exe (running as LOCAL SERVICE) via ALPC and simulate the functionality of
WINHTTP.DLL!WinHttpGetProxyForUrl (which is itself blocked by the OS). This results
in the WPAD service attempting to download a PAC file (a JS script) from a remote
URL of our choice and execute it in an attempt to update proxy configuration settings.

The PAC itself (on Windows 7 and 8.1) may force the legacy JS engine (jscript.dll)
to be loaded, and exploit it via memory corruption. In the latest version of Windows
10, WPAD has been thoroughly sandboxed: jscript.dll will no longer be loaded and
has been replaced with Chakra. Furthermore, the PAC file itself is now executed
within an extremely locked down child process called pacjsworker.exe which runs
as Low Integrity in conjunction with a slew of additional exploit mitigation systems
such as ACG and CIG. Despite this, access to the WPAD service (and the ability to
coerce it into downloading and running arbitrary JS in the form of PAC files) can
still be done even from most sandboxes (including Firefox and AppContainers) on
the latest Windows 10, thus making WPAD a persistent potential vector for both
sandbox escape and privilege escalation in the future.

When executed via Firefox CVE-2019-17026, this is the second shellcode to be run
as part of this chain and will be found on the heap by the JIT sprayed egg hunter
shellcode, set to +RWX and then executed via a CALL instruction.

When executed via Internet Explorer 11 Enhanced Protected Mode CVE-2020-0674 this
will be the first stage/initial shellcode to be executed, and will result in 
repeated continuous RPC calls to WPAD resulting in multiple payload execution.
This is due to IE11 running as Low Integrity being unable to create the global
event object needed to synchronize this shellcode with the Spool Potato shellcode.

It should also be noted that this code is designed to be run on Windows 8.1 or 10:
the WPAD RPC interface has changed between Windows 7 and 8.1 and the interface
information hardcoded into this client is for 8.1+. Before attempting to use this
client on Windows 7, the IDL file and all relevant interface information for WPAD
must be updated and re-compiled.

~

Design

Of significant note is that throughout my own testing, WPAD has only sporadically
been successful in downloading/running PAC files via this technique: it typically
takes several attempts (several RPC calls via this code) before the desired
logic is executed. For this reason, it was necessary to synchronize this shellcode
with the stage three shellcode (the Spool Potato shellcde) running within WPAD
so that this client could be notified when its RPC call had resulted in shellcode
execution and stop repeatedly making its RPC call.

In order to share the event object between the sandboxed shellcode running as
a regular user account and LOCAL SERVICE, it was placed in the global object
namespace (\BaseNamedObjects) as opposed to the default local namespace in
\Sessions\1\BaseNamedObjects. The ACL for the event object is then modified
to allow access to LOCAL SERVICE, which by default will be unable to interact
with the object.

~

Credits

Hacksys team - they did the reverse engineering and wrote the original PoC
for this technique.
```