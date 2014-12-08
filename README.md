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



