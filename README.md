PuttyRider
==========

Hijack Putty sessions in order to sniff conversation and inject Linux commands.


Help:
=====
	Operation modes:
		-w			Inject in all existing Putty sessions and wait in background for new sessions (and inject in those also)
		-p PID		Inject only in existing Putty session identified by pid then exit PuttyRider immediately
		-d			Debug mode. Do not exit or background. Display in console the messages received from the injected DLL
		-c CMD		Automatically execute a Linux command after successful injection
		-s ?		Get the list of all saved sessions and their information
		-x			Cleanup. Remove the DLL from all running Putty instances
		
	Output modes:
		-f 			Write all conversation to a file in the local directory. The filename will have the pid of current putty.exe appended
		-c IP:PORT	Connect back to the specified machine and start an interactive session.


Client interactive commands (this can be netcat or PuttyRiderClient)
		Linux cmd
		!disco
		!recon
		!exit
		!exitall


