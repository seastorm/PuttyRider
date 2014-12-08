dll:
		cl /nologo /c PuttyRiderDLL.c Utils.c
		link /nologo /dll /out:PuttyRider.dll PuttyRiderDLL.obj Utils.obj User32.lib Shlwapi.lib Ws2_32.lib Iphlpapi.lib Psapi.lib
		
main:
		cl /nologo /c PuttyRider.c Utils.c Wingetopt.c
		link /nologo /SUBSYSTEM:CONSOLE PuttyRider.obj Utils.obj Wingetopt.obj User32.lib Shlwapi.lib Ws2_32.lib Iphlpapi.lib Psapi.lib Shell32.lib