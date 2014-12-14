dll:
		cl /nologo /c PuttyRiderDLL.c Utils.c
		link /nologo /dll /machine:x86 /out:PuttyRider.dll PuttyRiderDLL.obj Utils.obj User32.lib Shlwapi.lib Ws2_32.lib Iphlpapi.lib Psapi.lib
		
main:
		cl /nologo /c PuttyRider.c Utils.c Wingetopt.c
		link /nologo /subsystem:console /machine:x86 PuttyRider.obj Utils.obj Wingetopt.obj User32.lib Shlwapi.lib Ws2_32.lib Iphlpapi.lib Psapi.lib Shell32.lib