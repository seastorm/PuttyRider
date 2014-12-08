/*
POSIX getopt for Windows
http://note.sonots.com/Comp/CompLang/cpp/getopt.html

AT&T Public License

Code given out at the 1985 UNIFORUM conference in Dallas.  
*/

#ifndef __GNUC__

#include "Wingetopt.h"
#include <stdio.h>


int	opterr = 1;
int	optind = 1;
int	optopt;
char *optarg;

int
getopt(argc, argv, opts)
int	argc;
char	**argv, *opts;
{
	static int sp = 1;
	register int c;
	register char *cp;
	if(sp == 1)
		if(optind >= argc ||
		   argv[optind][0] != '-' || argv[optind][1] == '\0')
			return(-1);
		else if(strcmp(argv[optind], "--") == 0) {
			optind++;
			return(-1);
		}
	optopt = c = argv[optind][sp];
	if(c == ':' || (cp=(char*)strchr(opts, c)) == NULL) {
		//ERR(": illegal option -- ", c);
		if(argv[optind][++sp] == '\0') {
			optind++;
			sp = 1;
		}
		return('?');
	}
	if(*++cp == ':') {
		if(argv[optind][sp+1] != '\0')
			optarg = &argv[optind++][sp+1];
		else if(++optind >= argc) {
			//ERR(": option requires an argument -- ", c);
			sp = 1;
			return('?');
		} else
			optarg = argv[optind++];
		sp = 1;
	} else {
		if(argv[optind][++sp] == '\0') {
			sp = 1;
			optind++;
		}
		optarg = NULL;
	}
	return(c);
}

#endif  /* __GNUC__ */