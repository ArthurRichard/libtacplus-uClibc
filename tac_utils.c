#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include "libtacplus.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "md5.h"

/*#if 0*/
int tac_error(const char *format, ...) {
	va_list	ap;
	int	result;
	char	errmsg[256];

	va_start(ap, format);
#if USE_SYSLOG
	result = vsnprintf(errmsg, sizeof(errmsg), format, ap);
	syslog (LOG_DAEMON, "libtacacs: %s", errmsg);  
#else
	result = vfprintf(stderr, format, ap);
#endif
	va_end(ap);
	return result;
}
/*#endif*/

/*
	tac_getipfromname - get string like xxx.xxx.xxx.xxx from name name.domain.ru
		name    name to resolve
	return
		string containing IP address
		NULL    FAILURE
*/
/*
char* tac_getipfromname(const char *name) {
   struct    in_addr  nas_addr;
   struct   hostent *host;
   static   char hostaddr[40];
   
   memset(hostaddr, 0, 40);
   host = gethostbyname(name);
   if (host == NULL) {
	tac_error("gethostbyname(%s) failure\n", name);
	strcpy(hostaddr, "0.0.0.0");
	return hostaddr;
   }
   memcpy((char *)&nas_addr, host->h_addr, host->h_length);
   strcpy(hostaddr, (char*)inet_ntoa(nas_addr));
   printf("NAME: %s, IP: %s\n", name, hostaddr);
  
   return (hostaddr);
}*/

char* tac_getipfromname(const char *name) {
    static   char hostaddr[40];
    char   buf[512];		//May need to be increased if needed
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    struct sockaddr_in *addr;
    
    int sfd, s, j;
    size_t len;
    ssize_t nread;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;    
    hints.ai_socktype = SOCK_STREAM; 
    hints.ai_flags = 0;
    hints.ai_protocol = 0;        

    s = getaddrinfo(name, NULL, &hints, &result);
    if (s != 0) {
        tac_error("getaddrinfo(%s) failure\n", name);
	printf("getaddrinfo %s\n", strerror(errno));
        printf("getaddrinfo : %s \n", gai_strerror(s));
        strcpy(hostaddr, "0.0.0.0");
	return hostaddr;
    }
    addr = (struct sockaddr_in *)result->ai_addr;
    strcpy(hostaddr, inet_ntoa((struct in_addr)addr->sin_addr));
    //printf("IP: %s\n", hostaddr);
    return hostaddr;
}

/*
   this function translate tacacs server authenticaton reply status
   to string
*/
char*
tac_print_authen_status(int status) {

   switch(status) {
   case 1:
      return("TAC_PLUS_AUTHEN_STATUS_PASS");
      break;
   case 2:
      return("TAC_PLUS_AUTHEN_STATUS_FAIL");
      break;
   case 3:
      return("TAC_PLUS_AUTHEN_STATUS_GETDATA");
      break;
   case 4:
      return("TAC_PLUS_AUTHEN_STATUS_GETUSER");
      break;
   case 5:
      return("TAC_PLUS_AUTHEN_STATUS_GETPASS");
      break;
   case 6:
      return("TAC_PLUS_AUTHEN_STATUS_RESTART");
      break;
   case 7:
      return("TAC_PLUS_AUTHEN_STATUS_ERROR");
      break;
   case 0x21:
      return("TAC_PLUS_AUTHEN_STATUS_FOLLOW");
      break;
   default:
      return("Unknown status");
      break;
  }
  return(NULL);
}


/* free avpairs array */
void
tac_free_avpairs(char **avp) {
   int i=0;
   while (avp[i]!=NULL) free(avp[i++]);
}


/* translate authorization status to string */
char*
tac_print_author_status(int status) {
      switch(status) {
       case TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
	  return("TAC_PLUS_AUTHOR_STATUS_PASS_ADD");
	  break;
       case TAC_PLUS_AUTHOR_STATUS_PASS_REPL:
	  return("TAC_PLUS_AUTHOR_STATUS_PASS_REPL");
	  break;
       case TAC_PLUS_AUTHOR_STATUS_FAIL:
	  return("TAC_PLUS_AUTHOR_STATUS_FAIL");
	  break;
       case TAC_PLUS_AUTHOR_STATUS_ERROR:
	  return("TAC_PLUS_AUTHOR_STATUS_ERROR");
	  break;
       case TAC_PLUS_AUTHOR_STATUS_FOLLOW:
	  return("TAC_PLUS_AUTHOR_STATUS_FOLLOW");
	  break;
       default:
	  return("Unknown");
	  break;
      }
      return(NULL);
}

/* translate accounting status to string */
char*
tac_print_account_status(int status) {
	switch (status) {
	  case TAC_PLUS_ACCT_STATUS_SUCCESS:
		return("TAC_PLUS_ACCT_STATUS_SUCCESS");
		break;
	  case TAC_PLUS_ACCT_STATUS_ERROR:
		return("TAC_PLUS_ACCT_STATUS_ERROR");
		break;
	  case TAC_PLUS_ACCT_STATUS_FOLLOW:
		return("TAC_PLUS_ACCT_STATUS_FOLLOW");
		break;
	  default:
		return("UNKNOWN");
		break;
	}
	return(NULL);
}

/*
/////////////////////////////////////////////
// ������� ������, ���������� �� NAS� � �������
// ���������� �� ����. ���� �� �������� ������ ���������
// ������ ��������� �� MD5 digest (��� CHAP)
//
// compare_password(password from base,password from nas)
//   return 0 - not equal, 1 - equal
*/
int
compare_password(char* pwduser, char* pwdnas) {
    char *secret, *chal, digest[MD5_LEN];
    u_char *mdp;
    char id;
    int chal_len, inlen;
    MD5_CTX mdcontext;

    if (strcmp(pwduser,pwdnas)==0) return 1;
    id=pwdnas[0];
    chal_len=strlen(pwdnas)-1-MD5_LEN;
    if (chal_len < 0) return(0);
    /* We now have the secret, the id, and the challenge value. Put them all
     * together, and run them through the MD5 digest algorithm. */
    inlen = sizeof(u_char) + strlen(pwduser) + chal_len;
    mdp = (u_char *) malloc(inlen);
    mdp[0] = id;
    memcpy(&mdp[1], secret, strlen(pwduser));
    chal = pwdnas + 1;
    memcpy(mdp + strlen(pwduser) + 1, chal, chal_len);
    MD5Init(&mdcontext);
    MD5Update(&mdcontext, mdp, inlen);
    MD5Final((u_char *) digest, &mdcontext);
    free(mdp);
    /* Now compare the received response value with the just calculated
     * digest value.  If they are equal, it's a pass, otherwise it's a
     * failure */
    if (memcmp(digest, pwdnas + 1 + chal_len, MD5_LEN))
       return 0;
    else
       return 1;
}
