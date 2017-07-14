#include <stdlib.h>
#include "libtacplus.h"

#define MAXHOST 5   /* maximum tacacs+ servers */

char *peer[MAXHOST];  /* servers */
char *timeout;        /* timeout */
char *key;            /* tacacs+ key */

struct server *tac_server;

/* initialisation
    num - number of tacacs+ servers
*/
void
tac_clnt_init(int num) {
    tac_server=(struct server *)malloc(sizeof (struct server) * num);
}
/* free */
void
tac_clnt_free() {
    free(tac_server);
}
/* add server to list */
void
tac_clnt_add_server(char *ip,char *key,int mode,int num) {
}

/* read config file
     1 - success
     0 - error
*/
static int
tac_clnt_readconf()
{
  FILE *cf;
  char buf[256];
  char *s1, *v1;
  int j=0;

  timeout=strdup("10");

  if ((cf = fopen(TAC_CLIENT_CONFIG, "r")) == NULL) return 0;
  while(fgets(buf, 256, cf) != NULL) {
     if (buf[0]==0) continue;
     if (buf[0]=='#') continue;
     s1 = strtok(buf, " =\t\n");
     v1 = strtok(NULL, " =\t\n");
     if (s1==NULL || v1==NULL) continue;
     if (!strcmp(s1, "server"))
     {
       if (j < MAXHOST)
	   peer[j++] = strdup(v1);
       peer[j]=NULL;
     }
     if (!strcmp(s1, "key")) key = strdup(v1);
     if (!strcmp(s1, "timeout")) timeout = strdup(v1);
  }
  fclose(cf);
  return 1;
}

int
tacacs_plus_auth(char *user,char *password,char *port,char *service) {
  int a;
  char str[50];
  int i=0;
  char  serv_msg[256];
  char  data_msg[256];
  struct session *session;
  char *avpair[10];

  strncpy(str,user,sizeof(str));

  tac_clnt_readconf();

  a=0; i=0;
  while(i<MAXHOST && peer[i]!=NULL && a!=TAC_PLUS_AUTHEN_STATUS_PASS)
  {
     if ((session=tac_connect(peer[i],atoi(timeout),key,0))==NULL)
     {
	i++;
	continue;
     }
     /* authentication */
     tac_authen_send_start(session,port,user,TACACS_ASCII_LOGIN,"");
     a=tac_authen_get_reply(session,serv_msg,data_msg);
     tac_authen_send_cont(session,password,"");
     a=tac_authen_get_reply(session,serv_msg,data_msg);
     tac_close(session);
     if (a != TAC_PLUS_AUTHEN_STATUS_PASS) return 0;
     if (strlen(service)==0) return 1; /* no authorization */
     a=0;
     /* authorization */
     if ((session=tac_connect(peer[i],atoi(timeout),key,0))==NULL)
	return 0;
     snprintf(str,sizeof(str),"service=%s",service);
     avpair[0]=strdup(str);
     avpair[1]=NULL;
     tac_author_send_request(session,TAC_PLUS_AUTHEN_METH_TACACSPLUS,
	 TAC_PLUS_PRIV_LVL_MIN,TAC_PLUS_AUTHEN_TYPE_ASCII,
	 TAC_PLUS_AUTHEN_SVC_LOGIN,user,port,avpair);
     tac_free_avpairs(avpair);
     a=tac_author_get_response(session,serv_msg,data_msg,(char**)&avpair);
     tac_close(session);
     tac_free_avpairs(avpair);
     if (a != TAC_PLUS_AUTHOR_STATUS_PASS_ADD) return 0;
     return 1;
  }
  return 0;
}

int
tacacs_plus_author(char *user,char *port,char *service) {
  int a;
  char str[50];
  int i=0;
  char  serv_msg[256];
  char  data_msg[256];
  struct session *session;
  char *avpair[10];

  strncpy(str,user,sizeof(str));

  tac_clnt_readconf();

  a=0; i=0;
  while(i<MAXHOST && peer[i]!=NULL)
  {
     if ((session=tac_connect(peer[i],atoi(timeout),key,0))==NULL)
     {
	i++;
	continue;
     }
     snprintf(str,sizeof(str),"service=%s",service);
     avpair[0]=strdup(str);
     avpair[1]=NULL;
     tac_author_send_request(session,TAC_PLUS_AUTHEN_METH_TACACSPLUS,
	 TAC_PLUS_PRIV_LVL_MIN,TAC_PLUS_AUTHEN_TYPE_ASCII,
	 TAC_PLUS_AUTHEN_SVC_LOGIN,user,port,avpair);
     tac_free_avpairs(avpair);
     a=tac_author_get_response(session,serv_msg,data_msg,(char**)&avpair);
     tac_close(session);
     tac_free_avpairs(avpair);
     if (a != TAC_PLUS_AUTHOR_STATUS_PASS_ADD) return 0;
     return 1;
  }
  return 0;
}
