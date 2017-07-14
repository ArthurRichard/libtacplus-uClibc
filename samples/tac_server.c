#include "libtacplus.h"

#define TAC_PORT   0
#define TAC_KEY    "cisco"


main()
{
   int  i,nbytes,nsock;
   char username[128];
   char port[50];
   char rem_addr[17];
   char data[256];
   char password[128];
   int  s,ns,pid;
   struct sockaddr_in serv_addr, clnt_addr;
   int  nsocket;
   int  nport,addrlen;
   struct session *session;
   HDR *hdr;
   char *buf;
   int method, priv_lvl, authen_type, authen_service;
   char *avpair[255];
   int flag;

   nport = htons((u_short)TAC_PORT);
   if ((s=socket(AF_INET,SOCK_STREAM,0))==-1)
   {
       printf("Error calling socket\n");
       return;
   }
   bzero(&serv_addr,sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons((u_short)TAC_PORT);
   if (bind(s,(struct sockaddr *)&serv_addr,sizeof(serv_addr))==-1)
   {
       printf("Error in bind\n");
       return;
   }
   if (listen(s,5)==-1)
   {
       printf("Error in listen\n");
       return;
   }
   while(1) { /* main server cicle */
      addrlen = sizeof(clnt_addr);
      bzero(&clnt_addr,addrlen);
      if ((ns=accept(s,(struct sockaddr *)&clnt_addr,&addrlen))==-1) {
	  printf("Error in accept\n");
	  continue;
      }
      printf("Connect from %s\n",inet_ntoa(clnt_addr.sin_addr));

      session = (struct session *)malloc(sizeof(struct session));
      session->key = strdup(TAC_KEY);
      session->peer = strdup((char*)inet_ntoa(clnt_addr.sin_addr));
      session->sock = ns;
      session->seq_no = 0;
      session->aborted = 0;
      session->version = 0;

      buf=read_packet(session);
      hdr=(HDR*)strdup(buf);

      switch (hdr->type) {
	 /* authentication */
       case TAC_PLUS_AUTHEN:
	  printf(" *** Authentication ***\n");
	  /* get authen start packet */
	  i=tac_authen_get_start_s(buf,session,username,port,rem_addr,data);
	  printf("Receive start packet with type = %d\n",i);
	  printf("user=%s,port=%s,rem_addr=%s\n",username,port,rem_addr);
	  if (strlen(username)==0) {
	      printf("send reply with login request string\n");
	      tac_authen_send_reply(session,TAC_PLUS_AUTHEN_STATUS_GETUSER,
				     "logons:","");
	      i=tac_authen_get_cont(session,username,data);
	      printf("Receive continue packet (%d) with username=%s\n",i,username);
	  }
	  printf("Send reply with password request string\n");
	  tac_authen_send_reply(session,TAC_PLUS_AUTHEN_STATUS_GETPASS,
				 "Passwords:","");
	  tac_authen_get_cont(session,password,data);
	  printf("Receive continue packet with password=%s\n",password);
	  printf("Send reply packet\n");
	  tac_authen_send_reply(session,TAC_PLUS_AUTHEN_STATUS_PASS,"","");
	  break;
       /* authorization */
       case TAC_PLUS_AUTHOR:
	  tac_author_get_request_s(buf,session,&method,&priv_lvl,
	      &authen_type,&authen_service,username,port,rem_addr,
		avpair);
	  i=0;
	  while (avpair[i]!=NULL)
	       printf("  Receive AVpair: %s\n",avpair[i++]);
	  tac_free_avpairs(avpair);
	  avpair[0]="service=tst";
	  avpair[1]=NULL;
	  printf("send response (AC_PLUS_AUTHOR_STATUS_PASS_ADD) to client\n");
	  tac_author_send_response(session,TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
	      "","",avpair);
	  break;
       /* accounting */
       case TAC_PLUS_ACCT:
	  flag=tac_account_get_request_s(buf,session,&method,&priv_lvl,
	       &authen_type,&authen_service,username,port,rem_addr,
	       avpair);
	  i=0;
	  while (avpair[i]!=NULL)
	       printf("  Receive AVpair: %s\n",avpair[i++]);
	  tac_free_avpairs(avpair);
	  printf("send reply TAC_PLUS_ACCT_STATUS_SUCCESS\n");
	  tac_account_send_reply(session,"","",TAC_PLUS_ACCT_STATUS_SUCCESS);
	  break;
       default:
	  printf("*** UNKNOWN PACKET ***\n");
	  break;
      }
      /* закроем соединение */
      printf("Close connection\n\n");
      tac_close(session);
   }
}
