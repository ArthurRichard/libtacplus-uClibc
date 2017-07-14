/* -------------------------------------------
 *
 *    tacacs+ client with aaa scenes
 *
 * -------------------------------------------
 */

#include "libtacplus.h"

#define TAC_PORT      10000
#define TAC_TIMEOUT   4


main()
{
   struct session *session;
   char tac_server[50];
   char tac_key[20];
   char port[10];
   char login[128];
   char password[128];
   int i=0;
   char *avpair[255];
   int status;
   char msg[255];
   char data[255];
   char str[100];
   char *aaa;

   printf("          *****  TACACS+ client  *****\n\n");

   /* asking common parameters */
   printf("Input tacacs server host:");
   scanf("%s",tac_server);
   printf("Input tacacs server key:");
   scanf("%s",tac_key);
   printf("Input client port (like tty10 or Async10):");
   scanf("%s",port);
   printf("\n");

   printf("Do you wish authentication (1-yes/2-no)?");
   scanf("%s",str);
   printf("\n",str);

   if (str[0]=='1') {
      printf ("  ************************************\n");
      printf ("  *         AUTHENTICATION           *\n");
      printf ("  ************************************\n\n");

      printf("- Try to connect to tacacs server %s ..... ",tac_server);

      /* initiate connection */
      session=tac_connect(tac_server,TAC_TIMEOUT,tac_key,TAC_PORT);
      if (!session) {
	  printf("Connection error\n");
          return;
      }
      if (session->key)
         printf("Success: %s\n",session->key);

      printf(" - Send authentication start packet ..... ");
      
      if (tac_authen_send_start(session,port,"",TACACS_ASCII_LOGIN,""))
	printf("Success\n");
      else {
	printf("Error (see syslog)\n");
	return;
      }
      printf("- Get reply from server ..... ");
      i=tac_authen_get_reply(session,msg,data);
      printf("%s",tac_print_authen_status(i));
      printf("  msg=[%s], data=[%s]\n\n",msg,data);
      if (i != TAC_PLUS_AUTHEN_STATUS_GETUSER) return;

      printf("Insert username:");
      scanf("%s",login);
      printf("- Send authentication continue packet ...... ");

      if (tac_authen_send_cont(session,login,""))
	  printf("Success\n");
      else {
	printf("Error (see syslog)\n");
	return;
      }
      printf("- Get reply packet ....... ");
      i=tac_authen_get_reply(session,msg,data);
      printf("%s",tac_print_authen_status(i));
      printf("  msg=[%s], data=[%s]\n",msg,data);
      if (i != TAC_PLUS_AUTHEN_STATUS_GETPASS) return;

      printf("Insert password:");
      scanf("%s",password);
      printf("- Send authentication continue packet ....... ");

      if (tac_authen_send_cont(session,password,""))
	  printf("Success\n");
      else {
	printf("Error (see syslog)\n");
	return;
      }
      printf("- Get reply packet ......... ");
      i=tac_authen_get_reply(session,msg,data);
      printf("%s",tac_print_authen_status(i));
      printf("  msg=[%s], data=[%s]\n",msg,data);

      /* now we are disconnect */
      tac_close(session);
   }

   printf("Do you wish authorization (1-yes/2-no)?");
   scanf("%s",str);
   printf("\n",str);

   if (str[0]=='1') {
      printf ("  ************************************\n");
      printf ("  *         AUTHORIZATION            *\n");
      printf ("  ************************************\n\n");

      printf("Insert username (0 for NULL):");
      scanf("%s",login);
      if (strcmp(login,"0")==0) aaa=strdup("");
      else aaa=strdup(login);

aaa:
      /* initiate connection */
      printf("- Try to connect to tacacs server %s ..... ",tac_server);
      if ((session=tac_connect(tac_server,TAC_TIMEOUT,tac_key,TAC_PORT))==NULL)
      {
	  printf("Connection error\n");
	  return;
      }
      printf("Success\n");

      printf ("Input AV-pairs for server, for stop enter 0:\n");
      i=0;
      str[0]='1';
      while (str[0]!='0') {
	 printf("    ");scanf("%s",str);
	 avpair[i++]=strdup(str);
      }
      if (avpair[i-1]) free(avpair[i-1]);
      avpair[i-1]=NULL;

      printf("- Send authorization request packet ...... ");

      if (tac_author_send_request(session,TAC_PLUS_AUTHEN_METH_TACACSPLUS,
	   TAC_PLUS_PRIV_LVL_MIN,TAC_PLUS_AUTHEN_TYPE_ASCII,
	   TAC_PLUS_AUTHEN_SVC_LOGIN,aaa,port,avpair))
	  printf("Success\n");
      else {
	printf("Error (see syslog)\n");
	return;
      }
      tac_free_avpairs(avpair);

      printf("- Get server response ..... ");
      status=tac_author_get_response(session,msg,data,&avpair);

      printf("%s msg=[%s], data=[%s]\n",
	      tac_print_author_status(status),msg,data);
      i=0;
      while(avpair[i]!=NULL)
	  printf ("  AV-pair %s\n",avpair[i++]);
      tac_free_avpairs(avpair);

      /* disconnect */
      tac_close(session);

      printf("Continue authorization? 1-Yes,2-No?");
      scanf("%s",str);
      printf("\n",str);
      if (str[0]=='1') goto aaa;

      free(aaa);
   }

   printf("\n\nDo you wish accounting (1-yes/2-no)?");
   scanf("%s",str);
   printf("\n",str);

   if (str[0]=='1') {
      printf ("  ************************************\n");
      printf ("  *           ACCOUNTING             *\n");
      printf ("  ************************************\n\n");

      printf ("Input AV-pairs for server, for stop enter 0:\n");
      i=0;
      str[0]='1';
      while (str[0]!='0') {
	 printf("    ");scanf("%s",str);
	 avpair[i++]=strdup(str);
      }
      free(avpair[i-1]);
      avpair[i-1]=NULL;

      printf("- Try to connect to tacacs server %s ..... ",tac_server);

      /* initiate connection */
      if ((session=tac_connect(tac_server,TAC_TIMEOUT,tac_key,TAC_PORT))==NULL)
      {
	  printf("Connection error\n");
	  return;
      }
      printf("Success\n");

      printf("Insert username:");
      scanf("%s",login);
      printf("- Send accounting request packet ...... ");

      if (tac_account_send_request(session,TAC_PLUS_ACCT_FLAG_START,
          TAC_PLUS_AUTHEN_METH_TACACSPLUS,
           TAC_PLUS_PRIV_LVL_MIN,TAC_PLUS_AUTHEN_TYPE_ASCII,
	   TAC_PLUS_AUTHEN_SVC_LOGIN,login,port,avpair))
	  printf("Success\n");
      else {
	printf("Error (see syslog)\n");
	return;
      }

      tac_free_avpairs(avpair);

      printf("- Get server reply ..... ");
      status=tac_account_get_reply(session,msg,data);

      /* disconnect */
      tac_close(session);
      printf("%s  msg=[%s], data=[%s]\n",
         tac_print_account_status(status),msg,data);
   }
}
