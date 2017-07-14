/* -------------------------------------------
 *
 *    tacacs+ client with aaa scenes
 *
 * -------------------------------------------
 */

#include "libtacplus.h"

#define TAC_PORT      10000
#define TAC_TIMEOUT   4
#define SERVER		"127.0.0.1"
#define KEY	     "key"
#define PORT		"tst"


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

   printf("          *****  TACACS++ client  *****\n\n");

   while(1) {
      printf ("  ************************************\n");
      printf ("  *         AUTHENTICATION           *\n");
      printf ("  ************************************\n\n");

      printf("- Try to connect to tacacs server %s ..... ",SERVER);

      /* initiate connection */
      session=tac_connect(SERVER,TAC_TIMEOUT,KEY,TAC_PORT);
      if (!session) {
	  printf("Connection error\n");
          return;
      }
      if (session->key)
         printf("Success: %s\n",session->key);

      printf(" - Send authentication start packet ..... ");
      
      if (tac_authen_send_start(session,PORT,"",TACACS_ASCII_LOGIN,""))
	printf("Success\n");
      else {
	printf("Error (see syslog)\n");
	return;
      }
      printf("- Get reply from server ..... ");
      bzero(data,sizeof(data));
      bzero(msg,sizeof(msg));
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
      bzero(data,sizeof(data));
      bzero(msg,sizeof(msg));
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
      bzero(data,sizeof(data));
      bzero(msg,sizeof(msg));
      i=tac_authen_get_reply(session,msg,data);
      printf("%s",tac_print_authen_status(i));
      printf("  msg=[%s], data=[%s]\n",msg,data);

      /* now we are disconnect */
      tac_close(session);
   }
}
