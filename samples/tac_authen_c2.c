/*
    client with reduced authentication scene
*/

#include "libtacplus.h"

/* REPLACE WITH YOUR INFORMATION ! */
#define TAC_LOGIN     "my_login"
#define TAC_PASSWORD  "my_password"
#define PORT          "tty10"
#define TYPE          TACACS_ASCII_LOGIN
#define TAC_PORT      0
#define TAC_KEY       "Cisco"
#define TAC_SERVER    "127.0.0.1"
#define TAC_TIMEOUT   4


main()
{
   char serv_msg[256];
   char data_msg[256];
   struct session *session;
   int i;

   /* initiate connection */
   if ((session=tac_connect(TAC_SERVER,TAC_TIMEOUT,TAC_KEY,TAC_PORT))==NULL)
   {
       printf("Connection error\n");
       return;
   }

 /*** authentication ***/
   printf("*** Send: start packet port=%s, username=%s ***\n",PORT,TAC_LOGIN);
   tac_authen_send_start(session,PORT,TAC_LOGIN,TACACS_ASCII_LOGIN,"");
   i=tac_authen_get_reply(session,serv_msg,data_msg);
   printf("*** Reply: %s, msg=%s, data=%s ***\n",tac_print_authen_status(i),serv_msg,data_msg);
   printf("*** Send: password string=%s ***\n",TAC_PASSWORD);
   tac_authen_send_cont(session,TAC_PASSWORD,"");
   i=tac_authen_get_reply(session,serv_msg,data_msg);
   printf("*** Reply: %s, msg=%s, data=%s ***\n",tac_print_authen_status(i),serv_msg,data_msg);
   /* now we are disconnect */
   tac_close(session);
}
