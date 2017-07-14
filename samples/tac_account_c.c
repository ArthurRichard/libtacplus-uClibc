#include "libtacplus.h"

/*** REPLACE WITH YOUR PARAMETERS FIRST ! ***/
#define TAC_SERVER   "10.1.1.1"
#define TAC_TIMEOUT   5
#define TAC_KEY      "Cisco"
#define TAC_PORT      0
#define PORT         "my_port"
#define USER         "username"

main()
{
   struct session *s;
   char *avpair[256];
   char data[256];
   char msg[256];   
   int status;

   /* initiate connection */
   if ((s=tac_connect(TAC_SERVER,TAC_TIMEOUT,TAC_KEY,TAC_PORT))==NULL)
   {
       printf("Connection error\n");
       return;
   }
   
   avpair[0]=strdup("service=ppp");
   avpair[1]=strdup("protocol=ip");
   avpair[2]=strdup("addr-pool*DIALUP");
   avpair[3]=NULL;

   tac_account_send_request(s,TAC_PLUS_ACCT_FLAG_START,
	TAC_PLUS_AUTHEN_METH_TACACSPLUS,
         TAC_PLUS_PRIV_LVL_MIN,TAC_PLUS_AUTHEN_TYPE_ASCII,
         TAC_PLUS_AUTHEN_SVC_LOGIN,USER,PORT,avpair);
   tac_free_avpairs(avpair);
   status=tac_account_get_reply(s,msg,data);
   tac_close(s);
   printf("Server response: %s  msg=%s, data=%s\n",
       tac_print_account_status(status),msg,data);
}
