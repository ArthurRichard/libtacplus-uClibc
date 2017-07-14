#include "libtacplus.h"

/* REPLACE WITH YOUR PARAMETERS FIRST ! */
#define TAC_SERVER   "127.0.0.1"
#define TAC_TIMEOUT  5
#define TAC_KEY      "Cisco"
#define TAC_PORT     0
#define USER     "username"
#define PORT     "my_port_10"


main() {
   struct session *s;
   int i=0;
   char *avpair[255];
   int status;
   char msg[255];
   char data[255];

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

   tac_author_send_request(s,TAC_PLUS_AUTHEN_METH_TACACSPLUS,
	 TAC_PLUS_PRIV_LVL_MIN,TAC_PLUS_AUTHEN_TYPE_ASCII,
	 TAC_PLUS_AUTHEN_SVC_LOGIN,USER,PORT,avpair);

   tac_free_avpairs(avpair);

   status=tac_author_get_response(s,msg,data,&avpair);
   tac_close(s);
   printf("Server response: %s msg=%s, data=%s\n",
	      tac_print_author_status(status),msg,data);
   i=0;
   while(avpair[i]!=NULL)
     printf ("  AV-pair %s\n",avpair[i++]);
   tac_free_avpairs(avpair);
}
