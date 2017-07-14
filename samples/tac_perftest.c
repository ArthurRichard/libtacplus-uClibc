/* -------------------------------------------
 *
 *    tacacs+ perfomance and stress tester
 *
 * -------------------------------------------
 */

/*

you should create users user1,user2,user3,user4 with
passwords pwd1,pwd2,pwd3,pwd4 on tacacs+ server,
also this usersh should have authorization
service=ppp
protocol=ip

for portname i use getpid()

*/

#include <time.h>
#include <sys/timeb.h>
#include <stdlib.h>
#include "libtacplus.h"

#define TAC_PORT      10000
#define TAC_TIMEOUT   4
#define SERVER        "127.0.0.1"
#define KEY           "VoiP"
#define PORT          "tst"

#define TAUTHENTICATION	1
/*#undef TAUTHENTICATION*/
#define TAUTHORIZATION		1
/*#undef TAUTHORIZATION*/
#define TACCOUNTING			1
/*#undef TACCOUNTING*/

#define MAX_USER        4
char users[MAX_USER][6]= {
    {"user1"},
    {"user2"},
    {"user3"},
    {"user4"}
};
char passwd[MAX_USER][6]= {
    {"pwd1"},
    {"pwd2"},
    {"pwd3"},
    {"pwd4"}
};

struct session *tconnect() {
  struct session *sess;
  sess=tac_connect((char*)SERVER,(int)TAC_TIMEOUT,(char*)KEY,(int)TAC_PORT);
  if(!sess) {
    printf("\nConnection error\n");
    exit(1);
  }
  return sess;
}

main()
{
   struct session *session;
   char tac_server[50];
   char tac_key[20];
   char login[128];
   char password[128];
   int i=0,k=0,count=0;
   char *avpair[255];
   char *avp[255];
   char *avpacct[255];
   char *avpaccts[255];
   int status;
   char msg[255];
   char data[255];
   char str[100];
   char str2[100];
   char *aaa;
   char port[32];

   double    old_tm,new_tm;
   struct timeb tb;
		int elapsed;

   avp[0] = strdup("service=ppp");
	 avp[1] = strdup("protocol=ip");
   avp[2] = NULL;

   avpacct[0] = strdup("service=ppp");
	 avpacct[1] = strdup("protocol=ip");
	 avpacct[2] = strdup("addr=10.1.1.1");
	 /*avpacct[3] = strdup("elapsed_time=30");*/
	 /*avpacct[4] = strdup("start_time=");*/
	 /*avpacct[5] = strdup("elapsed_time=30");*/
	 /*avpacct[6] = strdup("start_time=");*/
   avpacct[7] = NULL;

   avpaccts[0] = strdup("service=ppp");
	 avpaccts[1] = strdup("protocol=ip");
	 avpaccts[2] = strdup("addr=10.1.1.1");
   avpaccts[3] = NULL;


   snprintf(port,sizeof(port),"port%d",getpid());

   printf("TACACS+ perfomance meter utility\n");

   ftime(&tb);
   old_tm=new_tm=tb.time*1000 + tb.millitm;


   while(1) {
     count++;
     if(k == MAX_USER) k=0;

#ifdef TAUTHENTICATION
     /***** AUTHENTICATION *****/

     printf("authentication %s/%s (%d) ............ ",users[k],passwd[k],k);

     /* initiate connection */
     session = tconnect();

     if(!tac_authen_send_start(session,port,"",TACACS_ASCII_LOGIN,"")) {
       printf("\nError in tac_authen_send_start (see syslog)\n");
       return;
     }
     bzero(data,sizeof(data));
     bzero(msg,sizeof(msg));
     i=tac_authen_get_reply(session,msg,data);
//printf("%s",tac_print_authen_status(i));
//printf("  msg=[%s], data=[%s]\n",msg,data);
     if(i != TAC_PLUS_AUTHEN_STATUS_GETUSER) {
       printf("\ntac_authen_get_reply != TAC_PLUS_AUTHEN_STATUS_GETUSER and = %d\n",i);
       return;
     }

     if(!tac_authen_send_cont(session,users[k],"")) {
       printf("\nError in send login (see syslog)\n");
       return;
     }
     bzero(data,sizeof(data));
     bzero(msg,sizeof(msg));
     i = tac_authen_get_reply(session,msg,data);
//printf("%s",tac_print_authen_status(i));
//printf("  msg=[%s], data=[%s]\n",msg,data);
     if(i != TAC_PLUS_AUTHEN_STATUS_GETPASS) {
       printf("\ntac_authen_get_reply != TAC_PLUS_AUTHEN_STATUS_GETPASS and = %d\n",i);
       return;
     }

     if(!tac_authen_send_cont(session,passwd[k],"")) {
//     if(!tac_authen_send_cont(session,"pwd1","")) {
       printf("\nError in tac_authen_send_cont (see syslog)\n");
       return;
     }
     bzero(data,sizeof(data));
     bzero(msg,sizeof(msg));
     i=tac_authen_get_reply(session,msg,data);
     printf("%s(%d)",tac_print_authen_status(i),i);
     /*printf("  msg=[%s], data=[%s]\n",msg,data);*/

     /* now we disconnect from */
     tac_close(session);

     ftime(&tb);
     new_tm = tb.time*1000 + tb.millitm;
     printf(" ok - %d ms\n",(unsigned int)(new_tm-old_tm));
     old_tm = new_tm;
//exit(1);
#endif /*TAUTHENTICATION*/


#ifdef TAUTHORIZATION
     /***** AUTHORIZATION *****/

     printf("authorization %s (%d) .................. ",users[k],k);

     /* initiate connection */
     session = tconnect();

     /* authorization */
     if(tac_author_send_request(session,TAC_PLUS_AUTHEN_METH_TACACSPLUS,
           TAC_PLUS_PRIV_LVL_MIN,TAC_PLUS_AUTHEN_TYPE_ASCII,
           TAC_PLUS_AUTHEN_SVC_LOGIN,users[k],port,avp)) {
     } else {
        printf("\nAuthorization error\n");
        return;
     }

     status = tac_author_get_response(session,msg,data,avpair);

     tac_free_avpairs(avpair);
     /* now we disconnect from */
     tac_close(session);

     ftime(&tb);
     new_tm = tb.time*1000 + tb.millitm;
     printf("ok - %d ms (%s)\n",(unsigned int)(new_tm-old_tm),tac_print_author_status(status));
     old_tm = new_tm;

#endif /*TAUTHORIZATION*/


#ifdef TACCOUNTING
     /***** ACCOUNTING START *****/

     printf("accounting start %s (%d) ............... ",users[k],k);

     /* initiate connection */
     session = tconnect();

     if(tac_account_send_request(session,TAC_PLUS_ACCT_FLAG_START,
          TAC_PLUS_AUTHEN_METH_TACACSPLUS,
           TAC_PLUS_PRIV_LVL_MIN,TAC_PLUS_AUTHEN_TYPE_ASCII,
           TAC_PLUS_AUTHEN_SVC_LOGIN,users[k],port,avpaccts)) {
      } else {
        printf("\nAccounting error\n");
        return;
      }

      status=tac_account_get_reply(session,msg,data);

      /* disconnect */
      tac_close(session);

     ftime(&tb);
     new_tm = tb.time*1000 + tb.millitm;
     printf("ok - %d ms (%s)\n",(unsigned int)(new_tm-old_tm),tac_print_account_status(status));
     old_tm = new_tm;


     /***** ACCOUNTING STOP *****/

     printf("accounting stop %s (%d) ................ ",users[k],k);

     /* initiate connection */
     session = tconnect();

		 elapsed = RAND_MAX/rand() * 10;
		 snprintf(str,sizeof(str)-1,"start_time=%d",time(0)-elapsed);
//printf("\nstr=%s\n",str);
		 snprintf(str2,sizeof(str2)-1,"elapsed_time=%d",elapsed);
//printf("\nstr2=%s\n",str2);
		 avpacct[3] = strdup(str);
		 avpacct[4] = strdup(str2);
		 snprintf(str2,sizeof(str2)-1,"bytes_in=%d",RAND_MAX/rand() * 500);
		 avpacct[5] = strdup(str2);
		 snprintf(str2,sizeof(str2)-1,"bytes_out=%d",RAND_MAX/rand() * 900);
		 avpacct[6] = strdup(str2);

     if(tac_account_send_request(session,TAC_PLUS_ACCT_FLAG_STOP,
          TAC_PLUS_AUTHEN_METH_TACACSPLUS,
           TAC_PLUS_PRIV_LVL_MIN,TAC_PLUS_AUTHEN_TYPE_ASCII,
           TAC_PLUS_AUTHEN_SVC_LOGIN,users[k],port,avpacct)) {
     } else {
        printf("\nAccounting error\n");
        return;
     }

		 free(avpacct[3]);
		 free(avpacct[4]);
		 free(avpacct[5]);
		 free(avpacct[6]);

     status=tac_account_get_reply(session,msg,data);

     /* disconnect */
     tac_close(session);

     ftime(&tb);
     new_tm = tb.time*1000 + tb.millitm;
     printf("ok - %d ms (%s)\n",(unsigned int)(new_tm-old_tm),tac_print_account_status(status));
     old_tm = new_tm;
#endif

     k++;
   }
}
