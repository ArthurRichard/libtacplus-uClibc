#include "libtacplus.h"


/*
   send the accounting REQUEST  (client function)
*/
#define TAC_ACCT_REQ_FIXED_FIELDS_SIZE 9
struct acct {
    u_char flags;
    u_char authen_method;
    u_char priv_lvl;
    u_char authen_type;
    u_char authen_service;
    u_char user_len;
    u_char port_len;
    u_char rem_addr_len;
    u_char arg_cnt; /* the number of cmd args */
    /* one u_char containing size for each arg */
    /* <user_len bytes of char data> */
    /* <port_len bytes of char data> */
    /* <rem_addr_len bytes of u_char data> */
    /* char data for args 1 ... n */
};
/*
av-pairs:    (depends from IOS release)
  "task_id="
  "start_time="
  "stop_time="
  "elapsed_time="
  "timezone="
  "event=net_acct|cmd_acct|conn_acct|shell_acct|sys_acct|clock_change"
       Used only when "service=system"
  "reason="  - only for event attribute
  "bytes="
  "bytes_in="
  "bytes_out="
  "paks="
  "paks_in="
  "paks_out="
  "status="
	. . .
     The numeric status value associated with the action. This is a signed
     four (4) byte word in network byte order. 0 is defined as success.
     Negative numbers indicate errors. Positive numbers indicate non-error
     failures. The exact status values may be defined by the client.
  "err_msg="

   NULL - last

FLAGS:
TAC_PLUS_ACCT_FLAG_MORE     = 0x1     (deprecated)
TAC_PLUS_ACCT_FLAG_START    = 0x2
TAC_PLUS_ACCT_FLAG_STOP     = 0x4
TAC_PLUS_ACCT_FLAG_WATCHDOG = 0x8
*/
int
tac_account_send_request(struct session *session, const int flag,
	const int method, const int priv_lvl,const int authen_type,
	const int authen_service,const char *user, const char *port,
	char **avpair) {
   int i;
   char buf[512];
   char rem_addr[20];
   char name[100];
   HDR *hdr = (HDR *)buf;
   struct acct *acc = (struct acct *)(buf + TAC_PLUS_HDR_SIZE);
   char *lens=(char*)(buf+TAC_PLUS_HDR_SIZE+
		      TAC_ACCT_REQ_FIXED_FIELDS_SIZE);
   int arglens=0;

   /* this is addr */
   gethostname(name,sizeof(name));
   strcpy(rem_addr, tac_getipfromname(name));

   memset(buf, 0, sizeof(buf));
   hdr->version = TAC_PLUS_VER_0;
   hdr->type = TAC_PLUS_ACCT;
   hdr->seq_no = ++session->seq_no;
   hdr->encryption = TAC_PLUS_CLEAR; /*TAC_PLUS_ENCRYPTED;*/
   hdr->session_id = session->session_id;

   for (i=0; avpair[i]!=NULL ; i++) {
      if (strlen(avpair[i])>255)    /* if lenght of AVP>255 set it to 255 */
	 avpair[i][255]=0;
      arglens += strlen(avpair[i]);
   }
   hdr->datalength = htonl(TAC_ACCT_REQ_FIXED_FIELDS_SIZE +
	i+strlen(user)+strlen(port)+strlen(rem_addr)+arglens);

   acc->flags = (u_char) flag;
   acc->authen_method = (u_char) method;
   acc->priv_lvl = (u_char) priv_lvl;
   acc->authen_type = (u_char) authen_type;
   acc->authen_service = (u_char) authen_service;
   acc->user_len=(u_char)strlen(user);
   acc->port_len=(u_char)strlen(port);
   acc->rem_addr_len = (u_char) strlen(rem_addr);
   acc->arg_cnt = (u_char) i;

   for (i=0; avpair[i]!=NULL ; i++) {
      *lens=(u_char)strlen(avpair[i]);
      lens=lens+1;
   }
   /* filling data */
   if (strlen(user)>0) {
      strcpy(lens,user);
      lens += strlen(user);
   }
   if (strlen(port)>0) {
      strcpy(lens,port);
      lens += strlen(port);
   }
   if (strlen(rem_addr)>0) {
      strcpy(lens,rem_addr);
      lens += strlen(rem_addr);
   }
   for (i=0; avpair[i]!=NULL ; i++) {
       strcpy(lens,avpair[i]);
       lens += (u_char)strlen(avpair[i]);
   }
   if (write_packet(session,buf)) return 1;
   return 0;
}

/*********************************************
  get the account REQUEST (server function)
 
  return accounting flag if sussess
  0 - fail

**********************************************/
int
tac_account_get_request_s(char *buf,struct session *session,
   int *method,int *priv_lvl,
   int *authen_type, int *authen_service,
   char *user,char *port,char *rem_addr, char **avpair)
{
   int flag;
   int i;
   int l[255];
   char str[255];
   HDR *hdr = (HDR *)buf;
   struct acct *acc = (struct acct *)(buf + TAC_PLUS_HDR_SIZE);
   char *lens=(char*)(buf+TAC_PLUS_HDR_SIZE+
		      TAC_ACCT_REQ_FIXED_FIELDS_SIZE);
   int arglens=0;

   /* some checks */
   if (hdr->type != TAC_PLUS_ACCT) {
      tac_error("This is not ACCOUNT request\n");
      return 0;
   }
   if (hdr->seq_no != 1) {
      tac_error("Error in sequence in ACCOUNT/REQUEST\n");
      return 0;
   }
   session->session_id = hdr->session_id;
   /* count length */
   for (i=0; i < acc->arg_cnt; i++)
      arglens += (int)*(lens+i);
   if (hdr->datalength != htonl(TAC_ACCT_REQ_FIXED_FIELDS_SIZE+
      acc->arg_cnt+acc->user_len+acc->port_len+acc->rem_addr_len+
      arglens)) {
      tac_error("Error in ACCOUNT/REQUEST packet, check keys\n");
      return 0;
   }
   flag = acc->flags;
   *method = acc->authen_method;
   *priv_lvl = acc->priv_lvl;
   *authen_type = acc->authen_type;
   *authen_service = acc->authen_service;

   /* count length */
   for (i=0; i < acc->arg_cnt; i++) {
      l[i]=(int)*lens;
      lens++;
   }
   memset(user, 0, sizeof(user));
   strncpy(user,lens,acc->user_len);
   lens += acc->user_len;

   memset(port, 0, sizeof(port));
   strncpy(port,lens,acc->port_len);
   lens += acc->port_len;

   memset(rem_addr, 0, sizeof(rem_addr));
   strncpy(rem_addr,lens,acc->rem_addr_len);
   lens += acc->rem_addr_len;

   /* reviewing avpairs */
   for (i=0 ; i < acc->arg_cnt; i++) {
      memset(str, 0, sizeof(str));
      strncpy(str,lens,l[i]);
      avpair[i]=strdup(str);
      lens += l[i];
   }
   avpair[i]=NULL;
   return (flag);
}
int
tac_account_get_request(struct session *session,int *flag,
   int *method,int *priv_lvl,
   int *authen_type, int *authen_service,
   char *user,char *port,char *rem_addr, char **avpair)
{
   char *buf = read_packet(session);
   if (buf==NULL) return 0;
   return(tac_account_get_request_s(buf,session,
	 method,priv_lvl,authen_type,authen_service,
	 user,port,rem_addr,avpair));
}

/*****************************************
      send the accounting REPLY (server function)
*/
#define TAC_ACCT_REPLY_FIXED_FIELDS_SIZE 5
struct acct_reply {
    u_short msg_len;
    u_short data_len;
    u_char status;      /* status */
};
/* accounting status
TAC_PLUS_ACCT_STATUS_SUCCESS=1
TAC_PLUS_ACCT_STATUS_ERROR  =2
TAC_PLUS_ACCT_STATUS_FOLLOW =33
******************************************/
int
tac_account_send_reply(struct session *session,char *server_msg,
		       char *data, const int status)
{
   char buf[512];
   HDR *hdr = (HDR *)buf;
   struct acct_reply *acc = (struct acct_reply *)(buf + TAC_PLUS_HDR_SIZE);
   char *lens=(char*)(buf+TAC_PLUS_HDR_SIZE+
		      TAC_ACCT_REPLY_FIXED_FIELDS_SIZE);

   memset(buf, 0, sizeof(buf));
   hdr->version = TAC_PLUS_VER_0;
   hdr->type = TAC_PLUS_ACCT;
   hdr->seq_no = ++session->seq_no;
   hdr->encryption = TAC_PLUS_CLEAR; /*TAC_PLUS_ENCRYPTED;*/
   hdr->session_id = session->session_id;

   hdr->datalength=htonl(TAC_ACCT_REPLY_FIXED_FIELDS_SIZE+strlen(server_msg)+
	     strlen(data));
   acc->msg_len=(u_short)strlen(server_msg);
   acc->data_len=(u_short)strlen(data);
   acc->status=status;

   if (strlen(server_msg)>0) {
      strcpy(lens,server_msg);
      lens += strlen(server_msg);
   }
   if (strlen(data)>0) {
      strcpy(lens,data);
      lens += strlen(data);
   }
   /* thats all, folks */
   if (write_packet(session,buf)) return 1;
   return 0;
}


/*************************************************
    get the accounting REPLY (client function)
       1  SUCCESS
       0  FAILURE
**************************************************/
int
tac_account_get_reply(struct session *session,
		    char *server_msg, char *data)
{
   int status;

   char *buf = read_packet(session);
   HDR *hdr = (HDR *)buf;
   struct acct_reply *acc = (struct acct_reply *)(buf + TAC_PLUS_HDR_SIZE);
   char *lens=(char*)(buf + TAC_PLUS_HDR_SIZE +
		      TAC_ACCT_REPLY_FIXED_FIELDS_SIZE);

   if (buf==NULL) return 0;
   /* some checks */
   if (hdr->type != TAC_PLUS_ACCT) {
      tac_error("This is not ACCOUNT request\n");
      return -1;
   }
   if (hdr->seq_no != 2) {
      tac_error("Error in sequence in ACCOUNT/REQUEST\n");
      return 0;
   }
   session->session_id = hdr->session_id;

   if (hdr->datalength != htonl(TAC_ACCT_REPLY_FIXED_FIELDS_SIZE+
      acc->msg_len + acc->data_len)) {
	tac_error("Error in ACCOUNT/REPLY packet, check keys\n");
	return 0;
   }
   status=acc->status;

   memset(server_msg, 0, sizeof(server_msg));
   strncpy(server_msg,lens,acc->msg_len);
   lens = lens + acc->msg_len;
   memset(data, 0, sizeof(data));
   strncpy(data,lens,acc->data_len);

   return status;
}
