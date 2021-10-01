#define _GNU_SOURCE
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <getopt.h>
#include "radcl.h"

#define RADCL_TITLE "Radius Client Simulator Version 1.0"
#define Debug  0 

typedef struct radcl_thread_t_
{
  pthread_t pthread;
  rad_script_context_t ctx;
  char input[4096];
  char output[2048];
  char * input_begin;
  char * input_end;
  char * output_end;
  char user_name[64];
  char user_password[32];
  char auth_type[32];
  char nas_identifier[128];
  char called_station_id[128];
  char calling_station_id[128];
  char result_text[128];
  int ue_id;
  int done;
  struct timeval start_time;
  struct timeval end_time;
} radcl_thread_t;

typedef struct radcl_thread_list_t_
{
  radcl_thread_t * thread;
} radcl_thread_list_t;

radcl_thread_list_t thread_list;

const char * radius_password = "testing123";
char called_station_prefix[] = {0xac, 0x67, 0x06, 0x00, 0x00, 0x00};
char calling_station_prefix[] = {0x00, 0x21, 0x19, 0x00, 0x00, 0x00};
const char * ssid_prefix = "SSID";


static inline char *atoether( char *txt )
{
        static char retval[6];
        int ret_pos = 0;
        int len = 0;
        int val = 0;
        int cx = 0;

        len = strlen(txt);
        bzero(retval, 6);

        for (ret_pos = 0, cx = 0; cx < len; cx++) {
                if ( txt[cx] == '\0' )
                        return( retval );
                if ( (txt[cx] == ':') || (txt[cx] == '-') ) {
                        ret_pos++;
                        val = 0;
                        continue;
                }
                /* Shutdup */
                switch ( txt[cx] ) {
                        case '0':       val = 0;  break;
                        case '1':       val = 1;  break;
                        case '2':       val = 2;  break;
                        case '3':       val = 3;  break;
                        case '4':       val = 4;  break;
                        case '5':       val = 5;  break;
                        case '6':       val = 6;  break;
                        case '7':       val = 7;  break;
                        case '8':       val = 8;  break;
                        case '9':       val = 9;  break;
                        case 'A':
                        case 'a':       val = 10; break;
                        case 'B':
                        case 'b':       val = 11; break;
                        case 'C':
                        case 'c':       val = 12; break;
                        case 'D':
                        case 'd':       val = 13; break;
                        case 'E':
                        case 'e':       val = 14; break;
                        case 'F':
                        case 'f':       val = 15; break;
                }
                retval[ret_pos] = (u_int8_t) (((retval[ret_pos]) << 4) + val);
        }

        return( retval );
}

void
radcl_printf(rad_script_context_t * ctx, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);

  if (ctx->thread) {
    char * cp;
    cp = ctx->thread->output_end;
    ctx->thread->output_end += vsprintf(ctx->thread->output_end, fmt, ap);
    if (strncmp("Result:", cp, strlen("Result:")) == 0 || strncmp("Error:", cp, strlen("Error:")) == 0) {
      strncpy(ctx->thread->result_text, cp, sizeof(ctx->thread->result_text));
      cp = ctx->thread->result_text;
      while (*cp) {
	if (*cp == '\n' || *cp == '\r') {
	  *cp = 0;
	  break;
	}
	cp ++;
      }
    }
  } else {
    vfprintf(ctx->out_file, fmt, ap);
  }
  va_end(ap);
}


char *
radcl_gets(rad_script_context_t * ctx, char * line, int size)
{
  if (ctx->thread) {
    char * cp1 = ctx->thread->input_begin;
    char * cp2 = line;
    while (*cp1 != 0) {
      *cp2 = *cp1;
      cp2 ++;
      if (*cp1 == '\n') {
	break;
      }
      cp1 ++;
    }
    *cp2 = 0;
    if (*cp1) {
      ctx->thread->input_begin = cp1 + 1;
      return line;
    } else if (ctx->thread->input_begin == cp1) {
      return 0;
    } else {
      ctx->thread->input_begin = cp1;
      return line;
    }
  } else {
    return fgets(line, size, ctx->in_file);
  }
}

void
radcl_exit(rad_script_context_t * ctx, int code)
{
  if (ctx->thread) {
    void * retcode = (void *) (long long) code;

    if (gettimeofday(&ctx->thread->end_time, NULL) != 0) {
      fprintf(stderr, "Error: cannot get time of day\n");
      exit(1);
    }

    if (ctx->s != 0 && ctx->s != -1) {
      close(ctx->s);
      ctx->s = 0;
    }

    pthread_exit(retcode);
  } else {
    exit(code);
  }
}

void *
radcl_client_main(void * arg)
{
  radcl_thread_t * thread = (radcl_thread_t *) arg;

  if (gettimeofday(&thread->start_time, NULL) != 0) {
    fprintf(stderr, "Error: cannot get time of day\n");
    exit(1);
  }

  rad_run_script(&thread->ctx);

  return 0;
}

void
radcl_client_init(radcl_thread_t * thread, int ue_id, long server_ip, short server_udp_port, long local_ip, short local_udp_port)
{
  memset(thread, sizeof(*thread), 0);

  thread->ctx.thread = thread;

  thread->ctx.remote_ip = server_ip;
  thread->ctx.remote_udp_port = server_udp_port;
  thread->ctx.local_ip = local_ip;
  thread->ctx.local_udp_port = local_udp_port;
  thread->ctx.tx_retry_usec = RAD_DEFAULT_TX_RETRY_INTERVAL_USEC;
  thread->input_begin = thread->input;
  thread->input_end = thread->input;
  thread->output_end = thread->output;

  thread->ue_id = ue_id;
  thread->input_end += sprintf(thread->input_end, "Password=%s\n", radius_password);
}

void
radcl_client_prepare(radcl_thread_t * thread, int ap_id, int ssid_id)
{
  u_char smac[6];
  u_int32_t  smac_temp ;
  u_int32_t  local_ip = htonl(thread->ctx.local_ip);

  smac_temp = htonl(ntohl(*(u_int32_t *)(called_station_prefix + 2)) + ap_id -1);
  bcopy(called_station_prefix, smac, 2);
  bcopy(&smac_temp, smac + 2 , 4);

  sprintf(thread->nas_identifier, "%02X-%02X-%02X-%02X-%02X-%02X",
	smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);

  smac_temp = htonl(ntohl(*(u_int32_t *)(calling_station_prefix + 2)) + thread->ue_id -1);
  bcopy(calling_station_prefix, smac, 2);
  bcopy(&smac_temp, smac + 2 , 4);
  sprintf(thread->calling_station_id, "%02X-%02X-%02X-%02X-%02X-%02X",
	smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
  #if Debug
  fprintf(stdout,"Calling %s \n\r Called %s\r\n", thread->calling_station_id, thread->nas_identifier);
  #endif
  if (ssid_id < 0) {
    strcpy(thread->called_station_id, thread->nas_identifier);
  } else if (ssid_id == 0) {
    sprintf(thread->called_station_id, "%s:%s", thread->nas_identifier, ssid_prefix);
  } else {
    sprintf(thread->called_station_id, "%s:%s%u", thread->nas_identifier, ssid_prefix, ssid_id);
  }

  thread->input_end += sprintf(thread->input_end, "Open\n");
  if (strcmp(thread->auth_type, "EAPMD5") == 0) {
    fprintf(stdout,"Entering %s\n", thread->auth_type);
    thread->input_end += sprintf(thread->input_end, "TX-Begin\n");
    thread->input_end += sprintf(thread->input_end, "\tCode = Access-Request\n");
    thread->input_end += sprintf(thread->input_end, "\tPacket-Identifier = Auto\n");
    thread->input_end += sprintf(thread->input_end, "\tAVP:User-Name = %s\n", thread->user_name);
    thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-IP-Address = %s\n", inet_ntoa(*((struct in_addr*) &local_ip)));
    thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Identifier = %s\n", thread->nas_identifier);
    thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port = 3\n");
    thread->input_end += sprintf(thread->input_end, "\tAVP:Called-Station-Id = %s\n", thread->called_station_id);
    thread->input_end += sprintf(thread->input_end, "\tAVP:Calling-Station-Id = %s\n", thread->calling_station_id);
    thread->input_end += sprintf(thread->input_end, "\tAVP:Framed-MTU = 1400\n");
    thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port-Type = Wireless-802.11\n");
    thread->input_end += sprintf(thread->input_end, "\tAVP:Connect-Info = CONNECT 11Mbps 802.11b\n");
    thread->input_end += sprintf(thread->input_end, "\tEAP-Begin\n");
    thread->input_end += sprintf(thread->input_end, "\t\tEAP:Code = Response\n");
    thread->input_end += sprintf(thread->input_end, "\t\tEAP:Id = 0\n");
    thread->input_end += sprintf(thread->input_end, "\t\tEAP:Type = Identity\n");
    thread->input_end += sprintf(thread->input_end, "\t\tEAP:Identity = %s\n", thread->user_name);
    thread->input_end += sprintf(thread->input_end, "\tEAP-End\n");
    thread->input_end += sprintf(thread->input_end, "\tAVP:Message-Authenticator = Auto\n");
    thread->input_end += sprintf(thread->input_end, "TX-End\n");

    thread->input_end += sprintf(thread->input_end, "RX-Begin\n");
    thread->input_end += sprintf(thread->input_end, "RX-End\n");

    thread->input_end += sprintf(thread->input_end,"TX-Begin\n");
    thread->input_end += sprintf(thread->input_end, "\tCode = Access-Request\n");
    thread->input_end += sprintf(thread->input_end, "\tPacket-Identifier = Auto\n");
    thread->input_end += sprintf(thread->input_end, "\tAVP:User-Name = %s\n", thread->user_name);
    thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-IP-Address = %s\n", inet_ntoa(*((struct in_addr*) &local_ip)));
    thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Identifier = %s\n", thread->nas_identifier);
    thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port = 3\n");
    thread->input_end += sprintf(thread->input_end, "\tAVP:Called-Station-Id = %s\n", thread->called_station_id);
    thread->input_end += sprintf(thread->input_end, "\tAVP:Calling-Station-Id = %s\n", thread->calling_station_id);
    thread->input_end += sprintf(thread->input_end, "\tAVP:Framed-MTU = 1400\n");
    thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port-Type = Wireless-802.11\n");
    thread->input_end += sprintf(thread->input_end, "\tAVP:Connect-Info = CONNECT 11Mbps 802.11b\n");
    thread->input_end += sprintf(thread->input_end, "\tEAP-Begin\n");
    thread->input_end += sprintf(thread->input_end, "\t\tEAP:Code = Response\n");
    thread->input_end += sprintf(thread->input_end, "\t\tEAP:Id = Auto\n");
    thread->input_end += sprintf(thread->input_end, "\t\tEAP:Type = EAP-MD5\n");
    thread->input_end += sprintf(thread->input_end, "\t\tEAP:Subtype = Start\n");
    thread->input_end += sprintf(thread->input_end, "\t\tEAP:AT_SELECTED_VERSION = Auto\n");
    thread->input_end += sprintf(thread->input_end, "\t\tEAP:AT_NONCE_MT = Auto\n");
    thread->input_end += sprintf(thread->input_end, "\t\tEAP:AT_IDENTITY = %s\n", thread->user_name);
    thread->input_end += sprintf(thread->input_end, "\tEAP-End\n");
    thread->input_end += sprintf(thread->input_end, "\tAVP:Message-Authenticator = Auto\n");
    thread->input_end += sprintf(thread->input_end, "\tAVP:State = Auto\n");
    thread->input_end += sprintf(thread->input_end, "TX-End\n");
  } else if(strcmp(thread->auth_type, "PAP") == 0) {
     thread->input_end += sprintf(thread->input_end, "TX-Begin\n");
     thread->input_end += sprintf(thread->input_end, "\tCode = Access-Request\n");
     thread->input_end += sprintf(thread->input_end, "\tPacket-Identifier = Auto\n");
     thread->input_end += sprintf(thread->input_end, "\tAVP:User-Name = %s\n", thread->user_name);
     thread->input_end += sprintf(thread->input_end, "\tAVP:User-Password = %s\n", thread->user_password);
     thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-IP-Address = %s\n", inet_ntoa(*((struct in_addr*) &local_ip)));
     thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Identifier = %s\n", thread->nas_identifier);
     thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port = 3\n");
     thread->input_end += sprintf(thread->input_end, "\tAVP:Called-Station-Id = %s\n", thread->called_station_id);
     thread->input_end += sprintf(thread->input_end, "\tAVP:Calling-Station-Id = %s\n", thread->calling_station_id);
     thread->input_end += sprintf(thread->input_end, "\tAVP:Framed-MTU = 1400\n");
     thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port-Type = Wireless-802.11\n");
     thread->input_end += sprintf(thread->input_end, "\tAVP:Connect-Info = CONNECT 11Mbps 802.11b\n");
     thread->input_end += sprintf(thread->input_end, "\tAVP:Message-Authenticator = Auto\n");
     thread->input_end += sprintf(thread->input_end, "TX-End\n");
  } else if(strcmp(thread->auth_type, "CHAP") == 0) {
     thread->input_end += sprintf(thread->input_end, "TX-Begin\n");
     thread->input_end += sprintf(thread->input_end, "\tCode = Access-Request\n");
     thread->input_end += sprintf(thread->input_end, "\tPacket-Identifier = Auto\n");
     thread->input_end += sprintf(thread->input_end, "\tAVP:User-Name = %s\n", thread->user_name);
     thread->input_end += sprintf(thread->input_end, "\tAVP:CHAP-Password = %s\n", thread->user_password);
     thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-IP-Address = %s\n", inet_ntoa(*((struct in_addr*) &local_ip)));
     thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Identifier = %s\n", thread->nas_identifier);
     thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port = 3\n");
     thread->input_end += sprintf(thread->input_end, "\tAVP:Called-Station-Id = %s\n", thread->called_station_id);
     thread->input_end += sprintf(thread->input_end, "\tAVP:Calling-Station-Id = %s\n", thread->calling_station_id);
     thread->input_end += sprintf(thread->input_end, "\tAVP:Framed-MTU = 1400\n");
     thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port-Type = Wireless-802.11\n");
     thread->input_end += sprintf(thread->input_end, "\tAVP:Connect-Info = CONNECT 11Mbps 802.11b\n");
     thread->input_end += sprintf(thread->input_end, "\tAVP:Message-Authenticator = Auto\n");
     thread->input_end += sprintf(thread->input_end, "TX-End\n");
  } else if(strcmp(thread->auth_type, "EAPSIM") == 0) {
  thread->input_end += sprintf(thread->input_end, "TX-Begin\n");
  thread->input_end += sprintf(thread->input_end, "\tCode = Access-Request\n");
  thread->input_end += sprintf(thread->input_end, "\tPacket-Identifier = Auto\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:User-Name = %s\n", thread->user_name);
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-IP-Address = %s\n", inet_ntoa(*((struct in_addr*) &local_ip)));
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Identifier = %s\n", thread->nas_identifier);
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port = 3\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:Called-Station-Id = %s\n", thread->called_station_id);
  thread->input_end += sprintf(thread->input_end, "\tAVP:Calling-Station-Id = %s\n", thread->calling_station_id);
  thread->input_end += sprintf(thread->input_end, "\tAVP:Framed-MTU = 1400\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port-Type = Wireless-802.11\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:Connect-Info = CONNECT 11Mbps 802.11b\n");
  thread->input_end += sprintf(thread->input_end, "\tEAP-Begin\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Code = Response\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Id = 0\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Type = Identity\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Identity = %s\n", thread->user_name);
  thread->input_end += sprintf(thread->input_end, "\tEAP-End\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:Message-Authenticator = Auto\n");
  thread->input_end += sprintf(thread->input_end, "TX-End\n");

  thread->input_end += sprintf(thread->input_end, "RX-Begin\n");
  thread->input_end += sprintf(thread->input_end, "RX-End\n");

  thread->input_end += sprintf(thread->input_end,"TX-Begin\n");
  thread->input_end += sprintf(thread->input_end, "\tCode = Access-Request\n");
  thread->input_end += sprintf(thread->input_end, "\tPacket-Identifier = Auto\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:User-Name = %s\n", thread->user_name);
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-IP-Address = %s\n", inet_ntoa(*((struct in_addr*) &local_ip)));
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Identifier = %s\n", thread->nas_identifier);
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port = 3\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:Called-Station-Id = %s\n", thread->called_station_id);
  thread->input_end += sprintf(thread->input_end, "\tAVP:Calling-Station-Id = %s\n", thread->calling_station_id);
  thread->input_end += sprintf(thread->input_end, "\tAVP:Framed-MTU = 1400\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port-Type = Wireless-802.11\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:Connect-Info = CONNECT 11Mbps 802.11b\n");
  thread->input_end += sprintf(thread->input_end, "\tEAP-Begin\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Code = Response\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Id = Auto\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Type = EAP-SIM\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Subtype = Start\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:AT_SELECTED_VERSION = Auto\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:AT_NONCE_MT = Auto\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:AT_IDENTITY = %s\n", thread->user_name);
  thread->input_end += sprintf(thread->input_end, "\tEAP-End\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:Message-Authenticator = Auto\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:State = Auto\n");
  thread->input_end += sprintf(thread->input_end, "TX-End\n");

  thread->input_end += sprintf(thread->input_end, "RX-Begin\n");
  thread->input_end += sprintf(thread->input_end, "RX-End\n");

  thread->input_end += sprintf(thread->input_end, "TX-Begin\n");
  thread->input_end += sprintf(thread->input_end, "\tCode = Access-Request\n");
  thread->input_end += sprintf(thread->input_end, "\tPacket-Identifier = Auto\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:User-Name = %s\n", thread->user_name);
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-IP-Address = %s\n", inet_ntoa(*((struct in_addr*) &local_ip)));
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Identifier = %s\n", thread->nas_identifier);
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port = 3\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:Called-Station-Id = %s\n", thread->called_station_id);
  thread->input_end += sprintf(thread->input_end, "\tAVP:Calling-Station-Id = %s\n", thread->calling_station_id);
  thread->input_end += sprintf(thread->input_end, "\tAVP:Framed-MTU = 1400\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:NAS-Port-Type = Wireless-802.11\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:Connect-Info = CONNECT 11Mbps 802.11b\n");
  thread->input_end += sprintf(thread->input_end, "\tEAP-Begin\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Code = Response\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Id = Auto\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Type = EAP-SIM\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:Subtype = Challenge\n");
  thread->input_end += sprintf(thread->input_end, "\t\tEAP:AT_MAC = Auto\n");
  thread->input_end += sprintf(thread->input_end, "\tEAP-End\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:Message-Authenticator = Auto\n");
  thread->input_end += sprintf(thread->input_end, "\tAVP:State = Auto\n");
  thread->input_end += sprintf(thread->input_end, "TX-End\n");
  }
  thread->input_end += sprintf(thread->input_end, "RX-Begin\n");
  thread->input_end += sprintf(thread->input_end, "RX-End\n");
  thread->input_end += sprintf(thread->input_end, "Close\n");
  #if Debug
  printf("#### {\n%s}\n", thread->input);
  #endif
}

int
radcl_setup_clients(long server_ip, short server_udp_port, long local_ip, short local_udp_port, int num_ue, int num_ap, int num_ssid, const char * user_conf_filename)
{
  int n;
  int k;
  radcl_thread_t * thread;
  FILE * user_conf_file;
  char line[256];
  int status;
  char * cp;
  char field[128];
  char value[128];
  long l_ip;
  short l_port;

  if (user_conf_filename == 0) {
    fprintf(stderr, "Error: --user-conf is not specified.\n");
    exit(1);
  }

  user_conf_file = fopen(user_conf_filename, "r");
  if (user_conf_file == 0) {
    fprintf(stderr, "Error: cannot open user-conf file <%s>\n", user_conf_filename);
    exit(1);
  }

  memset(&thread_list, 0, sizeof(thread_list));
  thread_list.thread = (radcl_thread_t *) calloc(num_ue, sizeof(radcl_thread_t));
  if (thread_list.thread == 0) {
    fprintf(stderr, "Error: cannot allocate memory (%lu bytes)\n", num_ue * sizeof(radcl_thread_t));
    exit(1);
  }

  for (n = 0; n < num_ue; n++) {
    thread = &thread_list.thread[n];
    if (num_ap == 1) {
      l_ip = local_ip;
      l_port = local_udp_port;
    } else {
      l_ip = n%num_ap + local_ip;
      if (local_udp_port == 0) {
	l_port = 10000 + (n / num_ap);
      } else {
	l_port = local_udp_port + (n / num_ap);
	}
    }

    radcl_client_init(thread, n + 1, server_ip, server_udp_port, l_ip, l_port);
  }

  status = 0;
  n = 0;
  while (n < num_ue && fgets(line, sizeof(line), user_conf_file) == line) {
    for (cp = line; *cp != 0; cp++) {
      if (*cp == '\n' || *cp == '\r') {
	*cp = 0;
	break;
      }
    }

    for (cp = line; *cp != 0; cp++) {
      if (!isspace(*cp)) {
	break;
      }
    }

    if (status == 0) {
      if (*cp == 0) {
	continue;
      }

      thread = &thread_list.thread[n];
      for (k = 0; !isspace(*cp); k++, cp++) {
	thread->user_name[k] = *cp;
      }
      thread->user_name[k] = 0;

      while (isspace(*cp)) {
        cp++;
      }

      for (k = 0; !isspace(*cp); k++, cp++) {
	        thread->user_password[k] = *cp;
      }
          thread->user_password[k] = 0;

      while (isspace(*cp)) {
              cp++;
      }

      for (k = 0; !isspace(*cp); k++, cp++) {
	        thread->auth_type[k] = *cp;
      }
          thread->auth_type[k] = 0;

      status = 1;
    } else {
      if (*cp == 0) {
	int ssid_id;

	status = 0;
	if (num_ssid == 0) {
	  ssid_id = -1;
	} else if (num_ssid == 1) {
	  ssid_id = 0;
	} else {
	  ssid_id = (n % num_ssid) + 1;
	}

	radcl_client_prepare(thread, (n % num_ap) + 1, ssid_id);
	n ++;
	continue;
      }

      for (k = 0; !isspace(*cp) && *cp != '='; k++, cp++) {
	field[k] = *cp;
      }
      field[k] = 0;

      while (*cp != '=' && *cp != 0) {
	cp ++;
      }

      if (*cp != '=') {
	fprintf(stderr, "Error: invalid line <%s> in file %s\n", line, user_conf_filename);
	exit(1);
      }

      cp ++;

      while (isspace(*cp) && *cp != 0) {
	cp ++;
      }

      for (k = 0; !isspace(*cp) && *cp != ',' && *cp != 0; k++, cp++) {
	value[k] = *cp;
      }

      if (strcmp(field, "EAP-Sim-Rand1") == 0) {
	thread->input_end += sprintf(thread->input_end, "EAP-SIM-RAND1=%s\n", value + 2);
      } else if (strcmp(field, "EAP-Sim-Rand2") == 0) {
	thread->input_end += sprintf(thread->input_end, "EAP-SIM-RAND2=%s\n", value + 2);
      } else if (strcmp(field, "EAP-Sim-Rand3") == 0) {
	thread->input_end += sprintf(thread->input_end, "EAP-SIM-RAND3=%s\n", value + 2);
      } else if (strcmp(field, "EAP-Sim-SRES1") == 0) {
	thread->input_end += sprintf(thread->input_end, "EAP-SIM-SRES1=%s\n", value + 2);
      } else if (strcmp(field, "EAP-Sim-SRES2") == 0) {
	thread->input_end += sprintf(thread->input_end, "EAP-SIM-SRES2=%s\n", value + 2);
      } else if (strcmp(field, "EAP-Sim-SRES3") == 0) {
	thread->input_end += sprintf(thread->input_end, "EAP-SIM-SRES3=%s\n", value + 2);
      } else if (strcmp(field, "EAP-Sim-KC1") == 0) {
	thread->input_end += sprintf(thread->input_end, "EAP-SIM-KC1=%s\n", value + 2);
      } else if (strcmp(field, "EAP-Sim-KC2") == 0) {
	thread->input_end += sprintf(thread->input_end, "EAP-SIM-KC2=%s\n", value + 2);
      } else if (strcmp(field, "EAP-Sim-KC3") == 0) {
	thread->input_end += sprintf(thread->input_end, "EAP-SIM-KC3=%s\n", value + 2);
      }
    }
  }

  fclose(user_conf_file);
  user_conf_file = 0;
  return n;
}

void
radcl_run_clients(int num_ue, int num_concurrent)
{
  int num_completed;
  int num_running;
  int num_started;
  int n;
  int result;
  radcl_thread_t * thread;

  num_started = 0;
  num_completed = 0;
  num_running = 0;
  while (num_completed < num_ue) {
    while (num_running < num_concurrent && num_started < num_ue) {
      thread = &thread_list.thread[num_started];
      result = pthread_create(&thread->pthread, NULL, radcl_client_main, thread);
      if (result != 0) {
	if (result == EAGAIN) {
	  struct rlimit limit;
	  if (getrlimit(RLIMIT_NPROC, &limit) == 0) {
	    fprintf(stderr, "Error: cannot create thread #%d (running %d, RLIMIT_NPROC[cur=%d, max=%d])\n", num_started, num_running, (int) limit.rlim_cur, (int) limit.rlim_max);
	  } else {
	    fprintf(stderr, "Error: cannot create thread #%d (running %d. RLIMIT_NPROC[NA])\n", num_started, num_running);
	  }
	  exit(1);
	} else {
	  fprintf(stderr, "Error: cannot create thread #%d (running %d)\n", num_started, num_running);
	  exit(1);
	}
      } else {
	num_started ++;
	num_running ++;
      }
    }

    for (n = 0; n < num_started; n++) {
      thread = &thread_list.thread[n];
      if (!thread->done) {
	result = pthread_tryjoin_np(thread->pthread, NULL);
	if (result != 0) {
	  if (result != EBUSY) {
	    fprintf(stderr, "Error: cannot join thread #%d\n", n);
	    exit(1);
	  }
	} else {
	  thread->done = 1;
	  num_completed ++;
	  num_running --;
	  if (thread->end_time.tv_sec == 0) {
	    if (gettimeofday(&thread->end_time, NULL) != 0) {
	      fprintf(stderr, "Error: cannot get time of day\n");
	      exit(1);
	    }
	  }
	}
      }
    }
  }
}

void
radcl_analyze_results(int num_ue, int show_auth_summary)
{
  int n;
  radcl_thread_t * thread;
  struct timeval result;
  struct timeval start;
  struct timeval end;
  double min_time;
  double max_time;
  double duration;
  double total_sec;
  double speed;
  int num_access_accept;
  int num_access_reject;
  int num_error;
  int num_access_other;

  timerclear(&start);
  timerclear(&end);
  min_time = 0;
  max_time = 0;
  num_access_accept = 0;
  num_access_reject = 0;
  num_error = 0;
  num_access_other = 0;

  for (n = 0; n < num_ue; n++) {
    thread = &thread_list.thread[n];

    if (!timerisset(&start) || timercmp(&start, &thread->start_time, >)) {
      memcpy(&start, &thread->start_time, sizeof(start));
    }

    if (!timerisset(&end) || timercmp(&end, &thread->end_time, <)) {
      memcpy(&end, &thread->end_time, sizeof(end));
    }

    timersub(&thread->end_time, &thread->start_time, &result);
    duration = (result.tv_sec * 1E6 + result.tv_usec) / 1E6;
    if (min_time == 0 || min_time > duration) {
      min_time = duration;
    }

    if (max_time == 0 || max_time < duration) {
      max_time = duration;
    }

    if (strncmp(thread->result_text, "Result: Access-Accept", strlen("Result: Access-Accept")) == 0) {
      num_access_accept ++;
    } else if (strncmp(thread->result_text, "Result: Access-Reject", strlen("Result: Access-Reject")) == 0) {
      num_access_reject ++;
    } else if (strncmp(thread->result_text, "Error:", strlen("Error:")) == 0) {
      num_error ++;
    } else {
      num_access_other ++;
    }

    if (show_auth_summary) {
      fprintf(stdout, "(%u) %s > %s (%u.%06u sec)\n",
	      thread->ue_id,
	      thread->user_name,
	      thread->result_text,
	      (uint32_t) result.tv_sec,
	      (uint32_t) result.tv_usec);
    }
  }

  timersub(&end, &start, &result);
  total_sec = (result.tv_sec * 1E6 + result.tv_usec) / 1E6;
  speed = num_ue / total_sec;
  fprintf(stdout, "%u auths (%u accepts, %u rejects, %u errors, %u others), speed=%.2f auth/sec, total %.2f sec, range=(%.6f, %.6f)\n",
	  num_ue,
	  num_access_accept,
	  num_access_reject,
	  num_error,
	  num_access_other,
	  speed,
	  total_sec,
	  min_time,
	  max_time);
}

void
radcl_getrlimits()
{
  struct rlimit limit;

  if (getrlimit(RLIMIT_AS, &limit)) {
    fprintf(stderr, "Error: cannot get RLIMIT_AS\n");
  } else {
    fprintf(stdout, "limits: as=(%lld, %lld), ", (long long) limit.rlim_cur, (long long) limit.rlim_max);
  }

  if (getrlimit(RLIMIT_DATA, &limit)) {
    fprintf(stderr, "Error: cannot get RLIMIT_DATA\n");
  } else {
    fprintf(stdout, "data=(%lld, %lld), ", (long long) limit.rlim_cur, (long long) limit.rlim_max);
  }

  if (getrlimit( RLIMIT_NOFILE, &limit)) {
    fprintf(stderr, "Error: cannot get RLIMIT_NOFILE\n");
  } else {
    fprintf(stdout, "file=(%lld, %lld), ", (long long) limit.rlim_cur, (long long) limit.rlim_max);
  }

  if (getrlimit( RLIMIT_NPROC, &limit)) {
    fprintf(stderr, "Error: cannot get RLIMIT_NPROC\n");
  } else {
    fprintf(stdout, "proc=(%lld, %lld)", (long long) limit.rlim_cur, (long long) limit.rlim_max);
  }

  fprintf(stdout, "\n");
}

int
main(int argc, const char * argv[])
{
  long server_ip;
  short server_udp_port;
  long local_ip_base;
  short local_udp_port;
  rad_script_context_t ctx;
  const char * output_filename;
  FILE * output_file;
  const char * user_conf_filename;
  int num_ue;
  int num_ap;
  int num_ssid;
  int num_concurrent;
  int show_auth_summary;

  fprintf(stdout, "%s\n", RADCL_TITLE);

  server_ip = 0;
  local_udp_port = 0;
  local_ip_base = INADDR_ANY;
  server_udp_port = RADIUS_PORT;
  output_filename = NULL;
  user_conf_filename = NULL;
  num_ue = 0;
  num_ap = 1;
  num_ssid = 0;
  num_concurrent = 1;
  show_auth_summary = 1;

  if (argc < 3) {
  show_usage:
    fprintf(stderr, "Usage: %s (with the following options in the same line)\n"
	    "\t--server-ip <server-ip>\t\t\t[required]\n"
	    "\t--server-udp <udp-port>\t\t\t[default:%d]\n"
	    "\t--my-ip <ddd.ddd.ddd.ddd>\t\t\t\t[required if --ap is greater than 1]\n"
	    "\t--my-udp <my-udp-port>\t\t\t[optional]\n"
	    "\t--output <filename>\t\t\t[not supported]\n"
	    "\t--ue <num>\t\t\t\t[# of UEs, optional, default:%d]\n"
	    "\t--user-conf <conf>\t\t\t[triplets file]\n"
	    "\t--ap <num>\t\t\t\t[# of APs or radius clients, default:%d]\n"
	    "\t--ssid <num>\t\t\t\t[# of ssid, default:%d]\n"
	    "\t--concurrent <num>\t\t\t[# of concurrent sessions, default:%d]\n"
	    "\t--password <password>\t\t\t[radius shared secret, default:%s\n"
	    "\t--no-auth-summary\t\t\t[default display auth summary, optional]\n"
	    "\t--ssid-prefix <ssid>\t\t\t[ssid-prefix, default:%s]\n"
	    "\t--calling-sta-prefix <00:21:19:00:00:00>\t\n"
	    "\t--called-sta-prefix <AC:67:06:00:00:00>\t\n",
	    argv[0],
	    server_udp_port,
	    num_ue,
	    num_ap,
	    num_ssid,
	    num_concurrent,
	    radius_password,
	    ssid_prefix);
    return -1;
  }

        int option_index = 0;
	int c;
        static struct option long_options[] = {
                   {"my-udp", required_argument, 0,  0 },
                   {"server-udp", required_argument, 0,  1 },
                   {"server-ip", required_argument, 0,  2 },
                   {"my-ip", required_argument, 0,  3 },
                   {"output", required_argument, 0,  4 },
                   {"ue",  required_argument, 0,  5 },
                   {"ap", required_argument, 0, 7 },
                   {"ssid", required_argument, 0,  8 },
                   {"concurrent", required_argument, 0,  9 },
                   {"password",     required_argument, 0,  10 },
                   {"no-auth-summary",     required_argument, 0,  11 },
                   {"ssid-prefix",  required_argument, 0,  12 },
                   {"calling-sta-prefix",  required_argument, 0,  13 },
                   {"called-sta-prefix",  required_argument, 0,  14 },
                   {"user-conf",  required_argument, 0,  15 },
                   {0,         0,                 0,  0 } };

      struct in_addr svr_in_addr;
      struct in_addr my_in_addr;
      while((c = getopt_long_only(argc, (char * const *) argv, "ve:", long_options, &option_index)) != EOF) {
    switch (c) {
    case 0 :
      local_udp_port = atoi(optarg);
      break;
    case  1 :
      server_udp_port = atoi(optarg);
      break;
    case  2 :
      if (inet_aton(optarg, &svr_in_addr) == 0) {
	fprintf(stderr, "Error: invalid server ip (%s)\n", optarg);
	return -1;
      }
      server_ip = ntohl(svr_in_addr.s_addr);
      break;
    case  3:
      if (inet_aton(optarg, &my_in_addr) == 0) {
	fprintf(stderr, "Error: invalid my-ip (%s)\n", optarg);
	return -1;
      }
      local_ip_base = ntohl(my_in_addr.s_addr);
      break;
    case  4 :
      output_filename = optarg;
      break;
    case  5:
      num_ue = atoi(optarg);
      break;
    case  7:
      num_ap = atoi(optarg);
      break;
    case  8:
      num_ssid = atoi(optarg);
      break;
    case   9:
      num_concurrent = atoi(optarg);
      break;
    case   10:
      radius_password = optarg;
      break;
    case  11:
      show_auth_summary = 0;
    case  12:
      ssid_prefix = optarg;
      break;
    case 13:
      bcopy(atoether(optarg), (void *) calling_station_prefix, 6);
      break;
    case 14:
      bcopy(atoether(optarg), (void *) called_station_prefix, 6);
      break;
    case  15:
      user_conf_filename = optarg;
      break;
  }
}

  if (server_ip == 0) {
    goto show_usage;
  }

  if (num_ap > 1 && local_ip_base == INADDR_ANY) {
    fprintf(stderr, "Error: multiple APs have been specified, but --my-ip is not set\n");
    goto show_usage;
  }

  if (output_filename == NULL) {
    output_file = stdout;
  } else {
    output_file = fopen(output_filename, "w");
    if (output_file == NULL) {
      fprintf(stderr, "Error: cannot create output file <%s>\n", output_filename);
    }
  }

  if (num_ue == 0) {
    rad_script_init_context(&ctx, stdin, output_file, server_ip, server_udp_port, local_ip_base, local_udp_port);
    rad_run_script(&ctx);
  } else {
    num_ue = radcl_setup_clients(server_ip, server_udp_port, local_ip_base, local_udp_port, num_ue, num_ap, num_ssid, user_conf_filename);
    fprintf(stdout, "Attempting: %u auths, %u concurrents, %u radius clients, %u SSIDs\n", num_ue, num_concurrent, num_ap, num_ssid);
    radcl_getrlimits();
    radcl_run_clients(num_ue, num_concurrent);
    radcl_analyze_results(num_ue, show_auth_summary);
  }

  return 0;
}
