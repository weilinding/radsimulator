#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

typedef struct radconf_context_t_
{
  FILE * user_conf_file;
  char line[256];
  char user_conf_filename[256];
  unsigned int num_ue;
  unsigned int num_tuples;
  unsigned int mcc;
  unsigned int mnc;
  unsigned long long base_msin;
  unsigned long long base_msisdn;
  unsigned int ggsnip;
} radconf_context_t;

#define DEFAULT_MCC             553
#define DEFAULT_MNC             450
#define DEFAULT_BASE_MSIN       1LL
#define DEFAULT_BASE_MSISDN     447919000001LL
#define DEFAULT_GGSN            0x9014000a


void 
radconf_init_context(radconf_context_t * ctx)
{
  memset(ctx, 0, sizeof(*ctx));
  ctx->mcc = DEFAULT_MCC;
  ctx->mnc = DEFAULT_MNC;
  ctx->base_msin = DEFAULT_BASE_MSIN;
  ctx->base_msisdn = DEFAULT_BASE_MSISDN;
  ctx->ggsnip = DEFAULT_GGSN;
  ctx->num_tuples = 3;
}

char *
radconf_fill_random_hex(char *value, int len)
{
  int i;

  for (i = 0; i < len; i++) {
    sprintf(&value[i * 2], "%02x", (unsigned char) rand());
  }
  value[i * 2] = 0;
  return value;
}

void
radconf_generate(radconf_context_t * ctx)
{
  char value[128];
  unsigned long long msin;
  unsigned long long msisdn;
  unsigned int ggsnip;
  int i, j;

  msin = ctx->base_msin;
  msisdn = ctx->base_msisdn;
  ggsnip = ctx->ggsnip;

  for (i = 0; i < ctx->num_ue; i++) {
    fprintf(ctx->user_conf_file, "1%u%u1%.8llu@wlan.mnc%03u.mcc%03u.3gppnetwork.org\n",
    //fprintf(ctx->user_conf_file, "1%u%u1%.8llu@wlan.mnc%03u.mcc%03u.3gppnetwork.org Auth-Type:=EAP, EAP-Type:=SIM\n",
	    ctx->mcc,
	    ctx->mnc,
	    msin,
	    ctx->mnc,
	    ctx->mcc);

    for (j = 1; j <= ctx->num_tuples; j++) {
      fprintf(ctx->user_conf_file, "\tEAP-Sim-Rand%d = 0x%s,\n", j, radconf_fill_random_hex(value, 16));
      fprintf(ctx->user_conf_file, "\tEAP-Sim-SRES%d = 0x%s,\n", j, radconf_fill_random_hex(value, 4));
      fprintf(ctx->user_conf_file, "\tEAP-Sim-KC%d = 0x%s,\n", j, radconf_fill_random_hex(value, 8));
    }

    fprintf(ctx->user_conf_file, "\tChargeable-User-Identity = \"+%llu\",\n", msisdn);
    fprintf(ctx->user_conf_file, "\t3GPP-GGSN-Address = %s,\n", inet_ntoa(*((struct in_addr*) &ggsnip )) );
    fprintf(ctx->user_conf_file, "\t3GPP-PDP-Type = 0,\n", msisdn);
    fprintf(ctx->user_conf_file, "\t3GPP-Charging-ID = %d,\n", msisdn);
    fprintf(ctx->user_conf_file, "\tAcct-Interim-Interval = %llu,\n", msisdn%180);
    fprintf(ctx->user_conf_file, "\tSession-Timeout = %llu,\n", msisdn%3600);
   
    fprintf(ctx->user_conf_file, "\n");

    msin ++;
    msisdn ++;
  }  

  fclose(ctx->user_conf_file);
}

int
main(int argc, const char * argv[])
{
  int i;
  static radconf_context_t ctx;

  radconf_init_context(&ctx);

  if (argc < 3) {
  show_usage:
    fprintf(stderr, "Usage: %s\n"
	    "\t\t--ue <num>                  ; number of UEs\n"
	    "\t\t--ggsnip <ip>               ; ggsn IP [default:10.0.20.144]\n"
	    "\t\t--user-conf <filename>      ; user-conf file to be used by FreeRADIUS\n"
	    "\t\t--mcc <ddd>                 ; mcc (optional)                        [default:%u]\n"
	    "\t\t--mnc <ddd>                 ; mnc (optional)                        [default:%u]\n"
	    "\t\t--msin <dddddddddd>         ; base msin (optional)\n                [default:%llu]\n"
	    "\t\t--base-msisdn <ddddddd>     ; base msisdn (optional)\n              [default:%llu\n"
	    "\t\t--tuples <ddd>              ; number of triplets per UE (optional)  [default:3]\n", 
	    argv[0],
	    DEFAULT_MCC,
	    DEFAULT_MNC,
	    DEFAULT_BASE_MSIN,
	    DEFAULT_BASE_MSISDN);
    return -1;
  }

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--user-conf") == 0) {
      strcpy(ctx.user_conf_filename, argv[i+1]);
      i ++;
    } else if (strcmp(argv[i], "--mcc") == 0) {
      ctx.mcc = atoi(argv[i+1]);
      i ++;
    } else if (strcmp(argv[i], "--mnc") == 0) {
      ctx.mnc = atoi(argv[i+1]);
      i ++;
    } else if (strcmp(argv[i], "--base-msin") == 0) {
      ctx.base_msin = atoll(argv[i+1]);
      i ++;
    } else if (strcmp(argv[i], "--ue") == 0) {
      ctx.num_ue = atoi(argv[i+1]);
      i ++;
    } else if (strcmp(argv[i], "--tuples") == 0) {
      ctx.num_tuples = atoi(argv[i+1]);
      i ++;
    } else if (strcmp(argv[i], "--base-msisdn") == 0) {
      ctx.base_msisdn = atoll(argv[i+1]);
      i ++;
    } else if (strcmp(argv[i], "--ggsnip") == 0) {
      //ctx.ggsnip = atoll(argv[i+1]);
      if(inet_aton((char *)argv[i+1],(struct in_addr *)&ctx.ggsnip)== 0){
	 fprintf(stderr, "Bad source IP\n");
      	 goto show_usage;
      }
      i ++;
    } else {
      goto show_usage;
    }
  }

  if (ctx.user_conf_filename[0] == 0 ||
      ctx.num_ue == 0 ||
      ctx.mcc == 0 ||
      ctx.mnc == 0 ||
      ctx.base_msin == 0 ||
      ctx.base_msisdn == 0 ||
      ctx.num_tuples < 3) {
    goto show_usage;
  }

  ctx.user_conf_file = fopen(ctx.user_conf_filename, "w");
  if (ctx.user_conf_file == NULL) {
    fprintf(stderr, "Error: cannot create user config file <%s>\n", ctx.user_conf_filename);
    return -1;
  }

  radconf_generate(&ctx);

  return 0;
}
