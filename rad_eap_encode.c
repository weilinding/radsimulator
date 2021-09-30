#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "rad_dict.h"
#include "rad_script.h"
#include "rad_crypto.h"

char * 
rad_eap_append_string(FILE * out_file, const char * value, char * cp)
{
  strcpy(cp, value);
  cp += strlen(value);
  return cp;
}

char *
rad_eap_append_at_mac(rad_script_context_t * ctx, char * cp)
{
  ctx->eap_sim.at[RAD_EAP_AT_MAC] = cp;
  cp[0] = RAD_EAP_AT_MAC;
  cp[1] = 5;
  cp += cp[1] * 4;
  return cp;
}

void
rad_eap_update_at_mac(rad_script_context_t * ctx)
{
  char * cp;
  unsigned int c_len;
  unsigned char sres[RAD_MAX_AT_RAND_NUM * RAD_EAP_SIM_SRES_SIZE];

  rad_eap_sim_calculate_SRES(ctx, sres, ctx->eap_sim.at_rand, ctx->eap_sim.at_rand_num);

  if ((cp = ctx->eap_sim.at[RAD_EAP_AT_MAC]) != 0) {
    c_len = ntohs(ctx->eap_header->length);
    rad_calculate_hmac_sha1_128((unsigned char *) ctx->eap_header, 
				c_len,
				sres,
				ctx->eap_sim.at_rand_num * RAD_EAP_SIM_SRES_SIZE,
				ctx->eap_sim.K_aut, 
				sizeof(ctx->eap_sim.K_aut), 
				&cp[4]);
  }
}
