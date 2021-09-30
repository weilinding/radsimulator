#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "rad_dict.h"
#include "rad_script.h"

void
rad_eap_sim_calculate_Kc(rad_script_context_t * ctx, unsigned char * kc, const unsigned char * rand, unsigned kc_num)
{
  int n, k;
  
  for (n = 0; n < kc_num; n++) {
    for (k = 0; k <  RAD_MAX_TUPLE_NUM; k++) {
      if (memcmp(&rand[n * 16], ctx->eap_sim.tuple[k].rand, sizeof(ctx->eap_sim.tuple[k].rand)) == 0) {
	memcpy(&kc[n * RAD_EAP_SIM_KC_SIZE], ctx->eap_sim.tuple[k].kc, RAD_EAP_SIM_KC_SIZE);
	break;
      }
    }

    if (k == RAD_MAX_TUPLE_NUM) {
      radcl_printf(ctx, "Error: rand ");
      rad_output_hex(ctx, (char *) &rand[n * 16], 16);
      radcl_printf(ctx, " from remote is not defined\n");

      for (k = 0; k < RAD_MAX_TUPLE_NUM; k++) {
	radcl_printf(ctx, "tuple[%d].rand=", k);
	rad_output_hex(ctx, ctx->eap_sim.tuple[k].rand, 16);
	radcl_printf(ctx, "\n");
      }

      radcl_exit(ctx, 1);
    }
  }
}

void
rad_eap_sim_calculate_SRES(rad_script_context_t * ctx, unsigned char * sres, const unsigned char * rand, unsigned sres_num)
{
  int n, k;
  
  for (n = 0; n < sres_num; n++) {
    for (k = 0; k < RAD_MAX_TUPLE_NUM; k++) {
      if (memcmp(&rand[n * 16], ctx->eap_sim.tuple[k].rand, sizeof(ctx->eap_sim.tuple[k].rand)) == 0) {
	memcpy(&sres[n * RAD_EAP_SIM_SRES_SIZE], ctx->eap_sim.tuple[k].sres, RAD_EAP_SIM_SRES_SIZE);
	break;
      }
    }

    if (k == RAD_MAX_TUPLE_NUM) {
      radcl_printf(ctx, "Error: rand ");
      rad_output_hex(ctx, (char *) &rand[n * 16], 16);
      radcl_printf(ctx, " from remote is not defined\n");

      for (k = 0; k < RAD_MAX_TUPLE_NUM; k++) {
	radcl_printf(ctx, "tuple[%d].rand=", k);
	rad_output_hex(ctx, ctx->eap_sim.tuple[k].rand, 16);
	radcl_printf(ctx, "\n");
      }

      radcl_exit(ctx, 1);
    }
  }
}

