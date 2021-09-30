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

void
rad_output_hex(rad_script_context_t * ctx, char * hex, unsigned int len)
{
  unsigned int i;

  for (i = 0; i < len; i++) {
    radcl_printf(ctx, "%02x", (unsigned char) hex[i]);
#if 0
    if ((i % 20) == 19) {
      radcl_printf(ctx, "\n");
    } else 
#endif 
    if ((i % 4) == 3 && i != len - 1) {
      radcl_printf(ctx, "-");
    }
  }
}

void
rad_eap_decode_at_version_list(rad_script_context_t * ctx, rad_eap_at_version_list_t * at_version_list, unsigned short attr_length)
{
  unsigned short n;
  unsigned short i;
  unsigned short version;

  n = ntohs(at_version_list->actual_length);
  if (n > attr_length || n < 2 || (n % 2) != 0) {
    radcl_printf(ctx, 
	    "Error: invalid at_version_list->actual_length=%u but attr_length=%u\n", 
	    n, 
	    attr_length);
    radcl_exit(ctx, 1);
  }

  memcpy(ctx->eap_sim.version_list, at_version_list->supported_version, n);
  ctx->eap_sim.version_list_num = n = n / 2;

  for (i = 0; i < n; i++) {
    version = ntohs(at_version_list->supported_version[i]);
    if (version == 1) {
      break;
    }
  }

  if (i == n) {
    radcl_printf(ctx, "Error: Cannot find supported version in AT_VERSION_LIST=");
    for (i = 0; i < n; i++) {
      version = ntohs(at_version_list->supported_version[i]);
      radcl_printf(ctx, "%u", version);
      if (i < n-1) {
	radcl_printf(ctx, " ");
      }
    }
    radcl_printf(ctx, "\n");
    radcl_exit(ctx, 1);
  }

  ctx->eap_sim.selected_version = version;
}

void
rad_eap_decode_at_rand(rad_script_context_t * ctx, char * cp)
{
  unsigned int n;

  ctx->eap_sim.at_rand_num = (cp[1] - 1) / 4;
  if (ctx->eap_sim.at_rand_num  == 0 || ctx->eap_sim.at_rand_num > RAD_MAX_AT_RAND_NUM) {
    radcl_printf(ctx, "Error: invalid number (%u) of random number in AT_RAND\n", ctx->eap_sim.at_rand_num);
    radcl_exit(ctx, 1);
  }
  memcpy(ctx->eap_sim.at_rand, &cp[4], ctx->eap_sim.at_rand_num * 16);

  for (n = 0; n < ctx->eap_sim.at_rand_num; n++) {
    radcl_printf(ctx, "# Info: at_rand[%d]=", n);
    rad_output_hex(ctx, (char *) &ctx->eap_sim.at_rand[n * 16], 16);
    radcl_printf(ctx, "\n");
  }
}

void
rad_eap_sim_calculate_master_keys(rad_script_context_t * ctx)
{
  unsigned char content[1024];
  int n;
  int k;
  unsigned short selected_version;
  
  for (n = 0; n < sizeof(ctx->eap_sim.master_key); n++) {
    if (ctx->eap_sim.master_key[n]) {
      break;
    }
  }

  if (n < sizeof(ctx->eap_sim.master_key)) {
    return;
  }

  radcl_printf(ctx, "# Info: Computing master key ...\n");
  n = ctx->eap_identity_length;
  memcpy(content, ctx->eap_identity, n);
  
  radcl_printf(ctx, "# Info:   Identity=");
  rad_output_hex(ctx, ctx->eap_identity, n);
  radcl_printf(ctx, "\n");

  rad_eap_sim_calculate_Kc(ctx, &content[n], ctx->eap_sim.at_rand, ctx->eap_sim.at_rand_num);

  for (k = 0; k < ctx->eap_sim.at_rand_num; k++) {
    radcl_printf(ctx, "# Info:   Kc[%d]=", k);
    rad_output_hex(ctx, (char *) &content[n + k * 8], 8);
    radcl_printf(ctx, "\n");
  }

  n += RAD_EAP_SIM_KC_SIZE * ctx->eap_sim.at_rand_num;

#if 0
  ctx->eap_sim.nonce[0] = 0xb0;
  ctx->eap_sim.nonce[1] = 0xe6;
  ctx->eap_sim.nonce[2] = 0xe0;
  ctx->eap_sim.nonce[3] = 0x9e;
  ctx->eap_sim.nonce[4] = 0x4c;
  ctx->eap_sim.nonce[5] = 0xdf;
  ctx->eap_sim.nonce[6] = 0x37;
  ctx->eap_sim.nonce[7] = 0x98;
  ctx->eap_sim.nonce[8] = 0x9f;
  ctx->eap_sim.nonce[9] = 0xd0;
  ctx->eap_sim.nonce[10] = 0xe1;
  ctx->eap_sim.nonce[11] = 0x57;
  ctx->eap_sim.nonce[12] = 0x26;
  ctx->eap_sim.nonce[13] = 0xa1;
  ctx->eap_sim.nonce[14] = 0x49;
  ctx->eap_sim.nonce[15] = 0x47;
#endif

  radcl_printf(ctx, "# Info:   Nonce=");
  rad_output_hex(ctx, ctx->eap_sim.nonce, sizeof(ctx->eap_sim.nonce));
  radcl_printf(ctx, "\n");

  memcpy(&content[n], ctx->eap_sim.nonce, sizeof(ctx->eap_sim.nonce));
  n += sizeof(ctx->eap_sim.nonce);

  memcpy(&content[n], 
	 ctx->eap_sim.version_list, 
	 ctx->eap_sim.version_list_num * sizeof(ctx->eap_sim.version_list[0]));

  radcl_printf(ctx, "# Info:   version_list=");
  rad_output_hex(ctx, (char *) ctx->eap_sim.version_list, 	 
		 ctx->eap_sim.version_list_num * sizeof(ctx->eap_sim.version_list[0]));
  radcl_printf(ctx, "\n");

  n += ctx->eap_sim.version_list_num * sizeof(ctx->eap_sim.version_list[0]);
  selected_version = htons(ctx->eap_sim.selected_version);
  memcpy(&content[n], &selected_version, sizeof(selected_version));
  n += sizeof(selected_version);

  rad_calculate_sha1(content, n, ctx->eap_sim.master_key);

  rad_calculate_eap_sim_keys(ctx->eap_sim.master_key,
			     ctx->eap_sim.K_aut,
			     ctx->eap_sim.K_encr,
			     ctx->eap_sim.msk,
			     ctx->eap_sim.emsk);

  radcl_printf(ctx, "# Info: mk=");
  rad_output_hex(ctx, ctx->eap_sim.master_key, sizeof(ctx->eap_sim.master_key));
  radcl_printf(ctx, "\n");

  radcl_printf(ctx, "# Info: K_aut=");
  rad_output_hex(ctx, ctx->eap_sim.K_aut, sizeof(ctx->eap_sim.K_aut));
  radcl_printf(ctx, "\n");

  radcl_printf(ctx, "# Info: K_encr=");
  rad_output_hex(ctx, ctx->eap_sim.K_encr, sizeof(ctx->eap_sim.K_encr));
  radcl_printf(ctx, "\n");

  radcl_printf(ctx, "# Info: msk=");
  rad_output_hex(ctx, ctx->eap_sim.msk, sizeof(ctx->eap_sim.msk));
  radcl_printf(ctx, "\n");

  radcl_printf(ctx, "# Info: emsk=");
  rad_output_hex(ctx, ctx->eap_sim.emsk, sizeof(ctx->eap_sim.emsk));
  radcl_printf(ctx, "\n");
}

void
rad_eap_decode_at_mac(rad_script_context_t * ctx, char * cp)
{
  char at_mac[16];
  char calc_mac[16];
  unsigned int c_len;

  c_len = ntohs(ctx->eap_header->length);
  memcpy(at_mac, &cp[4], sizeof(at_mac));
  memset(&cp[4], 0, sizeof(at_mac));
  rad_calculate_hmac_sha1_128((unsigned char *) ctx->eap_header, 
			      c_len,
			      (unsigned char *) ctx->eap_sim.nonce,
			      sizeof(ctx->eap_sim.nonce),
			      ctx->eap_sim.K_aut, 
			      sizeof(ctx->eap_sim.K_aut), 
			      calc_mac);
  if (memcmp(at_mac, calc_mac, sizeof(at_mac)) != 0) {
    radcl_printf(ctx, "Error: RX invalid AT_MAC=");
    rad_output_hex(ctx, at_mac, 16);
    radcl_printf(ctx, " vs ");
    rad_output_hex(ctx, calc_mac, 16);
    radcl_printf(ctx, "\n");
    radcl_exit(ctx, 1);
  }
}

void
rad_eap_decode_sim_start(rad_script_context_t * ctx, char * cp, unsigned short attr_length)
{
  char * last_cp;

  memset(ctx->eap_sim.at, 0, sizeof(ctx->eap_sim.at));

  last_cp = &cp[attr_length];
  while (cp < last_cp) {
    if (*cp != RAD_EAP_AT_VERSION_LIST &&
	*cp != RAD_EAP_AT_FULLAUTH_ID_REQ &&
	*cp != RAD_EAP_AT_PERMANENT_ID_REQ &&
	*cp != RAD_EAP_AT_ANY_ID_REQ) {
      radcl_printf(ctx, "Error: unsupported AT_xxx (%u) in EAP-SIM START\n", *cp);
      radcl_exit(ctx, 1);
    }
    ctx->eap_sim.at[(unsigned char) *cp] = cp;
    cp += cp[1] * 4;
  }

  if ((cp = ctx->eap_sim.at[RAD_EAP_AT_FULLAUTH_ID_REQ]) != 0) {
    ctx->eap_sim.auth_method = RAD_EAP_AT_FULLAUTH_ID_REQ;
    ctx->eap_sim.selected_version = 0;
    memset(ctx->eap_sim.master_key, 0, sizeof(ctx->eap_sim.master_key));
  } else if ((cp = ctx->eap_sim.at[RAD_EAP_AT_PERMANENT_ID_REQ]) != 0) {
    ctx->eap_sim.auth_method = RAD_EAP_AT_PERMANENT_ID_REQ;
    ctx->eap_sim.selected_version = 0;
    memset(ctx->eap_sim.master_key, 0, sizeof(ctx->eap_sim.master_key));
  } else if ((cp = ctx->eap_sim.at[RAD_EAP_AT_ANY_ID_REQ]) != 0) {
    ctx->eap_sim.auth_method = RAD_EAP_AT_ANY_ID_REQ;
    ctx->eap_sim.selected_version = 0;
    memset(ctx->eap_sim.master_key, 0, sizeof(ctx->eap_sim.master_key));
  }

  if ((cp = ctx->eap_sim.at[RAD_EAP_AT_VERSION_LIST]) != 0) {
      rad_eap_decode_at_version_list(ctx, (rad_eap_at_version_list_t *) &cp[2], (unsigned short) cp[1] * 4 - 2);
  }
}

void
rad_eap_decode_sim_challenge(rad_script_context_t * ctx, char * cp, unsigned short attr_length)
{
  char * last_cp;

  memset(ctx->eap_sim.at, 0, sizeof(ctx->eap_sim.at));

  last_cp = &cp[attr_length];
  while (cp < last_cp) {
    if (*cp != RAD_EAP_AT_RAND &&
	*cp != RAD_EAP_AT_MAC) {
      radcl_printf(ctx, "Error: unsupported AT_xxx (%u) in EAP-SIM CHALLENGE\n", *cp);
      radcl_exit(ctx, 1);
    }
    ctx->eap_sim.at[(unsigned char) *cp] = cp;
    cp += cp[1] * 4;
  }

  if ((cp = ctx->eap_sim.at[RAD_EAP_AT_RAND]) != 0) {
    rad_eap_decode_at_rand(ctx, cp);
    rad_eap_sim_calculate_master_keys(ctx);
  }

  if ((cp = ctx->eap_sim.at[RAD_EAP_AT_MAC]) != 0) {
    rad_eap_decode_at_mac(ctx, cp);
  }
}

void
rad_eap_decode_md5(rad_script_context_t * ctx, char * cp)
{
//TODO
}
void
rad_eap_decode_md5_challenge(rad_script_context_t * ctx, char * cp, unsigned short attr_length)
{
  char * last_cp;

  last_cp = &cp[attr_length];
  rad_eap_decode_md5(ctx, cp);
}
void
rad_eap_decode(rad_script_context_t * ctx, rad_eap_header_t * eap_header, unsigned short eap_length)
{
  unsigned char subtype;
  char * cp;

  if (ntohs(eap_header->length) != eap_length) {
    radcl_printf(ctx, "Error: invalid eap length. eap_header->length=%u avp:eap_message->length=%u\n", 
	    ntohs(eap_header->length), eap_length);
    radcl_exit(ctx, 1);
  }

  ctx->eap_header = eap_header;
  ctx->eap_identifier = eap_header->identifier;
  switch (eap_header->code) {
    case RAD_EAP_CODE_REQUEST:
        switch (eap_header->type) {
            case RAD_EAP_TYPE_SIM:
              subtype = ((rad_eap_header_ext_t *) eap_header)->subtype;
              cp = (char *) &(((rad_eap_header_ext_t *) eap_header)[1]);
              switch (subtype) {
                case RAD_EAP_SIM_SUBTYPE_START:
                    rad_eap_decode_sim_start(ctx, cp, eap_length - sizeof(rad_eap_header_ext_t));
                    break;
                case RAD_EAP_SIM_SUBTYPE_CHALLENGE:
                    rad_eap_decode_sim_challenge(ctx, cp, eap_length - sizeof(rad_eap_header_ext_t));
                    break;
                default:
                    radcl_printf(ctx, "Error: unknown eap-sim subtype %u\n", subtype);
                    radcl_exit(ctx, 1);
              }
              break;

            case RAD_EAP_TYPE_MD5_CHALLENGE:
                if ( 0 == 0) {
                    radcl_printf(ctx, "Processing:  eap type MD5-Challenge (%u)\n", eap_header->type);
                    cp = (char *) &(((rad_eap_header_md5_t_ *) eap_header)[1]);
                    rad_eap_decode_md5_challenge(ctx, cp, eap_length - sizeof(rad_eap_header_md5_t_));
                } else {
                  radcl_printf(ctx, "Error: unsupported eap type MD5-Challenge (%u)\n", eap_header->type);
                  radcl_exit(ctx, 1);
                }

            default:
              radcl_printf(ctx, "Error: unsupported eap type (%u)\n", eap_header->type);
              radcl_exit(ctx, 1);
        }
        break;

    case RAD_EAP_CODE_SUCCESS:
        radcl_printf(ctx, "Result: Access-Accept\n");
        radcl_exit(ctx, 0);
        break;

    case RAD_EAP_CODE_FAILURE:
        radcl_printf(ctx, "Result: Access-Reject\n");
        radcl_exit(ctx, 0);
        break;

    default:
        radcl_printf(ctx, "Error: unsupport eap code (%u)\n", eap_header->code);
        radcl_exit(ctx, 1);
  }
}
