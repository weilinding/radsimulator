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
rad_avp_decode_state(rad_script_context_t * ctx, char * cp, unsigned short len)
{
  if (len != sizeof(ctx->avp_state)) {
    radcl_printf(ctx, "Error: invalid AVP_STATE->length=%u should be 16\n", len);
    radcl_exit(ctx, 1);
  }
  memcpy(ctx->avp_state, cp, sizeof(ctx->avp_state));
}

void
rad_avp_decode(rad_script_context_t * ctx)
{
  char * cp;
  char rx_message_authenticator[16];

  memset(ctx->rx_avp, 0, sizeof(ctx->rx_avp));
  cp = (char *) &ctx->rad_header[1];
  while (cp < &ctx->rx_buf[ctx->rx_buf_len]) {
    ctx->rx_avp[(unsigned char) *cp] = cp;
    cp += cp[1];
  }

  if (cp != &ctx->rx_buf[ctx->rx_buf_len]) {
    radcl_printf(ctx, "Error: invalid message format\n");
    radcl_exit(ctx, 1);
  }

  if (ctx->rx_avp[RAD_AVP_MESSAGE_AUTHENTICATOR]) {
    cp = ctx->rx_avp[RAD_AVP_MESSAGE_AUTHENTICATOR];
    memcpy(rx_message_authenticator, cp + 2, sizeof(rx_message_authenticator));
    memset(cp + 2, 0, sizeof(rx_message_authenticator));
    memcpy(ctx->rad_header->authenticator, ((rad_header_t *) ctx->tx_buf)->authenticator, sizeof(ctx->rad_header->authenticator));
    rad_avp_update_message_authenticator(cp, ctx->rad_header, ctx->rx_buf_len, ctx->password);
    if (memcmp(rx_message_authenticator, cp + 2, sizeof(rx_message_authenticator)) != 0) {
      radcl_printf(ctx, "Error: invalid message authenticator.\n");
      radcl_exit(ctx, 1);
    }
  }

  switch (ctx->rad_header->code) {
  case RAD_CODE_CHALLENGE:
    if ((cp = ctx->rx_avp[RAD_AVP_EAP_MESSAGE]) != 0) {
      rad_eap_decode(ctx, (rad_eap_header_t *) &cp[2], (unsigned short) cp[1] - 2); 
    } else {
      radcl_printf(ctx, "Error: missing EAP message in Challenge\n");
      radcl_exit(ctx, 1);
    }

    if ((cp = ctx->rx_avp[RAD_AVP_STATE]) != 0) {
      rad_avp_decode_state(ctx, &cp[2], (unsigned short) cp[1] - 2);
    }
    break;

  case RAD_CODE_ACCESS_ACCEPT:
    if ((cp = ctx->rx_avp[RAD_AVP_EAP_MESSAGE]) != 0) {
      rad_eap_decode(ctx, (rad_eap_header_t *) &cp[2], (unsigned short) cp[1] - 2); 
    } else {
      radcl_printf(ctx, "Result: Access-Accept, but missing EAP message in Access-Accept\n");
      radcl_exit(ctx, 1);
    }

    break;

  case RAD_CODE_ACCESS_REJECT:
    if ((cp = ctx->rx_avp[RAD_AVP_EAP_MESSAGE]) != 0) {
      rad_eap_decode(ctx, (rad_eap_header_t *) &cp[2], (unsigned short) cp[1] - 2); 
    } else {
      radcl_printf(ctx, "Result: Access-Reject (without EAP message in Access-Reject)\n");
      radcl_exit(ctx, 1);
    }
    break;

  default:
    radcl_printf(ctx, "Error: unsupported RADIUS code %d\n", ctx->rad_header->code);
    radcl_exit(ctx, 1);
  }
}
