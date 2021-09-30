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

#define RAD_RX_SLEEP_USECONDS  1000
#define RAD_RX_RETRY_TIMES     (4000 * (1000000 / RAD_RX_SLEEP_USECONDS))
#define RAD_TX_RETRY_INTERVAL  ((unsigned long) (ctx->tx_retry_usec / RAD_RX_SLEEP_USECONDS))

void
rad_open_socket(rad_script_context_t * ctx)
{
  struct sockaddr_in si_me;
  int s;
  int optval;

  if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1) {
    radcl_printf(ctx, "Error: cannot create udp socket\n");
    radcl_exit(ctx, 1);
  }
    
  if (ctx->local_ip != INADDR_ANY || ctx->local_udp_port) {
    optval = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    memset((char *) &si_me, 0, sizeof(si_me));
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(ctx->local_udp_port);
    si_me.sin_addr.s_addr = htonl(ctx->local_ip);
    if (bind(s, (struct sockaddr *) &si_me, sizeof(si_me))==-1) {
      struct in_addr local_ip;
      local_ip.s_addr = htonl(ctx->local_ip);
      radcl_printf(ctx, "Error: cannot bind to udp port (%s:%u)\n", inet_ntoa(local_ip), ctx->local_udp_port);
      radcl_exit(ctx, 1);
    }
  }

  ctx->s = s;
}

int 
fetch_line(rad_script_context_t * ctx, char ** field_p, char ** value_p)
{
  int    i;
  char * field;
  char * value;
  char * last;

  if (ctx->show_prompt) {
    radcl_printf(ctx, ctx->input_prompt);
    fflush(ctx->out_file);
  }
  
  if (radcl_gets(ctx, ctx->line, sizeof(ctx->line)) == NULL) {
    radcl_printf(ctx, "\n");
    return -1;
  }

  if (ctx->echo_input) {
    radcl_printf(ctx, "%s", ctx->line);
  }

  field = ctx->line;
  while (*field != 0 && isspace(*field)) {
    field ++;
  }
  
  if (*field == '#' || *field == 0) {
    return 0;
  }

  for (i = 0; field[i] != 0 && field[i] != '=' && field[i] != '\n' && field[i] != '#'; i++) {
  } 

  if (field[i] != '=') {
    field[i] = 0;
    value = 0;
  } else {
    field[i] = 0;
    value = &field[i+1];
    for (i = 0; value[i] != 0 && value[i] != '\n' && value[i] != '\r' && value[i] != '#'; i++) {
    }
    value[i] = 0;
  }

  if (field) {
    while (*field != 0 && isspace(*field)) {
      field ++;
    }

    last = field + strlen(field) - 1;
    while (last > field && isspace(*last)) {
      last --;
    }
  
    if (last < field) {
      field = NULL;
    } else {
      last[1] = 0;
    }
  }

  if (value) {
    while (*value != 0 && isspace(*value)) {
      value ++;
    }

    last = value + strlen(value) - 1;
    while (last > value && isspace(*last)) {
      last --;
    }

    if (last < value) {
      value = NULL;
    } else {
      last[1] = 0;
    }
  }

#if 0
  if (value == 0) {
    radcl_printf(ctx, "# Info: F=<%s>\n", field);
  } else {
    radcl_printf(ctx, "# Info: F=<%s> V=<%s>\n", field, value);
  }
#endif

  fflush(ctx->out_file);
  *field_p = field;
  *value_p = value;
  return 1;
}

void 
rad_script_init_context(rad_script_context_t * ctx, 
			FILE * in_file, 
			FILE * out_file, 
			long remote_ip, 
			short remote_udp_port, 
			long local_ip, 
			short local_udp_port)
{
  memset(ctx, 0, sizeof(*ctx));
  ctx->in_file = in_file;
  ctx->out_file = out_file;
  ctx->remote_ip = remote_ip;
  ctx->remote_udp_port = remote_udp_port;
  ctx->local_ip = local_ip;
  ctx->local_udp_port = local_udp_port;
  ctx->echo_input = 0;
  ctx->s = -1;
  ctx->tx_retry_usec = RAD_DEFAULT_TX_RETRY_INTERVAL_USEC;
  strncpy(ctx->input_prompt, "< ", sizeof(ctx->input_prompt));
  strncpy(ctx->output_prompt, "> ", sizeof(ctx->output_prompt));
}


void
rad_tx_packet(rad_script_context_t * ctx)
{
  int ret;
  ret = sendto(ctx->s, ctx->tx_buf, ctx->tx_buf_len, 0, (const struct sockaddr *) &ctx->si_other, sizeof(ctx->si_other));
  if (ret != ctx->tx_buf_len) {
    radcl_printf(ctx, "Error: failed to send the packet\n");
    radcl_exit(ctx, 1);
  }
}

void
rad_rx_packet(rad_script_context_t * ctx)
{
  int i;
  int ret;
  struct sockaddr_in si_source;
  socklen_t sock_len;

  for (i = 0; i < RAD_RX_RETRY_TIMES; i++) {
    sock_len = sizeof(si_source);
    ret = recvfrom(ctx->s, ctx->rx_buf, sizeof(ctx->rx_buf), MSG_DONTWAIT, (struct sockaddr *) &si_source, &sock_len);
    if (ret <= 0) {
      usleep(RAD_RX_SLEEP_USECONDS);
    } else if ((sock_len == sizeof(si_source) && memcmp(&ctx->si_other, &si_source, sizeof(si_source)) == 0) || 
	       ctx->si_other.sin_addr.s_addr == htonl(0x7f000001) /* don't check source if talking to server at loopback address */) {
      ctx->rx_buf_len = ret;
      break;
    } else {
      /*
      radcl_printf(ctx, "# Info: waiting for packet from source %s\n", inet_ntoa(ctx->si_other.sin_addr));
      radcl_printf(ctx, "# Info: dropping packet from source    %s\n", inet_ntoa(si_source.sin_addr));
      */
    }

    if ((i % RAD_TX_RETRY_INTERVAL) == 1) {
      /*
      radcl_printf(ctx, "Info: retry #%d since no message back from the server\n", i);
      */
      rad_tx_packet(ctx);
    }
  }

  if (i == RAD_RX_RETRY_TIMES) {
    radcl_printf(ctx, "Error: no message back from the server\n");
    radcl_exit(ctx, 1);
  }
}

int
rad_decode_packet(rad_script_context_t * ctx)
{
  int len;
  char authenticator[16];
  char fake_rx_buf[RADIUS_BUFLEN + sizeof(ctx->password)];

  ctx->rad_header = (rad_header_t *) ctx->rx_buf;
  len = ntohs(ctx->rad_header->length);
  if (len != ctx->rx_buf_len) {
    radcl_printf(ctx, "Error: receive invalid packet length. udp_len=%u header->len=%u\n", ctx->rx_buf_len, len);
    radcl_exit(ctx, 1);
  }

  if (ctx->packet_identifier != ctx->rad_header->packet_identifier) {
    if (ctx->packet_identifier > ctx->rad_header->packet_identifier) {
      radcl_printf(ctx, "Info: ignore old packet\n");
      return 1;
    } else {
      radcl_printf(ctx, "Error: invalid packet_identifier. expect=%u header->packet_identifier=%u\n", 
		   ctx->packet_identifier, 
		   ctx->rad_header->packet_identifier);
      radcl_exit(ctx, 1);
    }
  }

  memcpy(fake_rx_buf, ctx->rx_buf, len);
  memcpy(((rad_header_t *) fake_rx_buf)->authenticator, ((rad_header_t *) ctx->tx_buf)->authenticator, sizeof(ctx->rad_header->authenticator));
  strcpy(fake_rx_buf + len, ctx->password);
  rad_calculate_md5(fake_rx_buf, len + strlen(ctx->password), authenticator);
  if (memcmp(ctx->rad_header->authenticator, authenticator, sizeof(authenticator)) != 0) {
    radcl_printf(ctx, "Error: invalid header->authenticator. please check radius client password (%s).\n", ctx->password);
    radcl_exit(ctx, 1);
  }

  ctx->packet_identifier ++;

  rad_avp_decode(ctx);
  return 0;
}

void
rad_update_random(char * buffer, int size)
{
  int n;

  for (n = 0; n < size; n ++) {
    buffer[n] = rand();
  }
}

void
rad_set_hex(rad_script_context_t * ctx, char * source, char * target, unsigned short target_len)
{
  int i, v, d1;

  for (i = 0; i < target_len; i++) {
    v = source[i * 2];
    if (v >= '0' && v <= '9') {
      v = v - '0';
    } else if (v >= 'a' && v <= 'f') {
      v = v - 'a' + 10;
    } else if (v >= 'A' && v <= 'F') {
      v = v - 'A' + 10;
    } else {
      radcl_printf(ctx, "Error: invalid hex_%d <%s>\n", target_len, source);
      radcl_exit(ctx, 1);
    }

    d1 = v;

    v = source[i * 2 + 1];
    if (v >= '0' && v <= '9') {
      v = v - '0';
    } else if (v >= 'a' && v <= 'f') {
      v = v - 'a' + 10;
    } else if (v >= 'A' && v <= 'F') {
      v = v - 'A' + 10;
    } else {
      radcl_printf(ctx, "Error: invalid hex_%d <%s>\n", target_len, source);
      radcl_exit(ctx, 1);
    }

    target[i] = (d1 << 4) + v;
  }
}

void
rad_run_script(rad_script_context_t * ctx)
{
  int ret;
  char * field;
  char * value;
  char * cp;

  ctx->packet_identifier = 1;

  if (ctx->show_prompt) {
    radcl_printf(ctx, "# input your command at stdin ...\n");
  }

  while (1) {
    ret = fetch_line(ctx, &field, &value);
    if (ret == -1) {
      break;
    } else if (ret == 0) {
      continue;
    }

    if (strcmp(field, "Open") == 0) {
      rad_open_socket(ctx);
      memset((char *) &ctx->si_other, 0, sizeof(ctx->si_other));
      ctx->si_other.sin_family = AF_INET;
      ctx->si_other.sin_port = htons(ctx->remote_udp_port);
      ctx->si_other.sin_addr.s_addr = htonl(ctx->remote_ip);
    } else if (strcmp(field, "TX-Begin") == 0) {
      memset(ctx->tx_buf, 0, sizeof(ctx->tx_buf));
      memset(ctx->eap_sim.at, 0, sizeof(ctx->eap_sim.at));
      ctx->rad_header = (rad_header_t *) ctx->tx_buf;
      ctx->avp_message_authenticator = 0;
      ctx->avp_eap_header = 0;
      cp = &ctx->tx_buf[sizeof(rad_header_t)];
    } else if (strcmp(field, "TX-End") == 0) {
      ctx->tx_buf_len = cp - ctx->tx_buf;
      ctx->rad_header->packet_identifier = ctx->packet_identifier;
      ctx->rad_header->length = htons(ctx->tx_buf_len);
      rad_update_random(ctx->rad_header->authenticator, 16);
      rad_avp_update_message_authenticator(ctx->avp_message_authenticator, ctx->rad_header, ctx->tx_buf_len, ctx->password);
      rad_tx_packet(ctx);
    } else if (strcmp(field, "Close") == 0) {
      close(ctx->s);
      break;
    } else if (strcmp(field, "Password") == 0) {
      strncpy(ctx->password, value, sizeof(ctx->password));
    } else if (strcmp(field, "Echo-Input") == 0) {
      ctx->echo_input = atoi(value);
    } else if (strcmp(field, "Packet-Identifier") == 0) {
      if (strcmp(value, "Auto") == 0) {
	ctx->rad_header->packet_identifier = ctx->packet_identifier;
      } else {
	ctx->packet_identifier = atoi(value);
      }
    } else if (strcmp(field, "Code") == 0) {
      if (strcmp(value, "Access-Request") == 0) {
	ctx->rad_header->code = RAD_CODE_ACCESS_REQUEST;
      } else if (strcmp(value, "Account-Request") == 0) {
	ctx->rad_header->code = RAD_CODE_ACCOUNT_REQ;
      }
    } else if (strcmp(field, "AVP:User-Name") == 0) {
      cp = rad_avp_append_string(ctx->out_file, RAD_AVP_USER_NAME, value, cp);
    } else if (strcmp(field, "AVP:User-Password") == 0) {
      cp = rad_avp_append_pap_password(ctx->out_file, RAD_AVP_USER_PASSWORD, value, cp);
    } else if (strcmp(field, "AVP:CHAP-Password") == 0) {
      cp = rad_avp_append_chap_password(ctx->out_file, RAD_AVP_CHAP_PASSWORD, value, cp);
    } else if (strcmp(field, "AVP:NAS-IP-Address") == 0) {
      cp = rad_avp_append_ip(ctx->out_file, RAD_AVP_NAS_IP_ADDRESS, value, cp);
    } else if (strcmp(field, "AVP:NAS-Identifier") == 0) {
      cp = rad_avp_append_string(ctx->out_file, RAD_AVP_NAS_IDENTIFIER, value, cp);
    } else if (strcmp(field, "AVP:NAS-Port") == 0) {
      cp = rad_avp_append_u32(ctx->out_file, RAD_AVP_NAS_PORT, value, cp);
    } else if (strcmp(field, "AVP:Called-Station-Id") == 0) {
      cp = rad_avp_append_string(ctx->out_file, RAD_AVP_CALLED_STATION_ID, value, cp);
    } else if (strcmp(field, "AVP:Calling-Station-Id") == 0) {
      cp = rad_avp_append_string(ctx->out_file, RAD_AVP_CALLING_STATION_ID, value, cp);
    } else if (strcmp(field, "AVP:Framed-MTU") == 0) {
      cp = rad_avp_append_u32(ctx->out_file, RAD_AVP_FRAMED_MTU, value, cp);
    } else if (strcmp(field, "AVP:NAS-Port-Type") == 0) {
      cp = rad_avp_append_nas_port_type(ctx->out_file, RAD_AVP_NAS_PORT_TYPE, value, cp);
    } else if (strcmp(field, "AVP:Connect-Info") == 0) {
      cp = rad_avp_append_string(ctx->out_file, RAD_AVP_CONNECT_INFO, value, cp);
    } else if (strcmp(field, "AVP:Message-Authenticator") == 0) {
      if (strcmp(value, "Auto") == 0) {
	ctx->avp_message_authenticator = cp;
	cp = rad_avp_append_zero(RAD_AVP_MESSAGE_AUTHENTICATOR, 16, cp);
      } else {
	cp = rad_avp_append_hex_16(ctx->out_file, RAD_AVP_MESSAGE_AUTHENTICATOR, value, cp);
      }
    } else if (strcmp(field, "EAP-Begin") == 0) {
      ctx->avp_eap_header = cp;
      cp[0] = RAD_AVP_EAP_MESSAGE;
      cp += 2;
      ctx->eap_header = (rad_eap_header_t *) cp;
      ctx->eap_header->identifier = ctx->eap_identifier;
      cp = (char *) &ctx->eap_header[1];
    } else if (strcmp(field, "EAP-End") == 0) {
      int n = cp - (char *) ctx->eap_header;
      ctx->eap_header->length = htons(n);
      ctx->avp_eap_header[1] = n + 2;
      rad_eap_update_at_mac(ctx);
    } else if (strcmp(field, "EAP:Code") == 0) {
      if (strcmp(value, "Request") == 0) {
	ctx->eap_header->code = RAD_EAP_CODE_REQUEST;
      } else if (strcmp(value, "Response") == 0) {
	ctx->eap_header->code = RAD_EAP_CODE_RESPONSE;
      } else {
	radcl_printf(ctx, "Error: unknown EAP:Code <%s>\n", value);
	radcl_exit(ctx, 1);
      }
    } else if (strcmp(field, "EAP:Id") == 0) {
      if (strcmp(value, "Auto") == 0) {
	ctx->eap_header->identifier = ctx->eap_identifier;
      } else {
	ctx->eap_header->identifier = atoi(value);
      }
    } else if (strcmp(field, "EAP:Type") == 0) {
      if (strcmp(value, "Identity") == 0) {
	ctx->eap_header->type = RAD_EAP_TYPE_IDENTITY;
      } else if (strcmp(value, "EAP-SIM") == 0) {
	ctx->eap_header->type = RAD_EAP_TYPE_SIM;
	} else if (strcmp(value, "EAP-MD5") == 0) {
	ctx->eap_header->type = RAD_EAP_TYPE_MD5;
      } else {
	radcl_printf(ctx, "Error: unknown EAP:Type <%s>\n", value);
	radcl_exit(ctx, 1);
      }
    } else if (strcmp(field, "EAP:Subtype") == 0) {
      if (strcmp(value, "Start") == 0) {
	rad_eap_header_ext_t * eap_header_ext;
	eap_header_ext = (rad_eap_header_ext_t *) ctx->eap_header;
	eap_header_ext->subtype = RAD_EAP_SIM_SUBTYPE_START;
	cp = (char *) &eap_header_ext[1];
      } else if (strcmp(value, "Challenge") == 0) {
	rad_eap_header_ext_t * eap_header_ext;
	eap_header_ext = (rad_eap_header_ext_t *) ctx->eap_header;
	eap_header_ext->subtype = RAD_EAP_SIM_SUBTYPE_CHALLENGE;
	cp = (char *) &eap_header_ext[1];
      } else {
	radcl_printf(ctx, "Error: unknown EAP:Subtype=<%s>\n", value);
	radcl_exit(ctx, 1);
      }
    } else if (strcmp(field, "EAP:Identity") == 0) {
      cp = rad_eap_append_string(ctx->out_file, value, cp);
    } else if (strcmp(field, "RX-Begin") == 0) {
    } else if (strcmp(field, "RX-End") == 0) {
      do {
	rad_rx_packet(ctx);
      } while (rad_decode_packet(ctx));
    } else if (strcmp(field, "EAP:AT_SELECTED_VERSION") == 0) {
      unsigned short version;
      if (strcmp(value, "Auto") == 0) {
	version = ctx->eap_sim.selected_version;
      } else {
	version = atoi(value);
      }

      cp[0] = RAD_EAP_AT_SELECTED_VERSION;
      cp[1] = 1;
      cp[2] = version >> 8;
      cp[3] = version;
      cp += cp[1] * 4;
    } else if (strcmp(field, "EAP:AT_NONCE_MT") == 0) {
      if (strcmp(value, "Auto") == 0) {
	cp[0] = RAD_EAP_AT_NONCE_MT;
	cp[1] = 5;
	rad_update_random(ctx->eap_sim.nonce, 16);
	memcpy(cp + 4, ctx->eap_sim.nonce, sizeof(ctx->eap_sim.nonce));
	cp += cp[1] * 4;
      } else {
	radcl_printf(ctx, "Error: AT_NONCE_MT supports <Auto> only\n");
	radcl_exit(ctx, 1);
      }
    } else if (strcmp(field, "EAP:AT_MAC") == 0) {
      if (strcmp(value, "Auto") == 0) {
	cp = rad_eap_append_at_mac(ctx, cp);
      } else {
	radcl_printf(ctx, "Error: AT_CHALLENGE supports <Auto> only\n");
	radcl_exit(ctx, 1);
      }
    } else if (strcmp(field, "EAP:AT_IDENTITY") == 0) {
      unsigned short n;

      n = strlen(value);

      ctx->eap_identity_length = n;
      memcpy(ctx->eap_identity, value, n);

      cp[0] = RAD_EAP_AT_IDENTITY;
      cp[1] = (n + 7) / 4;
      cp[2] = n >> 8;
      cp[3] = n;
      strcpy(cp + 4, value);
      cp += cp[1] * 4;
    } else if (strcmp(field, "AVP:State") == 0) {
      if (strcmp(value, "Auto") == 0) {
	cp[0] = RAD_AVP_STATE;
	cp[1] = sizeof(ctx->avp_state) + 2;
	memcpy(cp+2, ctx->avp_state, sizeof(ctx->avp_state));
	cp += cp[1];
      } else {
	cp = rad_avp_append_hex_16(ctx->out_file, RAD_AVP_STATE, value, cp);
      }
    } else if (strcmp(field, "EAP-SIM-RAND1") == 0) {
      rad_set_hex(ctx, value, ctx->eap_sim.tuple[0].rand, 16);
    } else if (strcmp(field, "EAP-SIM-RAND2") == 0) {
      rad_set_hex(ctx, value, ctx->eap_sim.tuple[1].rand, 16);
    } else if (strcmp(field, "EAP-SIM-RAND3") == 0) {
      rad_set_hex(ctx, value, ctx->eap_sim.tuple[2].rand, 16);
    } else if (strcmp(field, "EAP-SIM-SRES1") == 0) {
      rad_set_hex(ctx, value, ctx->eap_sim.tuple[0].sres, 4);
    } else if (strcmp(field, "EAP-SIM-SRES2") == 0) {
      rad_set_hex(ctx, value, ctx->eap_sim.tuple[1].sres, 4);
    } else if (strcmp(field, "EAP-SIM-SRES3") == 0) {
      rad_set_hex(ctx, value, ctx->eap_sim.tuple[2].sres, 4);
    } else if (strcmp(field, "EAP-SIM-KC1") == 0) {
      rad_set_hex(ctx, value, ctx->eap_sim.tuple[0].kc, 8);
    } else if (strcmp(field, "EAP-SIM-KC2") == 0) {
      rad_set_hex(ctx, value, ctx->eap_sim.tuple[1].kc, 8);
    } else if (strcmp(field, "EAP-SIM-KC3") == 0) {
      rad_set_hex(ctx, value, ctx->eap_sim.tuple[2].kc, 8);
    } else {
      radcl_printf(ctx, "Error: unknown command <%s>\n", field);
      radcl_exit(ctx, 1);
    }
  }
}
