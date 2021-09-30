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
rad_avp_append_string(FILE * out_file, unsigned t, const char * value, char * cp)
{
  cp[0] = t;
  cp[1] = strlen(value) + 2;
  strcpy(&cp[2], value);
  cp += cp[1];
  return cp;
}

char * 
rad_avp_append_zero(unsigned t, int len, char * cp)
{
  cp[0] = t;
  cp[1] = len + 2;
  memset(&cp[2], 0, len);
  cp += cp[1];
  return cp;
}

char * 
rad_avp_append_hex_16(FILE * out_file, unsigned t, const char * value, char * cp)
{
  int i, v, d1;

  cp[0] = t;
  cp[1] = 18;

  for (i = 0; i < 16; i++) {
    v = value[i * 2];
    if (v >= '0' && v <= '9') {
      v = v - '0';
    } else if (v >= 'a' && v <= 'f') {
      v = v - 'a' + 10;
    } else if (v >= 'A' && v <= 'F') {
      v = v - 'A' + 10;
    } else {
      fprintf(out_file, "Error: invalid hex_16 <%s>\n", value);
      exit(1);
    }

    d1 = v;

    v = value[i * 2 + 1];
    if (v >= '0' && v <= '9') {
      v = v - '0';
    } else if (v >= 'a' && v <= 'f') {
      v = v - 'a' + 10;
    } else if (v >= 'A' && v <= 'F') {
      v = v - 'A' + 10;
    } else {
      fprintf(out_file, "Error: invalid hex_16 <%s>\n", value);
      exit(1);
    }

    cp[i+2] = (d1 << 4) + v;
  }

  cp += cp[1];
  return cp;
}

char * 
rad_avp_append_u16(FILE * out_file, unsigned t, const char * value, char * cp)
{
  unsigned short v;

  v = atoi(value);
  cp[0] = t;
  cp[1] = 4;
  cp[2] = v >> 8;
  cp[3] = v;
  cp += cp[1];
  return cp;
}

char * 
rad_avp_append_u32(FILE * out_file, unsigned t, const char * value, char * cp)
{
  unsigned long v;

  v = atoi(value);
  cp[0] = t;
  cp[1] = 6;
  cp[2] = v >> 24;
  cp[3] = v >> 16;
  cp[4] = v >> 8;
  cp[5] = v;
  cp += cp[1];
  return cp;
}

char * 
rad_avp_append_ip(FILE * out_file, unsigned t, const char * value, char * cp)
{
  struct in_addr ip;

  if (inet_aton(value, &ip) == 0) {
    fprintf(out_file, "Error: invalid server ip (%s)\n", value);
    exit(1);
  }
  cp[0] = t;
  cp[1] = 6;
  cp[2] = (char) ip.s_addr;
  cp[3] = (char) (ip.s_addr >> 8);
  cp[4] = ip.s_addr >> 16;
  cp[5] = ip.s_addr >> 24;
  cp += cp[1];

  return cp;
}

char * 
rad_avp_append_nas_port_type(FILE * out_file, unsigned t, const char * value, char * cp)
{
  int v;

  if (strcmp(value, "Wireless-802.11") == 0) {
    v = 19;
  } else {
    fprintf(out_file, "Error: unknown NAS-Port-Type <%s>\n", value);
    exit(1);
  }

  cp[0] = t;
  cp[1] = 6;
  cp[2] = v >> 24;
  cp[3] = v >> 16;
  cp[4] = v >> 8;
  cp[5] = v;
  cp += cp[1];
  return cp;
}

void 
rad_avp_update_message_authenticator(char * avp_message_authenticator, const rad_header_t * rad_header, size_t tx_pkt_len, const char * password)
{
  char md_value[16];

  if (avp_message_authenticator == 0) {
    return;
  }

  rad_calculate_hmac_md5(rad_header, tx_pkt_len, password, strlen(password), md_value, sizeof(md_value));
  memcpy(&avp_message_authenticator[2], md_value, sizeof(md_value));
}

void
rad_avp_append_chap_password(FILE * out_file, unsigned t, const char * value, char * cp)
{
  cp[0] = t;
  cp[1] = strlen(value) + 2;
  strcpy(&cp[2], value);
  cp += cp[1];
  return cp;
}

char *
rad_avp_append_pap_password(FILE * out_file, unsigned t, const char * value, char * cp)
{
  cp[0] = t;
  cp[1] = strlen(value) + 2;
  strcpy(&cp[2], value);
  cp += cp[1];
  return cp;
}
