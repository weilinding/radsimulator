#ifndef __RAD_FILE_H
#define __RAD_FILE_H

#define RADIUS_BUFLEN            (2 * 1024)
#define RAD_MAX_AT_RAND_NUM      5
#define RAD_MAX_TUPLE_NUM        10
#define RAD_DEFAULT_TX_RETRY_INTERVAL_USEC 1500000
#define MAX_STRING_LEN		254
#define AUTH_VECTOR_LEN		16

typedef struct rad_eap_sim_tuple_t_
{
  char rand[16];
  char sres[4];
  char kc[8];
} rad_eap_sim_tuple_t;

typedef struct rad_script_context_t_
{
  int echo_input;
  int show_prompt;
  unsigned long tx_retry_usec;
  char line[1024];
  FILE * in_file;
  FILE * out_file;
  char input_prompt[32];
  char output_prompt[32];
  long remote_ip;
  short remote_udp_port;
  long local_ip;
  short local_udp_port;
  unsigned char packet_identifier;
  rad_header_t * rad_header;
  struct sockaddr_in si_other;
  char tx_buf[RADIUS_BUFLEN];
  char rx_buf[RADIUS_BUFLEN];
  int tx_buf_len;
  int rx_buf_len;
  int s;
  char password[128];
  char * avp_message_authenticator;
  rad_eap_header_t * eap_header;
  char * avp_eap_header;
  char * rx_avp[256];
  char avp_state[16];
  unsigned eap_identifier;
  char eap_identity[256];
  unsigned short eap_identity_length;
  struct {
    char * at[256];
    unsigned short selected_version;
    unsigned short version_list[5];
    unsigned short version_list_num;
    unsigned char auth_method;
    char nonce[16];
    unsigned short at_rand_num;
    unsigned char at_rand[RAD_MAX_AT_RAND_NUM * 16];
    char master_key[20];
    char K_aut[16];
    char K_encr[16];
    char emsk[64];
    char msk[64];
    rad_eap_sim_tuple_t tuple[RAD_MAX_TUPLE_NUM];
  } eap_sim;

  struct radcl_thread_t_ * thread;

} rad_script_context_t;

void
rad_script_init_context(rad_script_context_t * ctx,
			FILE * in_file,
			FILE * out_file,
			long remote_ip,
			short remote_udp_port,
			long local_ip,
			short local_udp_port);

void rad_run_script(rad_script_context_t * ctx);

char * rad_avp_append_string(FILE * out_file, unsigned t, const char * value, char * cp);
char * rad_avp_append_pap_password(FILE * out_file, unsigned t, const char * value, char * cp);
char * rad_avp_append_chap_password(FILE * out_file, unsigned t, const char * value, char * cp);


char * rad_avp_append_zero(unsigned t, int len, char * cp);
char * rad_avp_append_hex_16(FILE * out_file, unsigned t, const char * value, char * cp);
char * rad_avp_append_u16(FILE * out_file, unsigned t, const char * value, char * cp);
char * rad_avp_append_u32(FILE * out_file, unsigned t, const char * value, char * cp);
char * rad_avp_append_ip(FILE * out_file, unsigned t, const char * value, char * cp);
char * rad_avp_append_nas_port_type(FILE * out_file, unsigned t, const char * value, char * cp);
void rad_avp_update_message_authenticator(char * avp_message_authenticator, const rad_header_t * rad_header, size_t tx_pkt_len, const char * password);

void rad_avp_decode(rad_script_context_t * ctx);

char * rad_eap_append_string(FILE * out_file, const char * value, char * cp);
char * rad_eap_append_at_mac(rad_script_context_t * ctx, char * cp);
void rad_eap_update_at_mac(rad_script_context_t * ctx);
void rad_eap_decode(rad_script_context_t * ctx, rad_eap_header_t * eap_header, unsigned short eap_length);
void rad_eap_sim_calculate_Kc(rad_script_context_t * ctx, unsigned char * kc, const unsigned char * rand, unsigned kc_num);
void rad_eap_sim_calculate_SRES(rad_script_context_t * ctx, unsigned char * sres, const unsigned char * rand, unsigned sres_num);
void rad_output_hex(rad_script_context_t * ctx, char * hex, unsigned int len);

void radcl_printf(rad_script_context_t * ctx, const char *fmt, ...);
char * radcl_gets(rad_script_context_t * ctx, char * line, int size);
void radcl_exit(rad_script_context_t * ctx, int code);

#endif
