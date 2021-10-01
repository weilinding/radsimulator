#ifndef __RAD_DICT_H
#define __RAD_DICT_H

#define RADIUS_PORT   (1812)

#define RAD_CODE_ACCESS_REQUEST        1
#define RAD_CODE_ACCESS_ACCEPT         2
#define RAD_CODE_ACCESS_REJECT         3
#define RAD_CODE_ACCOUNT_REQ           4
#define RAD_CODE_ACCOUNT_RSP           5
#define RAD_CODE_CHALLENGE            11

#define RAD_AVP_USER_NAME              1
#define RAD_AVP_USER_PASSWORD          2
#define RAD_AVP_CHAP_PASSWORD          3
#define RAD_AVP_NAS_IP_ADDRESS         4
#define RAD_AVP_NAS_PORT               5
#define RAD_AVP_FRAMED_MTU            12
#define RAD_AVP_STATE                 24
#define RAD_AVP_CALLED_STATION_ID     30
#define RAD_AVP_CALLING_STATION_ID    31
#define RAD_AVP_NAS_IDENTIFIER        32
#define RAD_AVP_NAS_PORT_TYPE         61
#define RAD_AVP_CONNECT_INFO          77
#define RAD_AVP_EAP_MESSAGE           79
#define RAD_AVP_MESSAGE_AUTHENTICATOR 80

#define RAD_EAP_CODE_REQUEST           1
#define RAD_EAP_CODE_RESPONSE          2
#define RAD_EAP_CODE_SUCCESS           3
#define RAD_EAP_CODE_FAILURE           4

#define RAD_EAP_TYPE_IDENTITY          1
#define RAD_EAP_TYPE_NOTIFICATION      2
#define RAD_EAP_TYPE_MD5               3
#define RAD_EAP_TYPE_MD5_CHALLENGE     4
#define RAD_EAP_TYPE_SIM              18

#define RAD_EAP_SIM_SUBTYPE_START     10
#define RAD_EAP_SIM_SUBTYPE_CHALLENGE 11

#define RAD_EAP_AT_RAND                1
#define RAD_EAP_AT_NONCE_MT            7
#define RAD_EAP_AT_PERMANENT_ID_REQ   10
#define RAD_EAP_AT_MAC                11
#define RAD_EAP_AT_ANY_ID_REQ         13
#define RAD_EAP_AT_IDENTITY           14
#define RAD_EAP_AT_VERSION_LIST       15
#define RAD_EAP_AT_SELECTED_VERSION   16
#define RAD_EAP_AT_FULLAUTH_ID_REQ    17

#define RAD_EAP_SIM_SRES_SIZE  4
#define RAD_EAP_SIM_KC_SIZE    8
#define RAD_EAP_SIM_RAND_SIZE 16

#define VENDORPEC_MICROSOFT		311
#define PW_MSCHAP_CHALLENGE		11
#define PW_MSCHAP_RESPONSE		1

#pragma pack(push)
#pragma pack(1)
typedef struct rad_header_t_
{
  unsigned char code;
  unsigned char packet_identifier;
  unsigned short length;
  char authenticator[16];
} rad_header_t;

typedef struct rad_eap_header_t_
{
  unsigned char code;
  unsigned char identifier;
  unsigned short length;
  unsigned char type;
} rad_eap_header_t;

typedef struct rad_eap_header_md5_t_
{
  unsigned char code;
  unsigned char identifier;
  unsigned short length;
  unsigned char type;
  unsigned char val_len;
} rad_eap_header_md5_t_;

typedef struct rad_eap_header_ext_t_
{
  unsigned char code;
  unsigned char identifier;
  unsigned short length;
  unsigned char type;
  unsigned char subtype;
  short reserved;
} rad_eap_header_ext_t;

typedef struct rad_eap_at_version_list_t_
{
  unsigned short actual_length;
  unsigned short supported_version[1];
} rad_eap_at_version_list_t;

#pragma pack(pop)

#endif
