#ifndef __HTTP_LOAD_PCAP__
#define __HTTP_LOAD_PCAP__

#include "flist.h"

#define FPCAP_NO_LATENCY -1
typedef struct _cli_state_t cli_state_t;

cli_state_t* pc_create_state();
void  pc_destroy_state(cli_state_t*);
void  pc_get_next_session(cli_state_t*);
void  pc_get_next_resp(cli_state_t* state);
void  pc_get_next_pkg(cli_state_t* state);
char* pc_get_pkg_data(cli_state_t* state);
int   pc_get_pkg_len(cli_state_t* state);
int   pc_is_last_pkg(cli_state_t* state);
int   pc_get_next_pkg_latency(cli_state_t* state);

int   load_http_resp(const char* filename, const char* rules);

#endif
