#ifndef __HTTP_LOAD_PCAP__
#define __HTTP_LOAD_PCAP__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
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
typedef unsigned int uint32_t;
typedef struct pcap_state_t{
    pl_mgr   resp_list;
    uint32_t resp_cnt;
    struct timeval syn_ts; // timestamp of creation
} pcap_state_t;
typedef struct data_pkg_t{
    struct timeval ts;
    char*  data;
    int    len;
    uint32_t ack; //used for detection of dumplicate TCP packet
    uint32_t seq;
} data_pkg_t;

typedef struct resp_t{
    pl_mgr      pkg_list;
    uint32_t    pkg_cnt;
    struct timeval cts; // timestamp of creation
} resp_t;
struct _cli_state_t {
    pcap_state_t* state;
    liter         resp_iter;
    liter         pkg_iter;
    resp_t*       curr_resp;
    data_pkg_t*   curr_pkg;
};

typedef struct {
    pcap_state_t* state;
    resp_t*       curr_resp;
    data_pkg_t*   curr_pkg;
    int           valid;
} sess_state_t;
#endif
