#ifndef __HTTP_HANDLERS__
#define __HTTP_HANDLERS__

#include "fev_buff.h"
#include "fev_timer.h"
#include "tu_inc.h"

#define FHTTP_MAX_LOG_FILENAME_SIZE 256
#define FHTTP_CRLF                "\r\n"
#define FHTTP_CRLF_SIZE           (sizeof(FHTTP_CRLF) - 1)

typedef enum {
    RESP_TYPE_CONTENT = 0,
    RESP_TYPE_CHUNKED,
    RESP_TYPE_MIX,
    RESP_PCAP,

    RESP_TYPE_NUM   // do not delete this, count of response type
} resp_type_t;

typedef struct {
    // from configuration
    int max_queue_len;
    int port;
    int workers;
    resp_type_t response_type;
    int chunk_ratio;

    int min_latency;
    int max_latency;
    int min_response_size;
    int max_response_size;

    int min_chunk_latency;
    int max_chunk_latency;
    int min_chunk_response_size;
    int max_chunk_response_size;
    int chunk_blocks;

    int timeout;
    int log_level;
    char log_filename[FHTTP_MAX_LOG_FILENAME_SIZE];

    // common args
    int max_open_files;
    int listen_fd;
    int cpu_cores;
} service_arg_t;

struct client;
struct timer_mgr;
struct client_mgr;

typedef struct timer_node {
    struct client*     cli;
    struct timer_node* prev;
    struct timer_node* next;
    struct timer_mgr*  owner;
    int                timeout; // unit [ms]
} timer_node;

typedef struct timer_mgr {
    timer_node* head;
    timer_node* tail;
    int         count;
} timer_mgr;

typedef struct response_opt {
    void (*init)(struct client*);
    void (*free)(struct client*);
    int  (*get_latency)(struct client*);
    void (*pre_send_req)(struct client*);
    int  (*handler)(struct client*, int* complete);
} resp_opt;

typedef struct client {
    int         fd;
    int         offset;
    int         request_complete;
    int         response_complete;
    my_time     last_active;
    fev_buff*   evbuff;
    timer_node* tnidx;
    struct client_mgr* owner;

    resp_opt    opt;
    void*       priv;
} client;

typedef struct client_mgr {
    timer_mgr  tm_main;
    timer_mgr  tm_minor;
    timer_mgr* current;
    timer_mgr* backup;

    service_arg_t* sargs;
    int        current_conn;
    size_t     buffsize;
    char*      response_buf;
    char*      response_body_buf;
} client_mgr;

typedef void (*register_resp_init)(client*);

int init_listen(service_arg_t*);
int init_service(service_arg_t*);
int start_service();

int gen_random_response_size(int min, int max);
int gen_random_latency(int min, int max);

void init_content_resp_opt(client*);
void init_chunk_resp_opt(client*);
void init_mix_resp_opt(client*);
void init_pcap_resp_opt(client*);

#endif
