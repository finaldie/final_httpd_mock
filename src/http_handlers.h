#ifndef __HTTP_HANDLERS__
#define __HTTP_HANDLERS__

#include "http_parser.h"

#include "flibs/fmbuf.h"
#include "flibs/fhash.h"
#include "flibs/fev_buff.h"
#include "flibs/fev_timer.h"
#include "flibs/fev_timer_service.h"

#define FHTTP_MAX_LOG_FILENAME_SIZE 256
#define FHTTP_PCAP_FILE_NAME_SIZE   512
#define FHTTP_PCAP_FILTER_RULE_SIZE 512
#define FHTTP_INVALID_LATENCY       -1
#define FHTTP_CRLF                  "\r\n"
#define FHTTP_CRLF_SIZE             (sizeof(FHTTP_CRLF) - 1)
#define FHTTP_MAX_URI_LEN           1024

typedef enum {
    RESP_TYPE_CONTENT = 0,
    RESP_TYPE_CHUNKED,
    RESP_TYPE_MIX,
    RESP_TYPE_PCAP,

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

    // pcap related
    char pcap_filename[FHTTP_PCAP_FILE_NAME_SIZE];
    char filter_rules[FHTTP_PCAP_FILTER_RULE_SIZE];

    int timeout;
    int log_level;
    char log_filename[FHTTP_MAX_LOG_FILENAME_SIZE];
    char access_log_filename[FHTTP_MAX_LOG_FILENAME_SIZE];

    // common args
    int max_open_files;
    int listen_fd;
    int cpu_cores;
} service_arg_t;

struct client;
struct timer_mgr;
struct client_mgr;

typedef struct response_opt {
    void (*init)(struct client*);
    void (*free)(struct client*);
    int  (*get_latency)(struct client*);
    void (*pre_send_req)(struct client*);
    int  (*handler)(struct client*, int* complete);
} resp_opt;

typedef struct client {
    int          fd;
    int          keepalive;
    int          request_complete;
    int          response_complete;
    int          last_latency;
    fev_buff*    evbuff;
    ftimer_node* response_timer;
    ftimer_node* shutdown_timer;
    struct client_mgr* owner;
    http_parser* parser;
    http_parser_settings settings;

    resp_opt    opt;
    void*       priv;

    // request info, tempoary store them here
    char        uri[FHTTP_MAX_URI_LEN + 1];
    size_t      uri_len;
} client;

typedef struct http_txn {
    // common
    client* cli;

    // request part
    unsigned char method;
    unsigned short http_major;
    unsigned short http_minor;
    fhash* url_params_tbl;
    fhash* req_headers_tbl;
    fmbuf* req_body_buf;

    // response part
    unsigned short status_code;
    fhash* resp_headers_tbl;
    fmbuf* resp_body_buf;

} http_txn;

typedef struct client_mgr {
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
