#ifndef __HTTP_HANDLERS__
#define __HTTP_HANDLERS__

#define FHTTP_MAX_LOG_FILENAME_SIZE 256

typedef enum {
    RESP_TYPE_CONTENT = 0,
    RESP_TYPE_CHUNKED,
    RESP_TYPE_MIX
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

int init_listen(service_arg_t*);
int init_service(service_arg_t*);
int start_service();

#endif
