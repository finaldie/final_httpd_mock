#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "fev_listener.h"
#include "fev_buff.h"
#include "fev_timer.h"
#include "tu_inc.h"
#include "log_inc.h"
#include "net_core.h"

#include "http_handlers.h"

#define fake_chunk_response_header \
"HTTP/1.1 200 OK\r\n" \
"Server: Http Mock\r\n" \
"Transfer-Encoding: chunked\r\n" \
"Connection: Keep-Alive\r\n" \
"Content-Type: text/html\r\n" \
"\r\n"

#define FHTTP_CHUNK_END           "0\r\n\r\n"
#define FHTTP_CHUNK_END_SIZE      (sizeof(FHTTP_CHUNK_END) - 1)
#define FHTTP_CHUNK_RESPONSE_HEADER_SIZE (sizeof(fake_chunk_response_header) - 1)
#define FCHUNK_ST(cli)            ((chunk_state*)(cli->priv))

extern log_file_t* glog;

typedef struct chunk_state {
    int         chunk_block_num;
    int         chunk_size;
    int         last_data_size;
} chunk_state;

// create simple chunk
// follow the chunk format:
// normal data:
//  size CRLF
//  data CRLF
// end data:
//  0 CRLF
static
size_t create_chunk_response(char* buf, size_t buffsize, size_t datasize)
{
    int offset = snprintf(buf, buffsize, "%lx\r\n", datasize);
    memset(buf+offset, 70, datasize);
    offset += datasize;
    buf[offset] = '\r';
    buf[offset+1] = '\n';
    buf[offset+2] = '\0';

    size_t totalsize = offset + FHTTP_CRLF_SIZE;
    return totalsize;
}

static
int init_chunk_data(client* cli)
{
    if ( !cli ) return 1;

    client_mgr* mgr = cli->owner;
    // 1. generate response body
    int response_size = gen_random_response_size(mgr->sargs->min_chunk_response_size,
                                                 mgr->sargs->max_chunk_response_size);
    FCHUNK_ST(cli)->last_data_size = response_size;
    FCHUNK_ST(cli)->chunk_size = response_size / mgr->sargs->chunk_blocks;
    // fix zero chunk size issue
    if ( FCHUNK_ST(cli)->last_data_size && !FCHUNK_ST(cli)->chunk_size ) {
        FCHUNK_ST(cli)->chunk_size = 1;
    }

    FLOG_DEBUG(glog, "new chunk request, init data: chunk_size=%d, left_data_size=%d",
               FCHUNK_ST(cli)->chunk_size, FCHUNK_ST(cli)->last_data_size);

    return 0;
}

static
int chunk_resp_handler(client* cli, int* complete)
{
    client_mgr* mgr = cli->owner;
    int offset = 0;
    *complete = 0;

    // if this is the first chunk block, fill response headers first
    if ( !FCHUNK_ST(cli)->chunk_block_num ) {
        // first time to send, construct header
        memcpy(mgr->response_buf, fake_chunk_response_header,
                FHTTP_CHUNK_RESPONSE_HEADER_SIZE);
        offset += FHTTP_CHUNK_RESPONSE_HEADER_SIZE;

        FLOG_DEBUG(glog, "send chunk response header");
    }

    // fill response
    if ( !FCHUNK_ST(cli)->last_data_size ) {
        // if no data left, fill the last chunk
        memcpy(&mgr->response_buf[offset], FHTTP_CHUNK_END, FHTTP_CHUNK_END_SIZE);
        offset += FHTTP_CHUNK_END_SIZE;

        // mark response complete and reset block num for next request
        FCHUNK_ST(cli)->chunk_block_num = 0;
        *complete = 1;
        FLOG_DEBUG(glog, "send chunk response complete");
    } else {
        // have data left, fill normal chunk
        int datasize = FCHUNK_ST(cli)->chunk_size < FCHUNK_ST(cli)->last_data_size ? FCHUNK_ST(cli)->chunk_size :
                                                               FCHUNK_ST(cli)->last_data_size;
        int len = create_chunk_response(mgr->response_buf + offset,
                                        mgr->buffsize - offset,
                                        datasize);
        // update status
        FCHUNK_ST(cli)->last_data_size -= datasize;
        FCHUNK_ST(cli)->chunk_block_num++;

        offset += len;
        FLOG_DEBUG(glog, "send chunk response, left_data_size=%d, block_num=%d", FCHUNK_ST(cli)->last_data_size, FCHUNK_ST(cli)->chunk_block_num);
    }

    // send out
    return fevbuff_write(cli->evbuff, mgr->response_buf, offset);
}

static inline
void chunk_resp_init(client* cli)
{
    cli->priv = malloc(sizeof(chunk_state));
    memset(cli->priv, 0, sizeof(chunk_state));
}

static inline
void chunk_resp_free(client* cli)
{
    free(cli->priv);
    cli->priv = NULL;
}

static inline
int chunk_get_latency(client* cli)
{
    if ( cli->last_latency != FHTTP_INVALID_LATENCY ) {
        return cli->last_latency;
    }

    cli->last_latency = gen_random_latency(cli->owner->sargs->min_chunk_latency,
                                     cli->owner->sargs->max_chunk_latency);
    return cli->last_latency;
}

static inline
void chunk_pre_send(client* cli)
{
    init_chunk_data(cli);
}

void init_chunk_resp_opt(client* cli)
{
    cli->opt.init = chunk_resp_init;
    cli->opt.free = chunk_resp_free;
    cli->opt.get_latency = chunk_get_latency;
    cli->opt.pre_send_req = chunk_pre_send;
    cli->opt.handler = chunk_resp_handler;
}
