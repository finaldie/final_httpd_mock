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

#define fake_response_header \
"HTTP/1.1 200 OK\r\n" \
"Date: Tue, 13 Nov 2012 13:21:30 GMT\r\n" \
"Server: Http Mock\r\n" \
"Last-Modified: Tue, 12 Jan 2010 13:48:00 GMT\r\n" \
"Content-Length: %d\r\n" \
"Connection: Keep-Alive\r\n" \
"Content-Type: text/html\r\n" \
"\r\n"

#define fake_response_body "%s"
#define FHTTP_REPONSE_HEADER_SIZE (sizeof(fake_response_header) + 10 )

static
int create_response(char* buf, size_t buffsize, size_t size)
{
    if ( size > (buffsize - 1) ) return 0;

    // fill all bytes with 'F'
    memset(buf, 70, size);
    buf[size] = '\0';

    return size + FHTTP_CRLF_SIZE;
}

static
int content_resp_handler(client* cli, int* complete)
{
    // here we have two options to implement
    // 1. snprintf once ( we choose this )
    // 2. writev ( in future )

    client_mgr* mgr = cli->owner;

    // 1. generate response body
    int response_size = gen_random_response_size(mgr->sargs->min_response_size,
                                                 mgr->sargs->max_response_size);
    create_response(mgr->response_body_buf, mgr->buffsize, response_size);
    // 2. fill whole response
    int total_len = snprintf(mgr->response_buf, mgr->buffsize,
                             fake_response_header fake_response_body,
                             response_size,
                             mgr->response_body_buf);
    // 3. send out
    *complete = 1;
    return fevbuff_write(cli->evbuff, mgr->response_buf, total_len);
}

static inline
void content_resp_init(client* cli)
{
    cli->priv = NULL;
}

static inline
void content_resp_free(client* cli)
{

}

static inline
void content_pre_send(client* cli)
{

}

static inline
int content_get_latency(client* cli)
{
    if ( cli->last_latency != FHTTP_INVALID_LATENCY ) {
        return cli->last_latency;
    }

    cli->last_latency = gen_random_latency(cli->owner->sargs->min_latency,
                                     cli->owner->sargs->max_latency);
    return cli->last_latency;
}

void init_content_resp_opt(client* cli)
{
    cli->opt.init = content_resp_init;
    cli->opt.free = content_resp_free;
    cli->opt.get_latency = content_get_latency;
    cli->opt.pre_send_req = content_pre_send;
    cli->opt.handler = content_resp_handler;
}
