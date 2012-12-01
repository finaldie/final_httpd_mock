//#include <assert.h>

#include <stdio.h>
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

#define fake_chunk_response_header \
"HTTP/1.1 200 OK\r\n" \
"Date: Tue, 13 Nov 2012 13:21:30 GMT\r\n" \
"Server: Http Mock\r\n" \
"Last-Modified: Tue, 12 Jan 2010 13:48:00 GMT\r\n" \
"Transfer-Encoding: chunked\r\n" \
"Connection: Keep-Alive\r\n" \
"Content-Type: text/html\r\n" \
"\r\n"

#define fake_response_body "%s\r\n"

#define FHTTP_REPONSE_HEADER_SIZE (sizeof(fake_response_header) + 10 )
#define FHTTP_CRLF                "\r\n"
#define FHTTP_CRLF_SIZE           (sizeof(FHTTP_CRLF) - 1)
#define FHTTP_1MS                 (1000000l)
#define FHTTP_CHUNK_END           "0\r\n\r\n"
#define FHTTP_CHUNK_END_SIZE      (sizeof(FHTTP_CHUNK_END) - 1)
#define FHTTP_CHUNK_RESPONSE_HEADER_SIZE (sizeof(fake_chunk_response_header) - 1)

/**
 * design mode:
 *     client_mgr
 *    /     |    \
 *client client client
 *   |      |     |
 * timer  timer  timer
 */

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

typedef struct client {
    int         fd;
    int         offset;
    int         request_complete;
    int         response_complete;
    my_time     last_active;
    fev_buff*   evbuff;
    timer_node* tnidx;
    struct client_mgr* owner;

    int         ischunked;
    int         chunk_block_num;
    int         chunk_size;
    int         last_data_size;
} client;

typedef struct timer_mgr {
    timer_node* head;
    timer_node* tail;
    int         count;
} timer_mgr;

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

static fev_state* fev = NULL;
static client_mgr* cli_mgr = NULL;
extern log_file_t* glog;

static
timer_node* timer_node_create(client* cli, int timeout)
{
    if ( cli->tnidx ) {
        cli->tnidx->timeout = timeout;
        return cli->tnidx;
    }

    timer_node* tnode = malloc(sizeof(timer_node));
    memset(tnode, 0, sizeof(*tnode));
    cli->tnidx = tnode;
    tnode->cli = cli;
    tnode->timeout = timeout;
    tnode->prev = tnode->next = NULL;

    return tnode;
}

static
void timer_node_delete(timer_mgr* mgr, timer_node* node)
{
    if ( !node )
        return;
    if ( !node->owner )
        goto RELEASE;

    //assert(node->owner == mgr);
    if ( !node->prev ) { // node at head
        mgr->head = node->next;
        if ( mgr->head ) mgr->head->prev = NULL;
    } else if ( !node->next ) { // node at tail
        mgr->tail = node->prev;
        if ( mgr->tail ) mgr->tail->next = NULL;
    } else { // node at middle
        node->prev->next = node->next;
        node->next->prev = node->prev;
    }

    node->owner = NULL;
    mgr->count--;
    if ( !mgr->count ) {
        mgr->head = mgr->tail = NULL;
    }

RELEASE:
    free(node);
}

static
int timer_node_push(timer_mgr* mgr, timer_node* node)
{
    if ( node->owner ) return 1;
    if ( mgr->head == mgr->tail && mgr->head == NULL ) {
        mgr->head = mgr->tail = node;
    } else {
        node->prev = mgr->tail;
        mgr->tail->next = node;
        mgr->tail = node;
    }

    node->owner = mgr;
    mgr->count++;
    return 0;
}

static
timer_node* timer_node_pop(timer_mgr* mgr)
{
    if ( !mgr->head ) {
        return NULL;
    } else {
        timer_node* node = mgr->head;
        mgr->head = mgr->head->next;
        if ( !mgr->head ) {
            mgr->tail = mgr->head;
        } else {
            mgr->head->prev = NULL;
        }

        node->prev = node->next = NULL;
        node->owner = NULL;
        mgr->count--;
        return node;
    }
}

static
client* create_client()
{
    client* cli = malloc(sizeof(client));
    memset(cli, 0, sizeof(*cli));

    return cli;
}

static
void destroy_client(client* cli)
{
    int fd = fevbuff_destroy(cli->evbuff);
    timer_node_delete(cli->owner->current, cli->tnidx);
    cli->owner->current_conn--;
    free(cli);
    close(fd);
    FLOG_DEBUG(glog, "destroy client fd=%d", fd);
}

static
client_mgr* create_client_mgr(size_t max_response_size)
{
    client_mgr* mgr = malloc(sizeof(client_mgr));
    memset(mgr, 0, sizeof(client_mgr));
    mgr->current = &mgr->tm_main;
    mgr->backup = &mgr->tm_minor;
    mgr->sargs = NULL;
    mgr->current_conn = 0;
    mgr->buffsize = FHTTP_REPONSE_HEADER_SIZE + max_response_size + FHTTP_CRLF_SIZE + 1;
    mgr->response_buf = malloc(mgr->buffsize);
    memset(mgr->response_buf, 0, mgr->buffsize);
    size_t body_size = max_response_size + FHTTP_CRLF_SIZE + 1;
    mgr->response_body_buf = malloc(body_size);
    memset(mgr->response_body_buf, 0, body_size);

    return mgr;
}

static
int gen_number_in_range(int min, int max)
{
    if ( min == max ) return min;
    int offset = rand() % (max - min + 1);
    return min + offset;
}

static
int gen_random_response_size(int min, int max)
{
    return gen_number_in_range(min, max);
}

static
int get_ischunked(resp_type_t response_type, int chunk_ratio)
{
    if ( response_type == RESP_TYPE_CONTENT ) {
        return 0;
    } else if ( response_type == RESP_TYPE_CHUNKED ) {
        return 1;
    } else {
        if ( chunk_ratio == 0 ) {
            return 0;
        } else if ( chunk_ratio == 100 ) {
            return 1;
        } else {
            return (rand() % 100) < chunk_ratio;
        }
    }
}

static
int gen_random_latency(int min, int max)
{
    return gen_number_in_range(min, max);
}

static
int create_response(char* buf, size_t buffsize, size_t size)
{
    if ( size > (buffsize - 3) ) return 0;

    // fill all bytes with 'F'
    memset(buf, 70, size);
    buf[size] = '\r';
    buf[size+1] = '\n';
    buf[size+2] = '\0';

    return size + FHTTP_CRLF_SIZE;
}

static
int send_http_response(client* cli)
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
                             response_size + (int)FHTTP_CRLF_SIZE + 2,
                             mgr->response_body_buf);
    // 3. send out
    cli->response_complete++;
    return fevbuff_write(cli->evbuff, mgr->response_buf, total_len);
}

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
int set_chunked_status(client* cli)
{
    if ( !cli ) return 1;

    client_mgr* mgr = cli->owner;
    // 1. generate response body
    int response_size = gen_random_response_size(mgr->sargs->min_chunk_response_size,
                                                 mgr->sargs->max_chunk_response_size);
    cli->last_data_size = response_size;
    cli->chunk_size = response_size / mgr->sargs->chunk_blocks;
    // fix zero chunk size issue
    if ( cli->last_data_size && !cli->chunk_size ) {
        cli->chunk_size = 1;
    }

    return 0;
}

static
int send_http_chunked_response(client* cli)
{
    client_mgr* mgr = cli->owner;
    int offset = 0;

    // if this is the first chunk block, fill response headers first
    if ( !cli->chunk_block_num ) {
        // first time to send, construct header
        memcpy(mgr->response_buf, fake_chunk_response_header,
                FHTTP_CHUNK_RESPONSE_HEADER_SIZE);
        offset += FHTTP_CHUNK_RESPONSE_HEADER_SIZE;
    }

    // fill response
    if ( !cli->last_data_size ) {
        // if no data left, fill the last chunk
        memcpy(&mgr->response_buf[offset], FHTTP_CHUNK_END, FHTTP_CHUNK_END_SIZE);
        offset += FHTTP_CHUNK_END_SIZE;

        // mark response complete and reset block num for next request
        cli->response_complete++;
        cli->chunk_block_num = 0;
    } else {
        // have data left, fill normal chunk
        int datasize = cli->chunk_size < cli->last_data_size ? cli->chunk_size :
                                                               cli->last_data_size;
        int len = create_chunk_response(mgr->response_buf + offset,
                                        mgr->buffsize - offset,
                                        datasize);
        // update status
        cli->last_data_size -= datasize;
        cli->chunk_block_num++;

        offset += len;
    }

    // send out
    return fevbuff_write(cli->evbuff, mgr->response_buf, offset);
}

static
void http_on_timer(fev_state* fev, void* arg)
{
    //FLOG_DEBUG(glog, "timer trigger");
    client_mgr* mgr = (client_mgr*)arg;
    timer_node* node = timer_node_pop(mgr->current);
    if ( !node ) return;

    my_time now;
    get_cur_time(&now);

    while ( node ) {
        int diff = get_diff_time(&node->cli->last_active, &now) / 1000;
        FLOG_DEBUG(glog, "on timer: fd=%d, diff=%d", node->cli->fd, diff);

        if ( diff >= node->timeout ) {
            if ( node->cli->response_complete < node->cli->request_complete ) {
                int ret = -1;
                int fd = node->cli->fd;
                if ( !node->cli->ischunked ) {
                    ret = send_http_response(node->cli);
                } else {
                    ret = send_http_chunked_response(node->cli);
                }

                if ( ret < 0 ) {
                    // something goes wrong
                    FLOG_DEBUG(glog, "on timer, but buffer cannot write, fd=%d", fd);
                    goto pop_next_node;
                }

                timer_node_push(mgr->backup, node);
            } else if ( diff >= mgr->sargs->timeout ) {
                FLOG_WARN(glog, "delete timeout");
                destroy_client(node->cli);
            } else {
                timer_node_push(mgr->backup, node);
            }
        } else {
            // not time out
            timer_node_push(mgr->backup, node);
        }

pop_next_node:
        node = timer_node_pop(mgr->current);
    }

    // swap tmp timer node header and tailer
    timer_mgr* tmp = mgr->current;
    mgr->current = mgr->backup;
    mgr->backup = tmp;
}

static
void http_read(fev_state* fev, fev_buff* evbuff, void* arg)
{
    client* cli = (client*)arg;
    int fd = cli->fd;
    int bytes = fevbuff_read(evbuff, NULL, 1024);
    if ( bytes < 0 ) {
        FLOG_DEBUG(glog, "buffer cannot read, fd=%d", fd);
        return;
    } else if ( bytes == 0 ) {
        FLOG_DEBUG(glog, "buffer read 0 byte, fd=%d", fd);
        return;
    }

    // we have data need to process
    char* read_buf = fevbuff_rawget(evbuff);
    int offset = cli->offset;

    // try to found one request
    int isfound = 0;
    while ( offset < bytes-2 ) {
        if ((read_buf[offset] == read_buf[offset+2] &&
             read_buf[offset] == '\n') ) {
            // we found a request
            isfound = 1;
            break;
        }
        offset++;
    }

    if ( !isfound ) {
        cli->offset = offset;
        return;
    }

    // header parser complete
    cli->request_complete++;

    // check k-a valid
    if ( (cli->request_complete - 1) != cli->response_complete ) {
        destroy_client(cli);
        FLOG_ERROR(glog, "not follow keep-alive rules, check client side");
        return;
    }

    // mark active
    get_cur_time(&cli->last_active);

    // to decide this response whether is chunked
    cli->ischunked = get_ischunked(cli->owner->sargs->response_type,
                                    cli->owner->sargs->chunk_ratio);

    int interval = 0, ret = 0;
    if ( !cli->ischunked ) {
        int latency = gen_random_latency(cli->owner->sargs->min_latency,
                                     cli->owner->sargs->max_latency);
        if ( latency ) {
            interval = latency;
        } else {
            interval = cli->owner->sargs->timeout;
            ret = send_http_response(cli);
        }
    } else {
        // set chunk status if client need chunked response
        set_chunked_status(cli);

        int latency = gen_random_latency(cli->owner->sargs->min_chunk_latency,
                                     cli->owner->sargs->max_chunk_latency);
        if ( latency ) {
            interval = latency;
        } else {
            interval = cli->owner->sargs->timeout;
            ret = send_http_chunked_response(cli);
        }
    }

    if ( ret < 0 ) {
        // something goes wrong, client has been destroyed
        FLOG_DEBUG(glog, "buffer cannot write, fd=%d", fd);
        return;
    }

    // create timer node
    timer_node* tnode = timer_node_create(cli, interval);
    timer_node_push(cli->owner->current, tnode);

    // pop last consumed data
    fevbuff_pop(evbuff, offset+2);
    // reset offset for next request
    cli->offset = 0;
}

static
void http_error(fev_state* fev, fev_buff* evbuff, void* arg)
{
    FLOG_DEBUG(glog, "eg error fd=%d", ((client*)arg)->fd);
    destroy_client((client*)arg);
}

static
void http_accept(fev_state* fev, int fd, void* ud)
{
    FLOG_DEBUG(glog, "accept fd=%d, pid=%d", fd, getpid());
    client_mgr* mgr = (client_mgr*)ud;
    if ( fd >= mgr->sargs->max_queue_len ) {
        FLOG_ERROR(glog, "fd > max open files, cannot accept pid=%d", getpid());
        goto EG_ERROR;
    }

    client* cli = create_client();
    fev_buff* evbuff = fevbuff_new(fev, fd, http_read, http_error, cli);
    if( evbuff ) {
        get_cur_time(&cli->last_active);
        cli->fd = fd;
        cli->evbuff = evbuff;
        cli->owner = mgr;
        cli->owner->current_conn++;
        cli->ischunked = 0;
        FLOG_DEBUG(glog, "fev_buff created fd=%d", fd);
    } else {
        FLOG_ERROR(glog, "cannot create evbuff fd=%d", fd);
EG_ERROR:
        close(fd);
    }
}

static
void http_on_show_status(fev_state* fev, void* arg)
{
    client_mgr* mgr = (client_mgr*)arg;

    FLOG_INFO(glog, "current connection = %d", mgr->current_conn);
}

int init_listen(service_arg_t* sargs)
{
    int listen_fd = net_create_listen(NULL, sargs->port, sargs->max_open_files, 0);
    if( listen_fd < 0 ) {
        return 1;
    }

    sargs->listen_fd = listen_fd;
    return 0;
}

int init_service(service_arg_t* sargs)
{
    fev = fev_create(sargs->max_queue_len);
    if( !fev ) {
        FLOG_ERROR(glog, "fev create failed, err=%s", strerror(errno));
        exit(1);
    }
    FLOG_INFO(glog, "fev create successful");

    cli_mgr = create_client_mgr(sargs->max_response_size);
    cli_mgr->sargs = sargs;

    fev_listen_info* fli = fev_add_listener_byfd(fev, sargs->listen_fd, http_accept, cli_mgr);
    if( !fli ) {
        FLOG_ERROR(glog, "add listener failed, err=%s", strerror(errno));
        exit(2);
    }
    FLOG_INFO(glog, "add listener successful, bind port is %d", sargs->port);

    // init random seed
    srand(time(NULL));

    return 0;
}

int start_service()
{
    // every 50ms, the timer will wake up
    fev_timer* resp_timer = fev_add_timer_event(fev, 50 * FHTTP_1MS, 50 * FHTTP_1MS,
                                                http_on_timer, cli_mgr);
    if ( !resp_timer ) {
        FLOG_ERROR(glog, "register response timer failed");
        exit(1);
    }

    fev_timer* status_timer = fev_add_timer_event(fev, 1000 * FHTTP_1MS, 1000 * FHTTP_1MS,
                                                http_on_show_status, cli_mgr);
    if ( !status_timer ) {
        FLOG_ERROR(glog, "register status timer failed");
        exit(1);
    }

    FLOG_INFO(glog, "register timer successful");
    FLOG_INFO(glog, "fev_poll start");

    while(1) {
        fev_poll(fev, 10000);
    }

    return 0;
}
