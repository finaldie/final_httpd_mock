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
#include "http_load_pcap.h"

#define FHTTP_REPONSE_HEADER_SIZE        2048
#define FHTTP_MAX_WAIT_TIME_FOR_1ST_REQ  (1000 * 10)
#define FHTTP_1MS                        (1000000l)

/**
 * design mode:
 *     client_mgr
 *    /     |    \
 *client client client
 *   |      |     |
 * timer  timer  timer
 */

static fev_state* fev = NULL;
static client_mgr* cli_mgr = NULL;
extern log_file_t* glog;

struct resp_tbl_t {
   register_resp_init init;
} resp_tbl[RESP_TYPE_NUM];

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
    cli->opt.free(cli);
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

int gen_random_response_size(int min, int max)
{
    return gen_number_in_range(min, max);
}

int gen_random_latency(int min, int max)
{
    return gen_number_in_range(min, max);
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
        int fd = node->cli->fd;
        FLOG_DEBUG(glog, "on timer: fd=%d, diff=%d, node_timeout=%d", fd, diff, node->timeout);

        if ( node->cli->response_complete < node->cli->request_complete ) {
            if ( diff >= node->timeout ) {
                // we need to send respose
                int ret = -1, complete = 0;
                ret = node->cli->opt.handler(node->cli, &complete);

                if ( ret < 0 ) {
                    // something goes wrong, the client has been destroyed, go
                    // to the next node
                    FLOG_DEBUG(glog, "on timer, but buffer cannot write, fd=%d", fd);
                    goto pop_next_node;
                }

                // update last active
                get_cur_time(&node->cli->last_active);

                // when we found the server timeout == 0, we can fast shutdown
                // the connection instead of going to next timer round checking
                if ( complete ) {
                    if( mgr->sargs->timeout == 0 ) {
                        destroy_client(node->cli);
                        FLOG_DEBUG(glog, "on timer, timeout==0 fast shutdown, fd=%d", fd);
                        goto pop_next_node;
                    } else {
                        // we are finished one request, then reset timeout
                        node->timeout = mgr->sargs->timeout;
                        node->cli->response_complete++;
                        FLOG_DEBUG(glog, "on timer: fd=%d, we have finished a request, reset timeout to %d",
                                   fd, mgr->sargs->timeout);
                    }
                } else {
                    // update latency
                    node->timeout = node->cli->opt.get_latency(node->cli);
                }
            }

            timer_node_push(mgr->backup, node);
        } else if ( node->cli->response_complete == node->cli->request_complete ) {
            // check whether client out of time
            if ( diff >= node->timeout ) {
                destroy_client(node->cli);
                FLOG_WARN(glog, "delete timeout, fd=%d", fd);
            } else {
                timer_node_push(mgr->backup, node);
            }
        } else {
            destroy_client(node->cli);
            FLOG_ERROR(glog, "on timer, internal error, fd=%d", fd);
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
        FLOG_ERROR(glog, "Didn't follow the keep-alive rules, check client side, request_cl_cnt=%d, response_cl_cnt=%d",
                   cli->request_complete, cli->response_complete);
        return;
    }

    // mark active
    get_cur_time(&cli->last_active);

    int ret = 0;
    int complete = 0;
    cli->opt.pre_send_req(cli);
    int latency = cli->opt.get_latency(cli);

    if( !latency ) {
        ret = cli->opt.handler(cli, &complete);
        if ( ret < 0 ) {
            // something goes wrong, client has been destroyed
            FLOG_DEBUG(glog, "buffer cannot write, fd=%d", fd);
            return;
        }

        if ( complete ) {
            int server_timeout = cli->owner->sargs->timeout;
            if( server_timeout == 0 ) {
                destroy_client(cli);
                FLOG_DEBUG(glog, "timeout==0 fast shutdown, fd=%d", fd);
                return;
            } else {
                latency = server_timeout;
                cli->response_complete++;
            }
        } else {
            latency = cli->opt.get_latency(cli);
        }
    }

    // create timer node
    timer_node* tnode = timer_node_create(cli, latency);
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
        cli->fd = fd;
        cli->last_latency = FHTTP_INVALID_LATENCY;
        cli->evbuff = evbuff;
        cli->owner = mgr;
        cli->owner->current_conn++;
        get_cur_time(&cli->last_active);
        timer_node* tnode = timer_node_create(cli, FHTTP_MAX_WAIT_TIME_FOR_1ST_REQ);
        timer_node_push(cli->owner->current, tnode);

        // init client private opt
        resp_tbl[cli_mgr->sargs->response_type].init(cli);
        // call client's init
        cli->opt.init(cli);

        FLOG_DEBUG(glog, "fev_buff created fd=%d", fd);
    } else {
        FLOG_ERROR(glog, "cannot create evbuff fd=%d", fd);
EG_ERROR:
        close(fd);
    }
}

static
void http_show_status(fev_state* fev, void* arg)
{
    client_mgr* mgr = (client_mgr*)arg;

    FLOG_INFO(glog, "current connection = %d", mgr->current_conn);
}

static
void register_resp(resp_type_t type, register_resp_init init)
{
    resp_tbl[type].init = init;   
}

static
void register_resp_handlers()
{
    register_resp(RESP_TYPE_CONTENT, init_content_resp_opt);
    register_resp(RESP_TYPE_CHUNKED, init_chunk_resp_opt);
    register_resp(RESP_TYPE_MIX, init_mix_resp_opt);
    register_resp(RESP_TYPE_PCAP, init_pcap_resp_opt);
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

    register_resp_handlers();
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

    if( cli_mgr->sargs->response_type == RESP_TYPE_PCAP ) {
        printf("loading pcap file...\n");
        service_arg_t* conf = cli_mgr->sargs;
        load_http_resp(conf->pcap_filename, conf->filter_rules);
        printf("load pcap file complete\n");
    }

    return 0;
}

int start_service()
{
    // every 10ms, the timer will wake up
    fev_timer* resp_timer = fev_add_timer_event(fev, 10 * FHTTP_1MS, 10 * FHTTP_1MS,
                                                http_on_timer, cli_mgr);
    if ( !resp_timer ) {
        FLOG_ERROR(glog, "register response timer failed");
        exit(1);
    }

    fev_timer* status_timer = fev_add_timer_event(fev, 1000 * FHTTP_1MS, 1000 * FHTTP_1MS,
                                                http_show_status, cli_mgr);
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
