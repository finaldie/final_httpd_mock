//#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "flibs/fev_listener.h"
#include "flibs/fev_buff.h"
#include "flibs/fev_timer.h"
#include "flibs/ftu_inc.h"
#include "flibs/flog_inc.h"
#include "flibs/fnet_core.h"

#include "http_handlers.h"
#include "http_load_pcap.h"

#define FHTTP_REPONSE_HEADER_SIZE        2048
#define FHTTP_1MS                        (1000000l)

static fev_state* fev = NULL;
static client_mgr* cli_mgr = NULL;
static fev_timer_svc* ftm_svc = NULL;
extern log_file_t* glog;

struct resp_tbl_t {
   register_resp_init init;
} resp_tbl[RESP_TYPE_NUM];

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
    fev_tmsvc_del_timer(cli->response_timer);
    fev_tmsvc_del_timer(cli->shutdown_timer);
    cli->response_timer = NULL;
    cli->shutdown_timer = NULL;

    if( cli->owner ) {
        cli->owner->current_conn--;
    }

    if( cli->opt.free ) {
        cli->opt.free(cli);
    }

    free(cli->parser);
    free(cli);
    close(fd);
    FLOG_DEBUG(glog, "destroy client fd=%d", fd);
}

static
client_mgr* create_client_mgr(size_t max_response_size)
{
    client_mgr* mgr = malloc(sizeof(client_mgr));
    memset(mgr, 0, sizeof(client_mgr));
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
void connection_shutdown_cb(fev_state* fev, void* arg)
{
    FLOG_INFO(glog, "connection shutdown, fd=%d", fev_get_fd(fev));

    client* cli = (client*)arg;
    // we should set this to NULL, since the timer service will delete this timer node,
    // so that this pointer is invalid to use
    cli->shutdown_timer = NULL;
    destroy_client(cli);
}

static
void send_response_cb(fev_state* fev __attribute__((unused)),
                      void* arg)
{
    FLOG_DEBUG(glog, "timer trigger");
    client* cli = (client*)arg;
    client_mgr* mgr = cli->owner;

    FLOG_DEBUG(glog, "send response: fd=%d", cli->fd);

    // we should set this to NULL, since the timer service will delete this timer node,
    // so that this pointer is invalid to use
    cli->response_timer = NULL;

    if ( cli->response_complete >= cli->request_complete ) {
        FLOG_ERROR(glog, "response_complete == request_complete, shouldn't go ahead");
        return;
    }

    // we need to send response
    int ret = -1, complete = 0;
    ret = cli->opt.handler(cli, &complete);

    if ( ret < 0 ) {
        // something goes wrong, the client has been destroyed
        FLOG_DEBUG(glog, "send response, but buffer cannot write, fd=%d", cli->fd);
        return;
    }

    // when we found the server timeout == 0, we can fast shutdown
    // the connection instead of going to next timer round checking
    if ( complete ) {
        if( mgr->sargs->timeout == 0 ) {
            destroy_client(cli);
            FLOG_DEBUG(glog, "send response, timeout==0 fast shutdown, fd=%d", cli->fd);
            return;
        } else {
            // we are finished one request, then reset timeout
            cli->response_complete++;

            if( fev_tmsvc_reset_timer(cli->shutdown_timer) ) {
                FLOG_ERROR(glog, "reset shutdown timer failed, fd=%d", cli->fd);
                destroy_client(cli);
                return;
            }

            FLOG_DEBUG(glog, "send response: fd=%d, we have finished a request, reset timeout to %d",
                       cli->fd, mgr->sargs->timeout);
        }
    } else {
        // if not complete, we need to get the new latency and create a timer for it
        int next_resp_latency = cli->opt.get_latency(cli);
        cli->response_timer = fev_tmsvc_add_timer(ftm_svc, next_resp_latency, send_response_cb, cli);
        if( !cli->response_timer ) {
            FLOG_ERROR(glog, "create new response timer failed, fd=%d", cli->fd);
            destroy_client(cli);
            return;
        }
    }
}

static
void http_read(fev_state* fev __attribute__((unused)),
               fev_buff* evbuff,
               void* arg)
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

    // http_parser test
    size_t nparsed = http_parser_execute(cli->parser, &cli->settings, read_buf, bytes);
    printf("http_parser nparsed=%zu\n", nparsed);

    if ( nparsed != (size_t)bytes ) {
        printf("Fatal error during parsing http request\n");
    }

    // pop last consumed data
    fevbuff_pop(evbuff, nparsed);
}

static
void http_error(fev_state* fev __attribute__((unused)),
                fev_buff* evbuff __attribute__((unused)),
                void* arg)
{
    FLOG_DEBUG(glog, "eg error fd=%d", ((client*)arg)->fd);
    destroy_client((client*)arg);
}

http_txn* fhttp_create_txn()
{
    http_txn* txn = malloc(sizeof(http_txn));
    memset(txn, 0, sizeof(http_txn));

    txn->url_params_tbl = fhash_create(100);
    txn->req_headers_tbl = fhash_create(20);
    txn->req_body_buf = fmbuf_create(1);
    txn->resp_headers_tbl = fhash_create(100);
    txn->resp_body_buf = fmbuf_create(1);

    return txn;
}

int http_msg_begin(http_parser* parser)
{
    (void)parser;
    printf("msg begin\n");
    printf("msg begin: http %d.%d, method=%d, nread=%u\n", parser->http_major, parser->http_minor, parser->method, parser->nread);
    return 0;
}

int http_on_url(http_parser* parser, const char* at, size_t length)
{
    printf("http_on_url: http %d.%d, method=%d, nread=%u\n", parser->http_major, parser->http_minor, parser->method, parser->nread);
    char tmp[1024];
    memset(tmp, 0, 1024);
    strncpy(tmp, at, length);
    printf("http_on_url: %s\n", tmp);
    return 0;
}

int http_on_status_complete(http_parser* parser)
{
    (void)parser;
    printf("status complete, nread=%u\n", parser->nread);
    return 0;
}

int http_on_hdr_field(http_parser* parser, const char* at, size_t length)
{
    (void)parser;
    printf("http_on_hdr_field: http %d.%d, method=%d, nread=%u\n", parser->http_major, parser->http_minor, parser->method, parser->nread);
    char tmp[1024];
    memset(tmp, 0, 1024);
    strncpy(tmp, at, length);
    printf("http_on_hdr_field: %s\n", tmp);
    return 0;
}

int http_on_hdr_value(http_parser* parser, const char* at, size_t length)
{
    (void)parser;
    char tmp[1024];
    memset(tmp, 0, 1024);
    strncpy(tmp, at, length);
    printf("http_on_hdr_value: %s, nread=%u\n", tmp, parser->nread);
    return 0;
}

int http_on_hdr_complete(http_parser* parser)
{
    (void)parser;
    printf("http_hdr_complete: http %d.%d, method=%d, nread=%u\n", parser->http_major, parser->http_minor, parser->method, parser->nread);
    return 0;
}

int http_on_body(http_parser* parser, const char* at, size_t length)
{
    (void)parser;
    char tmp[1024];
    memset(tmp, 0, 1024);
    strncpy(tmp, at, length);
    printf("http_on_body: %s, nread=%u\n", tmp, parser->nread);
    return 0;
}

int http_on_msg_complete(http_parser* parser)
{
    printf("msg complete, nread=%u\n", parser->nread);
    client* cli = (client*)parser->data;
    // header parser complete
    cli->request_complete++;

    // check pipe-lining, currently doesn't support it
    if ( (cli->request_complete - 1) != cli->response_complete ) {
        FLOG_ERROR(glog, "Destroy the client session: Receive a new request "
                         "while the old one has not been responsed, "
                         "request_cl_cnt=%d, response_cl_cnt=%d, fd=%d",
                         cli->request_complete, cli->response_complete, cli->fd);
        destroy_client(cli);
        return 1;
    }

    int ret = 0;
    int complete = 0;
    cli->opt.pre_send_req(cli);
    int latency = cli->opt.get_latency(cli);

    if( !latency ) {
        ret = cli->opt.handler(cli, &complete);
        if ( ret < 0 ) {
            // something goes wrong, client has been destroyed
            FLOG_DEBUG(glog, "buffer cannot write, fd=%d", cli->fd);
            return 1;
        }

        if ( complete ) {
            int server_timeout = cli->owner->sargs->timeout;
            if( server_timeout == 0 ) {
                destroy_client(cli);
                FLOG_DEBUG(glog, "timeout==0 fast shutdown, fd=%d", cli->fd);
                return 0;
            } else {
                latency = server_timeout;
                cli->response_complete++;
            }
        } else {
            latency = cli->opt.get_latency(cli);
        }
    }

    // create response timer node
    cli->response_timer = fev_tmsvc_add_timer(ftm_svc, latency, send_response_cb, cli);
    if( !cli->response_timer ) {
        FLOG_ERROR(glog, "create response timer failed, fd=%d", cli->fd);
        destroy_client(cli);
        return 1;
    }

    return 0;
}

static
void http_accept(fev_state* fev, int fd, void* ud)
{
    FLOG_DEBUG(glog, "accept fd=%d, pid=%d", fd, getpid());
    client_mgr* mgr = (client_mgr*)ud;
    if ( fd >= mgr->sargs->max_queue_len ) {
        FLOG_ERROR(glog, "fd > max open files, cannot accept pid=%d", getpid());
        close(fd);
        return;
    }

    client* cli = create_client();
    fev_buff* evbuff = fevbuff_new(fev, fd, http_read, http_error, cli);
    if( !evbuff ) {
        FLOG_ERROR(glog, "cannot create evbuff fd=%d", fd);
        goto EG_ERROR;
    }

    cli->fd = fd;
    cli->last_latency = FHTTP_INVALID_LATENCY;
    cli->evbuff = evbuff;
    cli->owner = mgr;
    cli->owner->current_conn++;

    // init client private opt
    resp_tbl[cli_mgr->sargs->response_type].init(cli);
    // call client's init
    cli->opt.init(cli);

    // create shutdown timer node
    cli->shutdown_timer = fev_tmsvc_add_timer(ftm_svc, mgr->sargs->timeout, connection_shutdown_cb, cli);
    if( !cli->shutdown_timer ) {
        FLOG_ERROR(glog, "create response timer failed, fd=%d", cli->fd);
        goto EG_ERROR;
    }

    // construct the http-parser
    cli->parser = malloc(sizeof(http_parser));
    http_parser_init(cli->parser, HTTP_REQUEST);
    cli->parser->data = cli;

    // fill the parser callbacks
    cli->settings.on_message_begin = http_msg_begin;
    cli->settings.on_url = http_on_url;
    cli->settings.on_status_complete = http_on_status_complete; // for response
    cli->settings.on_header_field = http_on_hdr_field;
    cli->settings.on_header_value = http_on_hdr_value;
    cli->settings.on_headers_complete = http_on_hdr_complete;
    cli->settings.on_body = http_on_body;
    cli->settings.on_message_complete = http_on_msg_complete;

    FLOG_DEBUG(glog, "fev_buff created fd=%d", fd);
    return;

EG_ERROR:
    destroy_client(cli);
}

static
void http_show_status(fev_state* fev __attribute__((unused)),
                      void* arg)
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
    int listen_fd = fnet_create_listen(NULL, sargs->port, sargs->max_open_files, 0);
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

    ftm_svc = fev_create_timer_service(fev, 1, FEV_TMSVC_SINGLE_LINKED);
    if( !ftm_svc ) {
        FLOG_ERROR(glog, "init timer service failed");
        exit(1);
    }

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
