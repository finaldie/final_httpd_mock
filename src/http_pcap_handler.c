#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "flibs/fev_listener.h"
#include "flibs/fev_buff.h"
#include "flibs/fev_timer.h"
#include "flibs/ftu_inc.h"
#include "flibs/flog_inc.h"
#include "flibs/fnet_core.h"

#include "http_handlers.h"
#include "http_load_pcap.h"

extern log_file_t* glog;

#define FPCAP_ST(cli) ((cli_state_t*)(cli->priv))

static
int  pcap_resp_handler(client* cli, int* complete)
{
    pc_get_next_pkg(FPCAP_ST(cli));

    // all send out?
    if( pc_is_last_pkg(FPCAP_ST(cli)) ) {
        *complete = 1;
    }

    return fevbuff_write(cli->evbuff, pc_get_pkg_data(FPCAP_ST(cli)), pc_get_pkg_len(FPCAP_ST(cli)));
}

static
void pcap_resp_free(client* cli)
{
    pc_destroy_state(FPCAP_ST(cli));
}

static
void pcap_resp_init(client* cli)
{
    cli_state_t* cli_state = pc_create_state();
    pc_get_next_session(cli_state);
    cli->priv = cli_state;
}

static
int  pcap_get_latency(client* cli)
{
    int latency = pc_get_next_pkg_latency(FPCAP_ST(cli));
    if( latency == FPCAP_NO_LATENCY ) {
        //printf("latency!!=%d\n", latency);
        return cli->owner->sargs->timeout;
    }
    //printf("latency=%d\n", latency);
    return latency;
}

static
void pcap_pre_send(client* cli)
{
    // move idx to next
    pc_get_next_resp(FPCAP_ST(cli));
}

void init_pcap_resp_opt(client* cli)
{
    cli->opt.init = pcap_resp_init;
    cli->opt.free = pcap_resp_free;
    cli->opt.get_latency = pcap_get_latency;
    cli->opt.pre_send_req = pcap_pre_send;
    cli->opt.handler = pcap_resp_handler;
}
