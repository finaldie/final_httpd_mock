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

void init_mix_resp_opt(client* cli)
{
    service_arg_t* sargs = cli->owner->sargs;
    if( get_ischunked(sargs->response_type, sargs->chunk_ratio) ) {
        init_chunk_resp_opt(cli);
    } else {
        init_content_resp_opt(cli);
    }
}
