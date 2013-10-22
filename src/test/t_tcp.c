#include <stdint.h>
#include "flist.h"
#include "ftu_inc.h"
#include "http_load_pcap.h"

typedef struct pcap_state_t{
    flist*   resp_list;
    uint32_t resp_cnt;
    struct timeval syn_ts; // timestamp of creation
} pcap_state_t;

typedef struct data_pkg_t{
    struct timeval ts;
    char*  data;
    int    len;
    uint32_t ack; //used for detection of dumplicate TCP packet
    uint32_t seq;
} data_pkg_t;

typedef struct resp_t{
    flist*      pkg_list;
    uint32_t    pkg_cnt;
    struct timeval cts; // timestamp of creation
} resp_t;

struct _cli_state_t {
    pcap_state_t* state;
    flist_iter    resp_iter;
    flist_iter    pkg_iter;
    resp_t*       curr_resp;
    data_pkg_t*   curr_pkg;
};

typedef struct {
    pcap_state_t* state;
    resp_t*       curr_resp;
    data_pkg_t*   curr_pkg;
    int           valid;
} sess_state_t;

int is_redundant(pcap_state_t* sess, int sess_index)
{
    int seq_arr[5000];
    int flag = 0;
    int resp_index, package_index=0;
    pcap_state_t* state = sess;

    int pkg_loop(void *data)
    {
        data_pkg_t* pkg = (data_pkg_t*)data;

        int i;
        for(i=0; i<package_index; ++i)
        {
            if(seq_arr[i] == pkg->seq)
            {
                 flag = 1;
                 return 0;
            }
        }
        seq_arr[package_index++] = pkg->seq;
        return 0;
    }

    int resp_loop(void *data)
    {
        resp_t* resp = (resp_t*)data;
        flist_foreach(resp->pkg_list, pkg_loop);
        resp_index++;
        return 0;
    }

    resp_index = 1;
    memset(seq_arr, 0, sizeof(seq_arr));
    flist_foreach(state->resp_list, resp_loop);

    return flag;
}

int is_muddled(pcap_state_t* sess, int sess_index )
{
    uint32_t pre_seq = 0;
    int resp_index = 1;
    int flag = 0;
    pcap_state_t* state = sess;

    int pkg_loop(void *data)
    {
        data_pkg_t* pkg = (data_pkg_t*)data;
        if(pkg->seq < pre_seq)
        {
            flag = 1;
            return 0;
        }
        pre_seq = pkg->seq;
        return 0;
    }

    int resp_loop(void *data)
    {
        resp_t* resp = (resp_t*)data;
        flist_foreach(resp->pkg_list, pkg_loop);
        resp_index++;
        return 0;
    }

    flist_foreach(state->resp_list, resp_loop);
    return flag;
}

void test_deal_duplicate()
{
    load_http_resp("./data/tcp_loss.pcap", "src port 80");

    int i = 0;
    cli_state_t* client = pc_create_state();
    // get the first
    pc_get_next_session(client);
    pcap_state_t* first = client->state;
    FTU_ASSERT( first );

    while(1)
    {
        pc_get_next_session(client);
        if( client->state == first)
            break;
        pcap_state_t* sess = client->state;
        FTU_ASSERT( is_redundant(sess, i) == 0 );
    }

    destroy_http_resp();
}

void test_deal_muddled()
{
    load_http_resp("./data/tcp_loss.pcap", "src port 80");

    int i=0;
    cli_state_t* client = pc_create_state();
    pc_get_next_session(client);
    pcap_state_t* first = client->state;
    FTU_ASSERT( first );

    while(1)
    {
        pc_get_next_session(client);
        if( client->state == first)
            break;
        pcap_state_t* sess = client->state;
        FTU_ASSERT( is_muddled(sess, i) == 0 );
    }

    destroy_http_resp();
}
