#include "../http_load_pcap.h"
#include "../../flibs/ftu/tu_inc.h"
extern pcap_state_t** session_queue;
extern int resp_queue_idx;

int is_redundant(pcap_state_t* sess, int sess_index)
{
	int seq_arr[5000];
	int flag = 0;
	int resp_index, package_index=0;
    pcap_state_t* state = sess;
	//FILE* tcp_info_fptr = fopen("tcp_info.data", "a+");
	FILE* redundant_fptr = fopen("redundant.data", "a+");
	int pkg_loop(void *data)
	{
        data_pkg_t* pkg = (data_pkg_t*)data;

        int i;
        //fprintf(tcp_info_fptr, "%u ", pkg->seq);
        for(i=0; i<package_index; ++i)
        {
            if(seq_arr[i] == pkg->seq)
            {
                 fprintf(redundant_fptr,"session %d response %d seq %u \n", sess_index, resp_index, pkg->seq);
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
		//fprintf(tcp_info_fptr, "response %d", resp_index);
		flist_foreach(resp->pkg_list, pkg_loop);
		resp_index++;
		return 0;
	}


	//fprintf(tcp_info_fptr, "\nsession %d %u responses\n", sess_index,
	//            state->resp_cnt);
    resp_index = 1;
    memset(seq_arr, 0, sizeof(seq_arr));
    flist_foreach(state->resp_list, resp_loop);

    //fclose(tcp_info_fptr);
    fclose(redundant_fptr);
	return flag;
}
int is_muddled(pcap_state_t* sess, int sess_index )
{
	uint32_t pre_seq = 0;
	int resp_index = 1;
	int flag = 0;
    pcap_state_t* state = sess;
	FILE* muddle_fptr = fopen("muddled.data", "a+");

	int pkg_loop(void *data)
	{
		data_pkg_t* pkg = (data_pkg_t*)data;
		if(pkg->seq < pre_seq)
		{
			fprintf(muddle_fptr, "session %d response %d seq %u\n", sess_index, resp_index, pkg->seq);
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
	fclose(muddle_fptr);
	return flag;
}
void test_deal_duplicate()
{
	int i;
	for(i=0; i<resp_queue_idx; ++i)
	{
		pcap_state_t* sess = session_queue[i];
		FTU_ASSERT( is_redundant(sess, i)== 0 );
	}

}
void test_deal_muddled()
{
	int i;
	for(i=0; i<resp_queue_idx; ++i)
	{
		pcap_state_t* sess = session_queue[i];
		FTU_ASSERT( is_muddled(sess, i)== 0 );
	}

}


