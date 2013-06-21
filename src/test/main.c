// create by final
// desc : test unit

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../http_load_pcap.h"
#include "tu_inc.h"
#include "inc.h"
#include "read_conf.h"
void register_module(){
    tu_register_module(test_deal_duplicate,         "for testing duplicate pkg");
    tu_register_module(test_deal_muddled,         "for testing muddled pkg");


}
void readPcapConfig(const char *cfg_file, char *pcap_file, char *rules)
{
	void _read_pairs(char* key, char* value) {
		if ( strcmp(key, "pcap_file") == 0 ) {
		     strcpy(pcap_file, value);
		}
		else if(  strcmp(key, "pcap_filter_rule") == 0 ){
			strcpy(rules, value);
		}
	}
	GenConfig(cfg_file, _read_pairs);

}
int main(int argc, char** argv){

    tu_register_init();
    register_module();
    //load pcap
    char *pcap_file = (char*)malloc(1000);

    char *rules = (char*)malloc(1000);
    readPcapConfig("../../../etc/httpd_mock.cfg", pcap_file, rules);
   // printf("haha%s\n", pcap_file);
    load_http_resp(pcap_file, rules);
    tu_run_cases();
    return 0;
}



