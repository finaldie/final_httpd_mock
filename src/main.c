#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <signal.h>

#include "read_conf.h"
#include "http_handlers.h"
#include "log_inc.h"

// global vars
int max_open_files = 0;
log_file_t* glog = NULL;

int set_cpu_mask(int cpu_index)                                               {
    cpu_set_t mask;
    /*  CPU_ZERO initializes all the bits in the mask to zero. */
    CPU_ZERO( &mask );
    /*  CPU_SET sets only the bit corresponding to cpu. */
    CPU_SET( cpu_index, &mask );
    /*  sched_setaffinity returns 0 in success */
    if( sched_setaffinity( 0, sizeof(mask), &mask ) == -1 ) {
        printf("WARNING: Could not set CPU Affinity, continuing...\n");
        return 1;
    }
    
    return 0;
}

static
int init_service_args(service_arg_t* sargs)
{
    if ( !sargs ) return 1;

    memset(sargs, 0, sizeof(service_arg_t));
    // configuration args
    sargs->max_queue_len = 1024;
    sargs->port = 80;
    sargs->workers = 1;
    sargs->response_type = RESP_TYPE_MIX;
    sargs->chunk_ratio = 20;
    sargs->min_latency = 100;
    sargs->max_latency = 200;
    sargs->min_response_size = 100;
    sargs->max_response_size = 200;
    sargs->min_chunk_latency = 100;
    sargs->max_chunk_latency = 200;
    sargs->min_chunk_response_size = 100;
    sargs->max_chunk_response_size = 200;
    sargs->chunk_blocks = 2;
    sargs->timeout = 10000;
    sargs->log_level = LOG_LEVEL_INFO;
    strncpy(sargs->log_filename, "/var/log/httpd_mock.log", FHTTP_MAX_LOG_FILENAME_SIZE);

    // common args
    sargs->listen_fd = -1;
    sargs->cpu_cores = sysconf(_SC_NPROCESSORS_CONF);

    struct rlimit limits;
    int ret = getrlimit(RLIMIT_NOFILE, &limits);
    if ( ret ) {
        perror("fail to get max open files");
        exit(1);
    }

    sargs->max_open_files = (int)limits.rlim_max;

    return 0;
}

void read_config(const char* filename, service_arg_t* sargs)
{
    // init args
    init_service_args(sargs);

    void _read_pairs(char* key, char* value) {
        if ( strcmp(key, "listen_port") == 0 ) {
            sargs->port = atoi(value);
        } else if ( strcmp(key, "max_connection") == 0 ) {
            sargs->max_queue_len = atoi(value);
        } else if ( strcmp(key, "workers") == 0 ) {
            sargs->workers = atoi(value);
        } else if ( strcmp(key, "response_type") == 0 ) {
            if ( strcasecmp(value, "CONTENT") == 0 ) {
                sargs->response_type = RESP_TYPE_CONTENT;
            } else if ( strcasecmp(value, "CHUNKED") == 0 ) {
                sargs->response_type = RESP_TYPE_CHUNKED;
            } else if ( strcasecmp(value, "MIX") == 0 ) {
                sargs->response_type = RESP_TYPE_MIX;
            } else {
                printf("not found any correct reponse type\n");
                exit(1);
            }
        } else if ( strcmp(key, "chunk_ratio") == 0 ) {
            sargs->chunk_ratio = atoi(value);
        } else if ( strcmp(key, "min_latency") == 0 ) {
            sargs->min_latency = atoi(value);
        } else if ( strcmp(key, "max_latency") == 0 ) {
            sargs->max_latency = atoi(value);
        } else if ( strcmp(key, "min_response_size") == 0 ) {
            sargs->min_response_size = atoi(value);
        } else if ( strcmp(key, "max_response_size") == 0 ) {
            sargs->max_response_size = atoi(value);
        } else if ( strcmp(key, "min_chunk_latency") == 0 ) {
            sargs->min_chunk_latency = atoi(value);
        } else if ( strcmp(key, "max_chunk_latency") == 0 ) {
            sargs->max_chunk_latency = atoi(value);
        } else if ( strcmp(key, "min_chunk_response_size") == 0 ) {
            sargs->min_chunk_response_size = atoi(value);
        } else if ( strcmp(key, "max_chunk_response_size") == 0 ) {
            sargs->max_chunk_response_size = atoi(value);
        } else if ( strcmp(key, "chunk_blocks") == 0 ) {
            sargs->chunk_blocks = atoi(value);
        } else if ( strcmp(key, "timeout") == 0 ) {
            sargs->timeout = atoi(value);
        } else if ( strcmp(key, "log_level") == 0 ) {
            if ( strcmp(value, "TRACE") == 0 ) {
                sargs->log_level = LOG_LEVEL_TRACE;
            } else if ( strcmp(value, "DEBUG") == 0 ) {
                sargs->log_level = LOG_LEVEL_DEBUG;
            } else if ( strcmp(value, "INFO") == 0 ) {
                sargs->log_level = LOG_LEVEL_INFO;
            } else if ( strcmp(value, "WARN") == 0 ) {
                sargs->log_level = LOG_LEVEL_WARN;
            } else if ( strcmp(value, "ERROR") == 0 ) {
                sargs->log_level = LOG_LEVEL_ERROR;
            } else if ( strcmp(value, "FATAL") == 0 ) {
                sargs->log_level = LOG_LEVEL_FATAL;
            } else {
                printf("not found any correct log level\n");
                exit(1);
            }
        } else if ( strcmp(key, "log_filename") == 0 ) {
            strncpy(sargs->log_filename, value, FHTTP_MAX_LOG_FILENAME_SIZE);
        }
    }

    int ret = GenConfig(filename, _read_pairs);
    if ( ret ) {
        printf("configuration error, please check it\n");
        exit(1);
    }
}

int checkServiceArgs(service_arg_t* sargs)
{
    // check max open files
    struct rlimit limits;
    int ret = getrlimit(RLIMIT_NOFILE, &limits);
    if ( ret ) {
        perror("fail to get max open files");
        exit(1);
    }

    max_open_files = (int)limits.rlim_max;
    printf("max open files = %d\n", max_open_files);
    if ( sargs->max_queue_len > max_open_files ) {
        sargs->max_queue_len = max_open_files;
    }

    // check workers
    if ( sargs->workers <= 0 ) {
        sargs->workers = 1;
    }

    // check port
    if ( sargs->port <= 0 || sargs->port > 65535 ) {
        printf("invalid port number [%d], must in [1-65535]\n", sargs->port);
        exit(1);
    }

    if ( (sargs->response_type == RESP_TYPE_MIX) &&
         (sargs->chunk_ratio < 0 || sargs->chunk_ratio > 100) ) {
        printf("chunk_ratio must in [0-100]\n");
        exit(1);
    }

    if ( sargs->min_latency < 0 || sargs->max_latency < 0 ) {
        printf("latency must >= 0\n");
        exit(1);
    }

    if ( sargs->min_latency > sargs->max_latency ) {
        printf("min latency must < max latency\n");
        exit(1);
    }

    if ( sargs->min_response_size < 0 || sargs->max_response_size < 0 ) {
        printf("response size must >= 0\n");
        exit(1);
    }

    if ( sargs->min_response_size > sargs->max_response_size ) {
        printf("min response size must > max response size\n");
        exit(1);
    }

    if ( sargs->min_chunk_latency < 0 || sargs->max_chunk_latency < 0 ) {
        printf("chunk latency must >= 0\n");
        exit(1);
    }

    if ( sargs->min_chunk_latency > sargs->max_chunk_latency ) {
        printf("min chunk latency must < max chunk latency\n");
        exit(1);
    }

    if ( sargs->min_chunk_response_size < 0 || sargs->max_chunk_response_size < 0 ) {
        printf("chunk response size must >= 0\n");
        exit(1);
    }

    if ( sargs->min_chunk_response_size > sargs->max_chunk_response_size ) {
        printf("min chunk response size must > max chunk response size\n");
        exit(1);
    }


    if ( sargs->chunk_blocks <= 0 ) {
        printf("chunk blocks must > 0\n");
        exit(1);
    }

    if ( sargs->log_level < LOG_LEVEL_TRACE || sargs->log_level > LOG_LEVEL_FATAL ) {
        printf("invalid log level\n");
        exit(1);
    }

    printf("args:\n");
    printf("  \\_ listen_port : %d\n", sargs->port);
    printf("  \\_ workers : %d\n", sargs->workers);
    printf("  \\_ max_connection : %d\n", sargs->max_queue_len);
    printf("  \\_ response type : %d\n", sargs->response_type);
    printf("  \\_ chunk ratio : %d\n", sargs->chunk_ratio);
    printf("  \\_ min_latency : %d\n", sargs->min_latency);
    printf("  \\_ max_latency : %d\n", sargs->max_latency);
    printf("  \\_ min_response_size : %d\n", sargs->min_response_size);
    printf("  \\_ max_response_size : %d\n", sargs->max_response_size);
    printf("  \\_ min_chunk_latency : %d\n", sargs->min_chunk_latency);
    printf("  \\_ max_chunk_latency : %d\n", sargs->max_chunk_latency);
    printf("  \\_ min_chunk_response_size : %d\n", sargs->min_chunk_response_size);
    printf("  \\_ max_chunk_response_size : %d\n", sargs->max_chunk_response_size);
    printf("  \\_ chunk_blocks : %d\n", sargs->chunk_blocks);
    printf("  \\_ timeout : %d\n", sargs->timeout);
    printf("  \\_ log_level : %d\n", sargs->log_level);
    printf("  \\_ log_filename : %s\n", sargs->log_filename);
    printf("\n");

    return 0;
}

void printUsage()
{
    printf("usage:\n");
    printf("  \\_ http_mock [-p port] [-c config_file]\n");
    printf("args:\n");
    printf("  \\_ p : listen port number\n");
    printf("  \\_ c : configuration file, use the absolute path\n");
}

void prepare(service_arg_t* sargs)
{
    // create log system
    glog = flog_create(sargs->log_filename);
    if ( !glog ) {
        printf("cannot init log system\n");
        exit(1);
    }

    flog_set_mode(LOG_ASYNC_MODE);
    flog_set_level(sargs->log_level);
    flog_set_flush_interval(1);

    sigset_t set, old;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, &old);
}

// NOTICE: before fork, do not write log
void dump_config(service_arg_t* sargs)
{
    FLOG_INFO(glog, "server started");
    FLOG_INFO(glog, "server args:");
    FLOG_INFO(glog, "  \\_ listen_port : %d", sargs->port);
    FLOG_INFO(glog, "  \\_ workers : %d", sargs->workers);
    FLOG_INFO(glog, "  \\_ max_connection : %d", sargs->max_queue_len);
    FLOG_INFO(glog, "  \\_ response type : %d\n", sargs->response_type);
    FLOG_INFO(glog, "  \\_ chunk ratio : %d\n", sargs->chunk_ratio);
    FLOG_INFO(glog, "  \\_ min_latency : %d", sargs->min_latency);
    FLOG_INFO(glog, "  \\_ max_latency : %d", sargs->max_latency);
    FLOG_INFO(glog, "  \\_ min_response_size : %d", sargs->min_response_size);
    FLOG_INFO(glog, "  \\_ max_response_size : %d", sargs->max_response_size);
    FLOG_INFO(glog, "  \\_ min_chunk_latency : %d\n", sargs->min_chunk_latency);
    FLOG_INFO(glog, "  \\_ max_chunk_latency : %d\n", sargs->max_chunk_latency);
    FLOG_INFO(glog, "  \\_ min_chunk_response_size : %d\n", sargs->min_chunk_response_size);
    FLOG_INFO(glog, "  \\_ max_chunk_response_size : %d\n", sargs->max_chunk_response_size);
    FLOG_INFO(glog, "  \\_ chunk_blocks : %d", sargs->chunk_blocks);
    FLOG_INFO(glog, "  \\_ timeout : %d", sargs->timeout);
    FLOG_INFO(glog, "  \\_ log_level : %d", sargs->log_level);
    FLOG_INFO(glog, "  \\_ log_filename : %s", sargs->log_filename);
}

int main ( int argc, char *argv[] )
{
    service_arg_t service_arg;
    init_service_args(&service_arg);

    printf("httpd mock pid=%d\n", getpid());

    if ( argc > 1 ) {
        char opt;
        while ((opt = getopt(argc, argv, "p:c:")) != -1) {
            switch (opt) {
                case 'c':
                    read_config(optarg, &service_arg);
                    goto prepare_start;
                case 'p':
                    service_arg.port = atoi(optarg);
                    break;
                default:
                    printUsage();
                    exit(0);
            }
        }
    } else {
        printUsage();
        exit(0);
    }

prepare_start:
    checkServiceArgs(&service_arg);
    init_listen(&service_arg);

    int i = 0;
    while ( i < (service_arg.workers - 1) ) {
        int ret = fork();
        if ( ret == 0 ) {
            break;
        }
        i++;
    }

    printf("start service pid=%d, ppid=%d\n", getpid(), getppid());
    if ( set_cpu_mask(i % service_arg.cpu_cores) ) {
        printf("set cpu mask for cpuid=%d failed\n", i);
    }

    prepare(&service_arg);
    init_service(&service_arg);
    dump_config(&service_arg);

    start_service();
    return EXIT_SUCCESS;
} /* ----------  end of function main  ---------- */
