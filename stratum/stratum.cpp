#include "stratum.h"
#include <signal.h>
#include <sys/resource.h>

// === ORIGINAL GLOBAL LISTS AND VARIABLES ===
CommonList g_list_coind;
CommonList g_list_client;
CommonList g_list_job;
CommonList g_list_remote;
CommonList g_list_renter;
CommonList g_list_share;
CommonList g_list_worker;
CommonList g_list_block;
CommonList g_list_submit;
CommonList g_list_source;

int g_tcp_port;
char g_tcp_server[1024];
char g_tcp_password[1024];

char g_sql_host[1024];
char g_sql_database[1024];
char g_sql_username[1024];
char g_sql_password[1024];
int g_sql_port = 3306;

char g_stratum_coin_include[256];
char g_stratum_coin_exclude[256];

char g_stratum_algo[256];
double g_stratum_difficulty;
double g_stratum_nicehash_difficulty;
double g_stratum_nicehash_min_diff;
double g_stratum_nicehash_max_diff;
double g_stratum_min_diff;
double g_stratum_max_diff;

int g_stratum_max_ttf;
int g_stratum_max_cons = 5000;
bool g_stratum_reconnect;
bool g_stratum_renting;
bool g_stratum_segwit = false;

int g_limit_txs_per_block = 0;

bool g_handle_haproxy_ips = false;
int g_socket_recv_timeout = 600;

bool g_debuglog_client;
bool g_debuglog_hash;
bool g_debuglog_socket;
bool g_debuglog_rpc;
bool g_debuglog_list;
bool g_debuglog_remote;

bool g_autoexchange = true;

uint64_t g_max_shares = 0;
uint64_t g_shares_counter = 0;
uint64_t g_shares_log = 0;

bool g_allow_rolltime = true;
time_t g_last_broadcasted = 0;
YAAMP_DB *g_db = NULL;

pthread_mutex_t g_db_mutex;
pthread_mutex_t g_nonce1_mutex;
pthread_mutex_t g_job_create_mutex;

struct ifaddrs *g_ifaddr;
volatile bool g_exiting = false;

YAAMP_ALGO *g_current_algo = NULL;

// === ROLLING / NTIME / EXTRANONCE LOGIC ===
static void apply_rolling_nonce(YAAMP_CLIENT *client, uint8_t *binary_nonce, const char *hex_nonce)
{
    hex_to_bin(hex_nonce, binary_nonce, 32);

    for(int i = 0; i < client->extranonce2size; i++)
        binary_nonce[i] = client->extranonce2[i];

    if(client->block_template && client->block_template->ntime && g_allow_rolltime)
    {
        uint32_t *ntime_ptr = (uint32_t*)&binary_nonce[12];
        *ntime_ptr = client->block_template->ntime + (rand() & 1);
    }
}

// === SHARE VALIDATION ===
static bool validate_client_share(YAAMP_CLIENT *client, const char *hex_nonce, double target)
{
    uint8_t binary_nonce[32];
    apply_rolling_nonce(client, binary_nonce, hex_nonce);

    uint8_t hash[32];
    g_current_algo->hash_function(binary_nonce, hash, sizeof(binary_nonce));

    if(!check_target(hash, target))
        return false;

    client->shares++;
    g_shares_counter++;

    return true;
}

// === JOB ASSIGNMENT ===
static bool job_assign_client(YAAMP_JOB *job, YAAMP_CLIENT *client, double maxhash)
{
    if(client->deleted) return true;
    if(client->jobid_next) return true;
    if(client->jobid_locked && client->jobid_locked != job->id) return true;
    if(client_find_job_history(client, job->id)) return true;
    if(maxhash > 0 && job->speed + client->speed > maxhash) return true;

    if(!g_autoexchange && maxhash >= 0. && client->coinid != job->coind->id) return true;

    if(job->remote)
    {
        YAAMP_REMOTE *remote = job->remote;
        if(!client->extranonce_subscribe && !client->reconnectable) return true;
        if(client->reconnecting) return true;
        if(job->count >= YAAMP_JOB_MAXSUBIDS) return false;

        if(remote->difficulty_actual < client->difficulty_actual)
        {
            if(client->difficulty_fixed) return true;
            if(remote->difficulty_actual*4 < client->difficulty_actual) return true;
        }
    }

    client->jobid_next = job->id;
    client->job_next = job;
    job->count++;

    return false;
}

// === BROADCAST JOB TO ALL CLIENTS ===
void job_broadcast(YAAMP_JOB *job)
{
    int count = 0;

    for(CLI li = g_list_client.first; li; li = li->next)
    {
        YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
        if(client->deleted) continue;
        if(!client->sock) continue;
        if(client->job_next != job) continue;

        uint8_t binary_nonce[32];
        apply_rolling_nonce(client, binary_nonce, client->current_hex_nonce);

        client_send_job(client, job, binary_nonce);
        count++;
    }

    g_last_broadcasted = time(NULL);
}

// === MONITOR THREAD ===
void *monitor_thread(void *p)
{
    while(!g_exiting)
    {
        sleep(120);

        if(g_last_broadcasted + YAAMP_MAXJOBDELAY < time(NULL))
        {
            g_exiting = true;
            stratumlogdate("%s dead lock, exiting...\n", g_stratum_algo);
            exit(1);
        }

        if(g_max_shares && g_shares_counter)
        {
            if((g_shares_counter - g_shares_log) > 10000)
            {
                stratumlogdate("%s %luK shares...\n", g_stratum_algo, (g_shares_counter/1000u));
                g_shares_log = g_shares_counter;
            }

            if(g_shares_counter > g_max_shares)
            {
                g_exiting = true;
                stratumlogdate("%s need a restart (%lu shares), exiting...\n", g_stratum_algo, (unsigned long) g_max_shares);
                exit(1);
            }
        }
    }
}

// === STRATUM THREAD ===
void *stratum_thread(void *p)
{
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_sock <= 0) yaamp_error("socket");

    int optval = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

    struct sockaddr_in serv;
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_port = htons(g_tcp_port);

    int res = bind(listen_sock, (struct sockaddr*)&serv, sizeof(serv));
    if(res < 0) yaamp_error("bind");

    res = listen(listen_sock, 4096);
    if(res < 0) yaamp_error("listen");

    int failcount = 0;
    while(!g_exiting)
    {
        int sock = accept(listen_sock, NULL, NULL);
        if(sock <= 0)
        {
            int error = errno;
            failcount++;
            usleep(50000);
            if(error == 24 && failcount > 5)
            {
                g_exiting = true;
                stratumlogdate("%s too much socket failure, exiting...\n", g_stratum_algo);
                exit(error);
            }
            continue;
        }

        failcount = 0;
        pthread_t thread;
        int res = pthread_create(&thread, NULL, client_thread, (void *)(long)sock);
        if(res != 0)
        {
            close(sock);
            g_exiting = true;
            stratumlog("%s pthread_create error %d %d\n", g_stratum_algo, res, errno);
        }

        pthread_detach(thread);
    }
}

// === CLIENT SHARE SUBMISSION ===
void client_submit_share(YAAMP_CLIENT *client, const char *hex_nonce)
{
    double target = client->difficulty_actual;

    if(validate_client_share(client, hex_nonce, target))
    {
        share_add(client, hex_nonce, target);
        stratumlogdate("%s share accepted from %s\n", g_stratum_algo, client->username);
    }
    else
    {
        stratumlogdate("%s invalid share from %s\n", g_stratum_algo, client->username);
    }
}
