#include "stratum.h"

static int g_job_next_id = 0;

int job_get_jobid()
{
	CommonLock(&g_job_create_mutex);
	int jobid = ++g_job_next_id;
	CommonUnlock(&g_job_create_mutex);
	return jobid;
}

static void job_mining_notify_buffer(YAAMP_JOB *job, char *buffer)
{
	YAAMP_JOB_TEMPLATE *templ = job->templ;

	// Prepare version field for rolling if allowed
	char version_hex[32];
	if (templ->version_rolling_allowed)
		sprintf(version_hex, "%08x", templ->job_version);
	else
		strcpy(version_hex, templ->version);

	if (!strcmp(g_stratum_algo, "lbry")) {
		sprintf(buffer, "{\"id\":null,\"method\":\"mining.notify\",\"params\":["
			"\"%x\",\"%s\",\"%s\",\"%s\",\"%s\",[%s],\"%s\",\"%s\",\"%s\",true]}\n",
			job->id, templ->prevhash_be, templ->claim_be, templ->coinb1, templ->coinb2,
			templ->txmerkles, version_hex, templ->nbits, templ->ntime);
		return;
	} else if (strlen(templ->extradata_hex) == 128) {
		sprintf(buffer, "{\"id\":null,\"method\":\"mining.notify\",\"params\":["
			"\"%x\",\"%s\",\"%s\",\"%s\",\"%s\",[%s],\"%s\",\"%s\",\"%s\",true]}\n",
			job->id, templ->prevhash_be, templ->extradata_be, templ->coinb1, templ->coinb2,
			templ->txmerkles, version_hex, templ->nbits, templ->ntime);
		return;
	}

	// standard stratum
	sprintf(buffer, "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"%x\",\"%s\",\"%s\",\"%s\",[%s],\"%s\",\"%s\",\"%s\",true]}\n",
		job->id, templ->prevhash_be, templ->coinb1, templ->coinb2, templ->txmerkles, version_hex, templ->nbits, templ->ntime);
}

static YAAMP_JOB *job_get_last(int coinid)
{
	g_list_job.Enter();
	for(CLI li = g_list_job.first; li; li = li->prev)
	{
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if(!job_can_mine(job)) continue;
		if(!job->coind) continue;
		if(coinid > 0 && job->coind->id != coinid) continue;

		g_list_job.Leave();
		return job;
	}
	g_list_job.Leave();
	return NULL;
}

void job_send_last(YAAMP_CLIENT *client)
{
#ifdef NO_EXCHANGE
	YAAMP_JOB *job = job_get_last(client->coinid);
	if(!job) job = job_get_last(0);
#else
	YAAMP_JOB *job = job_get_last(0);
#endif
	if(!job) return;

	YAAMP_JOB_TEMPLATE *templ = job->templ;
	client->jobid_sent = job->id;

	char buffer[YAAMP_SMALLBUFSIZE];
	job_mining_notify_buffer(job, buffer);

	socket_send_raw(client->sock, buffer, strlen(buffer));
}

void job_send_jobid(YAAMP_CLIENT *client, int jobid)
{
	YAAMP_JOB *job = (YAAMP_JOB *)object_find(&g_list_job, jobid, true);
	if(!job)
	{
		job_send_last(client);
		return;
	}

	char buffer[YAAMP_SMALLBUFSIZE];
	job_mining_notify_buffer(job, buffer);

	YAAMP_JOB_TEMPLATE *templ = job->templ;
	client->jobid_sent = job->id;

	socket_send_raw(client->sock, buffer, strlen(buffer));
	object_unlock(job);
}

void job_broadcast(YAAMP_JOB *job)
{
	int s1 = current_timestamp_dms();
	int count = 0;
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 100000;

	YAAMP_JOB_TEMPLATE *templ = job->templ;

	char buffer[YAAMP_SMALLBUFSIZE];
	job_mining_notify_buffer(job, buffer);

	g_list_client.Enter();
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->deleted) continue;
		if(!client->sock) continue;

		if(client->jobid_next != job->id) continue;
		if(client->jobid_sent == job->id) continue;

		client->jobid_sent = job->id;
		client_add_job_history(client, job->id);

		client_adjust_difficulty(client);

		setsockopt(client->sock->sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

		if (socket_send_raw(client->sock, buffer, strlen(buffer)) == -1) {
			int err = errno;
			client->broadcast_timeouts++;
			if (client->broadcast_timeouts >= 3) {
				shutdown(client->sock->sock, SHUT_RDWR);
				clientlog(client, "unable to send job, sock err %d (%d times)", err, client->broadcast_timeouts);
				if(client->workerid && !client->reconnecting) {
					db_clear_worker(g_db, client);
				}
				object_delete(client);
			}
		}
		count++;
	}

	g_list_client.Leave();
	g_last_broadcasted = time(NULL);

	int s2 = current_timestamp_dms();
	if(!count) return;

	uint64_t coin_target = decode_compact(templ->nbits);
	if (templ->nbits && !coin_target) coin_target = 0xFFFF000000000000ULL;
	double coin_diff = target_to_diff(coin_target);

	debuglog("%s %d - diff %.9f job %x to %d/%d/%d clients, hash %.3f/%.3f in %.1f ms\n", job->name,
		templ->height, coin_diff, job->id, count, job->count, g_list_client.count, job->speed, job->maxspeed, 0.1*(s2-s1));
}
