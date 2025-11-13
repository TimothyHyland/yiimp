#include "stratum.h"

// global mutex/cond
pthread_mutex_t g_job_mutex;
pthread_cond_t g_job_cond;

uint64_t lyra2z_height = 0;

////////////////////////////////////////////////////////////////////////
// Compute job version per client based on rolling settings
static inline unsigned int compute_client_version(YAAMP_JOB_TEMPLATE *templ)
{
	if(!templ->version_rolling_allowed) return templ->job_version;

	// roll allowed bits using version_mask
	return templ->job_version | (templ->version_mask & 0xFF);
}

////////////////////////////////////////////////////////////////////////
// Send job JSON to a client
static void job_send_to_client(YAAMP_CLIENT *client, YAAMP_JOB *job)
{
	if(!client || !job || !client->sock) return;
	if(!job->templ) return;

	YAAMP_JOB_TEMPLATE *templ = job->templ;

	unsigned int version = compute_client_version(templ);

	// send standard stratum JSON (difficulty + notify)
	socket_send(client->sock,
		"[[[\"mining.set_difficulty\",\"%.3g\"],[\"mining.notify\",\"%s\"]],\"%s\",%d]",
		client->difficulty_actual,
		templ->claim_hex,
		client->extranonce1,
		client->extranonce2size);

//	debuglog("job sent %x version %x to %s\n", job->id, version, client->sock->ip);
}

////////////////////////////////////////////////////////////////////////
// Send last job to a client
void job_send_last(YAAMP_CLIENT *client)
{
	if(!client || !client->jobid_sent) return;

	g_list_job.Enter();
	for(CLI li = g_list_job.first; li; li = li->next)
	{
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if(job->id != client->jobid_sent) continue;

		job_send_to_client(client, job);
		break;
	}
	g_list_job.Leave();
}

////////////////////////////////////////////////////////////////////////
// Broadcast a job to all clients
void job_broadcast(YAAMP_JOB *job)
{
	if(!job) return;

	g_list_client.Enter();
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->deleted) continue;
		if(!client->sock) continue;
		if(!job_can_mine(job)) continue;

		job_send_to_client(client, job);
	}
	g_list_client.Leave();
}

////////////////////////////////////////////////////////////////////////
// Send job by ID to a client
void job_send_jobid(YAAMP_CLIENT *client, int jobid)
{
	if(!client) return;

	g_list_job.Enter();
	for(CLI li = g_list_job.first; li; li = li->next)
	{
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if(job->id != jobid) continue;

		job_send_to_client(client, job);
		break;
	}
	g_list_job.Leave();
}

////////////////////////////////////////////////////////////////////////
// Assign a client to a job
static bool job_assign_client(YAAMP_JOB *job, YAAMP_CLIENT *client, double maxhash)
{
	#define RETURN_ON_CONDITION(condition, ret) \
		if(condition) { return ret; }

	RETURN_ON_CONDITION(client->deleted, true);
	RETURN_ON_CONDITION(client->jobid_next, true);
	RETURN_ON_CONDITION(client->jobid_locked && client->jobid_locked != job->id, true);
	RETURN_ON_CONDITION(client_find_job_history(client, job->id), true);
	RETURN_ON_CONDITION(maxhash > 0 && job->speed + client->speed > maxhash, true);

	if(!g_autoexchange && maxhash >= 0. && client->coinid != job->coind->id)
		return true;

	if(job->remote)
	{
		YAAMP_REMOTE *remote = job->remote;

		if(g_stratum_reconnect)
			{RETURN_ON_CONDITION(!client->extranonce_subscribe && !client->reconnectable, true);}
		else
			{RETURN_ON_CONDITION(!client->extranonce_subscribe, true);}

		RETURN_ON_CONDITION(client->reconnecting, true);
		RETURN_ON_CONDITION(job->count >= YAAMP_JOB_MAXSUBIDS, false);

		double difficulty_remote = client->difficulty_remote;
		if(remote->difficulty_actual < client->difficulty_actual)
		{
			RETURN_ON_CONDITION(client->difficulty_fixed, true);
			RETURN_ON_CONDITION(remote->difficulty_actual*4 < client->difficulty_actual, true);

			difficulty_remote = remote->difficulty_actual;
		}
		else if(remote->difficulty_actual > client->difficulty_actual)
			difficulty_remote = 0;

		if(remote->nonce2size == 2)
		{
			RETURN_ON_CONDITION(job->count > 0, false);
			strcpy(client->extranonce1, remote->nonce1);
			client->extranonce2size = 2;
		}
		else if(job->id != client->jobid_sent)
		{
			if(!job->remote_subids[client->extranonce1_id])
				job->remote_subids[client->extranonce1_id] = true;
			else
			{
				int i=0;
				for(; i<YAAMP_JOB_MAXSUBIDS; i++) if(!job->remote_subids[i])
				{
					job->remote_subids[i] = true;
					client->extranonce1_id = i;
					break;
				}
				RETURN_ON_CONDITION(i == YAAMP_JOB_MAXSUBIDS, false);
			}

			sprintf(client->extranonce1, "%s%02x", remote->nonce1, client->extranonce1_id);
			client->extranonce2size = remote->nonce2size-1;
			client->difficulty_remote = difficulty_remote;
		}

		client->jobid_locked = job->id;
	}
	else
	{
		strcpy(client->extranonce1, client->extranonce1_default);
		client->extranonce2size = client->extranonce2size_default;

		if (g_current_algo->name && !strcmp(g_current_algo->name,"decred")) {
			memset(client->extranonce1, '0', sizeof(client->extranonce1));
			memcpy(&client->extranonce1[16], client->extranonce1_default, 8);
			client->extranonce1[24] = '\0';
		}

		client->difficulty_remote = 0;
		client->jobid_locked = 0;
	}

	client->jobid_next = job->id;
	job->speed += client->speed;
	job->count++;

	if(strcmp(client->extranonce1, client->extranonce1_last) || client->extranonce2size != client->extranonce2size_last)
	{
		if(!client->extranonce_subscribe)
		{
			strcpy(client->extranonce1_reconnect, client->extranonce1);
			client->extranonce2size_reconnect = client->extranonce2size;

			strcpy(client->extranonce1, client->extranonce1_default);
			client->extranonce2size = client->extranonce2size_default;

			client->reconnecting = true;
			client->lock_count++;
			client->unlock = true;
			client->jobid_sent = client->jobid_next;

			socket_send(client->sock, "{\"id\":null,\"method\":\"client.reconnect\",\"params\":[\"%s\",%d,0]}\n", g_tcp_server, g_tcp_port);
		}
		else
		{
			strcpy(client->extranonce1_last, client->extranonce1);
			client->extranonce2size_last = client->extranonce2size;

			socket_send(client->sock, "{\"id\":null,\"method\":\"mining.set_extranonce\",\"params\":[\"%s\",%d]}\n",
				client->extranonce1, client->extranonce2size);
		}
	}

	return true;
}

////////////////////////////////////////////////////////////////////////
// Assign all clients to a job
void job_assign_clients(YAAMP_JOB *job, double maxhash)
{
	if(!job) return;

	job->speed = 0;
	job->count = 0;

	g_list_client.Enter();

	// pass0: locked
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->jobid_locked && client->jobid_locked != job->id) continue;

		if(!job_assign_client(job, client, maxhash)) break;
	}

	// pass1: sent
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->jobid_sent != job->id) continue;

		if(!job_assign_client(job, client, maxhash)) break;
	}

	// pass2: extranonce_subscribe
	if(job->remote) for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(!client->extranonce_subscribe) continue;

		if(!job_assign_client(job, client, maxhash)) break;
	}

	// pass3: rest
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(!job_assign_client(job, client, maxhash)) break;
	}

	g_list_client.Leave();
}

////////////////////////////////////////////////////////////////////////
// Thread functions
void *job_thread(void *p)
{
	CommonLock(&g_job_mutex);
	while(!g_exiting)
	{
		job_update();
		pthread_cond_wait(&g_job_cond, &g_job_mutex);
	}
}

void job_init()
{
	pthread_mutex_init(&g_job_mutex, 0);
	pthread_cond_init(&g_job_cond, 0);

	pthread_t thread3;
	pthread_create(&thread3, NULL, job_thread, NULL);
}

void job_signal()
{
	CommonLock(&g_job_mutex);
	pthread_cond_signal(&g_job_cond);
	CommonUnlock(&g_job_mutex);
}

////////////////////////////////////////////////////////////////////////
// Main job update logic
void job_update()
{
	job_reset_clients();

	g_list_job.Enter();
	job_sort();

	for(CLI li = g_list_job.first; li; li = li->next)
	{
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if(!job_can_mine(job)) continue;

		job_assign_clients(job, job->maxspeed);
		job_unlock_clients(job);

		if(!job_has_free_client()) break;
	}

	job_unlock_clients();
	g_list_job.Leave();

	////////////////////////////////////////////////////////////////////////////////////////////////

	g_list_coind.Enter();
	coind_sort();

	job_assign_clients_left(1);
	job_assign_clients_left(1);
	job_assign_clients_left(-1);

	g_list_coind.Leave();

	////////////////////////////////////////////////////////////////////////////////////////////////

	// catch clients without jobs
	g_list_client.Enter();
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->deleted || client->jobid_next) continue;

		g_current_algo->overflow = true;

		if(!g_list_coind.first) break;

		YAAMP_COIND *coind = (YAAMP_COIND *)g_list_coind.first->data;
		if(!coind) break;

		job_reset_clients(coind->job);
		coind_create_job(coind, true);
		job_assign_clients(coind->job, -1);

		break;
	}
	g_list_client.Leave();

	////////////////////////////////////////////////////////////////////////////////////////////////
	// broadcast jobs
	g_list_job.Enter();
	for(CLI li = g_list_job.first; li; li = li->next)
	{
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if(!job_can_mine(job)) continue;

		job_broadcast(job);
	}
	g_list_job.Leave();
}
