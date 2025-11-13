#include "stratum.h"

//#define MERKLE_DEBUGLOG
//#define DONTSUBMIT

uint64_t lyra2z_height = 0;

////////////////////////////////////////////////////////////////////////
// Assign client version/rolling logic helper
static inline unsigned int compute_client_version(YAAMP_JOB_TEMPLATE *templ)
{
	if(!templ->version_rolling_allowed) return templ->job_version;
	// roll bits allowed by version_mask
	return templ->job_version | (templ->version_mask & 0xFF); 
}

////////////////////////////////////////////////////////////////////////
static void job_send_to_client(YAAMP_CLIENT *client, YAAMP_JOB *job)
{
	if(!client || !job) return;
	if(!client->sock) return;

	YAAMP_JOB_TEMPLATE *templ = job->templ;
	if(!templ) return;

	// compute version for client
	unsigned int version = compute_client_version(templ);

	// prepare job JSON for this client
	socket_send(client->sock,
		"[[[\"mining.set_difficulty\",\"%.3g\"],[\"mining.notify\",\"%s\"]],\"%s\",%d]",
		client->difficulty_actual,
		templ->claim_hex,
		client->extranonce1,
		client->extranonce2size);

	// optionally debug
//	debuglog("sent job %x version %x to %s\n", job->id, version, client->sock->ip);
}

////////////////////////////////////////////////////////////////////////
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
