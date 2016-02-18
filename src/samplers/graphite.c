#include <stddef.h>
#define _GNU_SOURCE
#include <sys/uio.h>
#include <sys/socket.h>
#include "brubeck.h"

#ifdef __GLIBC__
#	if ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 12)))
#		define HAVE_RECVMMSG 1
#	endif
#endif

#define MAX_PACKET_SIZE 512

#ifdef HAVE_RECVMMSG
static void graphite_run_recvmmsg(struct brubeck_graphite *graphite, int sock)
{
        const unsigned int SIM_PACKETS = graphite->mmsg_count;
        struct brubeck_server *server = graphite->sampler.server;

        struct brubeck_graphite_msg msg;
        struct brubeck_metric *metric;
        unsigned int i;

        struct iovec iovecs[SIM_PACKETS];
        struct mmsghdr msgs[SIM_PACKETS];

        memset(msgs, 0x0, sizeof(msgs));

        for (i = 0; i < SIM_PACKETS; ++i) {
                iovecs[i].iov_base = xmalloc(MAX_PACKET_SIZE);
                iovecs[i].iov_len = MAX_PACKET_SIZE - 1;
                msgs[i].msg_hdr.msg_iov = &iovecs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
        }

        log_splunk("sampler=graphite event=worker_online syscall=recvmmsg socket=%d", sock);

        for (;;) {
                int res = recvmmsg(sock, msgs, SIM_PACKETS, 0, NULL);

                if (res < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                continue;

                        log_splunk_errno("sampler=graphite event=failed_read");
                        brubeck_server_mark_dropped(server);
                        continue;
                }

                /* store stats */
                brubeck_atomic_add(&server->stats.metrics, SIM_PACKETS);
                brubeck_atomic_add(&graphite->sampler.inflow, SIM_PACKETS);

                for (i = 0; i < SIM_PACKETS; ++i) {
                        char *buf = msgs[i].msg_hdr.msg_iov->iov_base;
                        int len = msgs[i].msg_len;

                        if (brubeck_graphite_msg_parse(&msg, buf, len) < 0) {
                                if (msg.key_len > 0)
                                        buf[msg.key_len] = ':';

                                log_splunk("sampler=graphite event=bad_key key='%.*s'", len, buf);
                                brubeck_server_mark_dropped(server);
                                continue;
                        }

                        metric = brubeck_metric_find(server, msg.key, msg.key_len, BRUBECK_MT_GAUGE);

                        if (metric != NULL)
                                brubeck_metric_record(metric, msg.value);
                }
        }

}
#endif

static void graphite_run_recvmsg(struct brubeck_graphite *graphite, int sock)
{
        struct brubeck_server *server = graphite->sampler.server;

        struct brubeck_graphite_msg msg;
        struct brubeck_metric *metric;

        char buffer[MAX_PACKET_SIZE];

        struct sockaddr_in reporter;
        socklen_t reporter_len = sizeof(reporter);
        memset(&reporter, 0, reporter_len);

        log_splunk("sampler=graphite event=worker_online syscall=recvmsg socket=%d", sock);

        for (;;) {
                int res = recvfrom(sock, buffer,
                        sizeof(buffer) - 1, 0,
                        (struct sockaddr *)&reporter, &reporter_len);

                if (res < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;

			log_splunk_errno("sampler=graphite event=failed_read from=%s",
				inet_ntoa(reporter.sin_addr));
			brubeck_server_mark_dropped(server);
			continue;
                }

                /* store stats */
                brubeck_atomic_inc(&server->stats.metrics);
                brubeck_atomic_inc(&graphite->sampler.inflow);

                if (brubeck_graphite_msg_parse(&msg, buffer, (size_t)res) < 0) {
                        if (msg.key_len > 0)
                                buffer[msg.key_len] = ':';

                        log_splunk("sampler=graphite event=bad_key key='%.*s' from=%s",
                                res, buffer, inet_ntoa(reporter.sin_addr));

                        brubeck_server_mark_dropped(server);
                        continue;
                }

                metric = brubeck_metric_find(server, msg.key, msg.key_len, BRUBECK_MT_GAUGE);
                 
		if (metric != NULL) {
			brubeck_metric_record(metric, msg.value);
		}
        }
}

int brubeck_graphite_msg_parse(struct brubeck_graphite_msg *msg, char *buffer, size_t length)
{
        char *end = buffer + length;
        *end = '\0';

        /**
         * Message key: all the string until the first whitespace.
         * metricname value [timestamp]
         * ^^^^^^^^^^
         */
        {

                msg->key = buffer;
                msg->key_len = 0;
                while (*buffer != ' ' && *buffer != '\0') {
                    ++buffer;
                }
                if (*buffer == '\0')
                        return -1;

                msg->key_len = buffer - msg->key;
                *buffer++ = '\0';
        }

        /**
         * Message value: the numeric value until the second whitespace. 
         * This is already converted to an integer.
         * metricname value [timestamp]
         *            ^^^^^
         */
        {
                int negative = 0;
                char *start = buffer;

                msg->value = 0.0;

                if (*buffer == '-') {
                        ++buffer;
                        negative = 1;
                }

                while (*buffer >= '0' && *buffer <= '9') {
                        msg->value = (msg->value * 10.0) + (*buffer - '0');
                        ++buffer;
                }

                if (*buffer == '.') {
                        double f = 0.0, n = 0.0;
                        ++buffer;

                        while (*buffer >= '0' && *buffer <= '9') {
                                f = (f * 10.0) + (*buffer - '0');
                                ++buffer;
                                n += 1.0;
                        }

                        msg->value += f / pow(10.0, n);
                }

                if (negative)
                        msg->value = -msg->value;

                if (unlikely(*buffer == 'e')) {
                        msg->value = strtod(start, &buffer);
                }

                if (*buffer == '\n')
                    return 0;
                if (*buffer != ' ')
                    return -1;

                buffer++;
        }

        /**
         * Timestamp
         * This is optional. Parse only.
         */
        {
                msg->timestamp = 0;

                while (*buffer >= '0' && *buffer <= '9') {
                        msg->timestamp = (msg->timestamp * 10) + (*buffer - '0');
                        ++buffer;
                }

                if (*buffer != '\n')
                        return -1;
        }
}

static void *graphite__thread(void *_in)
{
        struct brubeck_graphite *graphite = _in;
        int sock = graphite->sampler.in_sock;

#ifdef SO_REUSEPORT
        if (sock < 0) {
                sock = brubeck_sampler_socket(&graphite->sampler, 1);
        }
#endif

        assert(sock >= 0);

#ifdef HAVE_RECVMMSG
        if (graphite->mmsg_count > 1) {
                graphite_run_recvmmsg(graphite, sock);
                return NULL;
        }
#endif

        graphite_run_recvmsg(graphite, sock);
        return NULL;
}

static void run_worker_threads(struct brubeck_graphite *graphite)
{
        unsigned int i;
        graphite->workers = xmalloc(graphite->worker_count * sizeof(pthread_t));

        for (i = 0; i < graphite->worker_count; ++i) {
                if (pthread_create(&graphite->workers[i], NULL, &graphite__thread, graphite) != 0) {
                        die("failed to start sampler thread");
                }
        }
}

static void shutdown_sampler(struct brubeck_sampler *sampler)
{
        struct brubeck_graphite *graphite = (struct brubeck_graphite *)sampler;
        size_t  i;

        for (i = 0 ; i < graphite->worker_count; ++i) {
                pthread_cancel(graphite->workers[i]);
        }
}

struct brubeck_sampler *
brubeck_graphite_new(struct brubeck_server *server, json_t *settings)
{
        struct brubeck_graphite *std = xmalloc(sizeof(struct brubeck_graphite));

        char *address;
        int port;
        int multisock = 0;

        std->sampler.type = BRUBECK_SAMPLER_GRAPHITE;
         
	std->sampler.shutdown = &shutdown_sampler;
	std->sampler.in_sock = -1;
	std->worker_count = 4;
	std->mmsg_count = 1;

	json_unpack_or_die(settings,
		"{s:s, s:i, s?:i, s?:i, s?:b}",
		"address", &address,
		"port", &port,
		"workers", &std->worker_count,
		"multimsg", &std->mmsg_count,
		"multisock", &multisock);

	brubeck_sampler_init_inet(&std->sampler, server, address, port);

#ifndef SO_REUSEPORT
	multisock = 0;
#endif

	if (!multisock)
		std->sampler.in_sock = brubeck_sampler_socket(&std->sampler, 0);

	run_worker_threads(std);
	return &std->sampler;
}
