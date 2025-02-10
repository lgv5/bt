/*
 * Copyright (c) 2025 Lucas Gabriel Vuotto <lucas@lgv5.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bt.h"


#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define BTTC_UDP_ANNOUNCE_MAGIC	UINT64_C(0x41727101980)

#define BTT_UDP_ACTION_CONNECT	0
#define BTT_UDP_ACTION_ANNOUNCE	1
#define BTT_UDP_ACTION_SCRAPE	2


struct bttc_ctx {
	const char		*url;
	char			*host;
	char			*port;
	int			 socktype;
	int			 sock;
	uint64_t		 cid;
};

struct udpc_req_head {
	uint64_t	connection_id;
	uint32_t	action;
	uint32_t	transaction_id;
} __packed;

struct udpc_res_head {
	uint32_t	action;
	uint32_t	transaction_id;
} __packed;

struct udpc_connect_req {
	uint64_t	protocol_id;
	uint32_t	action;
	uint32_t	transaction_id;
} __packed;

struct udpc_connect_res {
	uint32_t	action;
	uint32_t	transaction_id;
	uint64_t	connection_id;
} __packed;

struct udpc_scrape_res {
	uint32_t	*seeders;
	uint32_t	*completed;
	uint32_t	*leechers;
};


static int	tracker_dial(const char *, const char *, int, const char **);
static int	url_parse(const char *, char **, char **);

static int	udpc_action_connect(int, uint64_t *);
static int	udpc_action_scrape(int, uint64_t, struct btt_scrape_stats *,
		    const struct btih *, size_t);


static int
tracker_dial(const char *host, const char *port, int socktype,
    const char **cause)
{
	struct addrinfo	hints, *res, *res0;
	int		error, save_errno, s;

	*cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = socktype;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error) {
		*cause = gai_strerror(error);
		return -1;
	}

	s = -1;
	for (res = res0; res != NULL; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			*cause = "socket";
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			*cause = "connect";
			save_errno = errno;
			close(s);
			errno = save_errno;
			s = -1;
			continue;
		}

		break;
	}

	return s;
}

static int
url_parse(const char *tracker, char **host, char **port)
{
	const char	*colon, *end;
	size_t		 hostlen, portlen;

	colon = strchr(tracker, ':');
	if (colon == NULL || colon == tracker)
		return 0;
	hostlen = colon - tracker + 1;

	colon++;
	end = strchr(colon, '/');
	if (end == NULL)
		end = strchr(colon, '\0');
	if (end == colon)
		return 0;
	portlen = end - colon + 1;

	*host = malloc(hostlen);
	*port = malloc(portlen);
	if (*host == NULL || *port == NULL) {
		free(*host);
		free(*port);
		*host = *port = NULL;
		return 0;
	}

	(void)strlcpy(*host, tracker, hostlen);
    	(void)strlcpy(*port, colon, portlen);

	/* XXX handle extensions. */

	return 1;
}


static int
udpc_action_connect(int s, uint64_t *cid)
{
	char			buf[512];
	struct udpc_connect_req	req;
	struct udpc_connect_res	res;
	uint32_t		tid;

	tid = arc4random();
	req.protocol_id = htobe64(BTTC_UDP_ANNOUNCE_MAGIC);
	req.action = htobe32(BTT_UDP_ACTION_CONNECT);
	req.transaction_id = htobe32(tid);

	if (send(s, &req, sizeof(req), 0) != sizeof(req))
		return 0;
	if (recv(s, buf, sizeof(buf), 0) < (ssize_t)sizeof(res))
		return 0;
	memcpy(&res, buf, sizeof(res));

	if (be32toh(res.action) != BTT_UDP_ACTION_CONNECT ||
	    be32toh(res.transaction_id) != tid)
		return 0;

	*cid = be64toh(res.connection_id);

	return 1;
}

static int
udpc_action_scrape(int s, uint64_t cid, struct btt_scrape_stats *stats,
    const struct btih *btih, size_t btihlen)
{
	struct iovec		 reqiov[2], resiov[2];
	uint32_t		*rawstats;
	uint8_t			*rawbtih;
	struct msghdr		 reqmsg, resmsg;
	struct udpc_req_head	 reqhead;
	struct udpc_res_head	 reshead;
	size_t			 i;
	ssize_t			 n;
	uint32_t		 tid;

	if (btihlen == 0)
		return 0;

	rawbtih = reallocarray(NULL, btihlen, BTIH_LEN * sizeof(uint8_t));
	if (rawbtih == NULL)
		return 0;

	tid = arc4random();
	reqhead.connection_id = htobe64(cid);
	reqhead.action = htobe32(BTT_UDP_ACTION_SCRAPE);
	reqhead.transaction_id = htobe32(tid);
	reqiov[0].iov_base = &reqhead;
	reqiov[0].iov_len = sizeof(reqhead);

	for (i = 0; i < btihlen; i++)
		memcpy(&rawbtih[i * BTIH_LEN], btih[i].hash,
		    BTIH_LEN * sizeof(uint8_t));
	reqiov[1].iov_base = rawbtih;
	reqiov[1].iov_len = btihlen * BTIH_LEN * sizeof(uint8_t);

	memset(&reqmsg, 0, sizeof(reqmsg));
	reqmsg.msg_iov = reqiov;
	reqmsg.msg_iovlen = nitems(reqiov);

	n = sendmsg(s, &reqmsg, 0);
	free(rawbtih);
	if (n == -1)
		return 0;

	rawstats = reallocarray(NULL, btihlen, 3 * sizeof(uint32_t));
	if (rawstats == NULL)
		return 0;

	resiov[0].iov_base = &reshead;
	resiov[0].iov_len = sizeof(reshead);
	resiov[1].iov_base = rawstats;
	resiov[1].iov_len = btihlen * 3 * sizeof(uint32_t);

	memset(&resmsg, 0, sizeof(resmsg));
	resmsg.msg_iov = resiov;
	resmsg.msg_iovlen = nitems(resiov);

	n = recvmsg(s, &resmsg, 0);
	if (n == -1) {
		free(rawstats);
		return 0;
	}

	if (be32toh(reshead.action) != BTT_UDP_ACTION_SCRAPE ||
	    be32toh(reshead.transaction_id) != tid) {
		free(rawstats);
		return 0;
	}

	for (i = 0; i < btihlen; i++) {
		stats[i].seeders = be32toh(rawstats[3 * i]);
		stats[i].completed = be32toh(rawstats[3 * i + 1]);
		stats[i].leechers = be32toh(rawstats[3 * i + 2]);
	}
	free(rawstats);

	return 1;
}


struct bttc_ctx *
bttc_ctx_new(const char *tracker)
{
	struct bttc_ctx	*ctx;

	if (tracker == NULL)
		return NULL;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return NULL;

	if (strncmp(tracker, "udp://", 6) == 0) {
		if (!url_parse(tracker + 6, &ctx->host, &ctx->port))
			return 0;
		ctx->socktype = SOCK_DGRAM;
	} else {
		free(ctx);
		return NULL;
	}

	ctx->url = tracker;
	ctx->sock = -1;

	return ctx;
}

void
bttc_ctx_free(struct bttc_ctx *ctx)
{

	if (ctx == NULL)
		return;

	if (ctx->sock != -1)
		(void)close(ctx->sock);
	free(ctx->host);
	free(ctx->port);
	free(ctx);
}

const char *
bttc_get_tracker(const struct bttc_ctx *ctx)
{
	return ctx->url;
}

int
bttc_scrape(struct bttc_ctx *ctx, struct btt_scrape_stats *stats,
    const struct btih *btih, size_t btihlen, const char **cause)
{

	*cause = NULL;
	if (ctx->sock == -1) {
		ctx->sock = tracker_dial(ctx->host, ctx->port, ctx->socktype,
		    cause);
		if (ctx->sock == -1)
			return 0;
	}

	if (!udpc_action_connect(ctx->sock, &ctx->cid)) {
		*cause = "failed connection handshake";
		return 0;
	}

	if (!udpc_action_scrape(ctx->sock, ctx->cid, stats, btih, btihlen)) {
		*cause = "failed scrape";
		return 0;
	}

	return 1;
}
