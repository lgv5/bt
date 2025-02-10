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

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bt.h"


#define GROWTH_FACTOR	1024


static void	usage(void);
static int	do_bcode(int, char *[]);
static int	do_tracker(int, char *[]);


static void
usage(void)
{
	const char	*p;

	p = getprogname();
	fprintf(stderr, "Usage:\n"
	    "\t%s -b [torrent-file]\n"
	    "\t%s -t tracker\n",
	    p, p);
	exit(1);
}

static int
do_bcode(int argc, char *argv[])
{
	struct bcode	*bcode;
	uint8_t		*buf, *p;
	FILE		*fp;
	size_t		 n, bufcap, bufsz;

	if (argc > 1)
		usage();

	if (argc == 1) {
		fp = fopen(argv[0], "r");
		if (fp == NULL)
			err(1, "fopen");
	} else
		fp = stdin;

	buf = malloc(GROWTH_FACTOR);
	if (buf == NULL)
		err(1, "out of memory");
	bufcap = GROWTH_FACTOR;
	bufsz = 0;
	for (;;) {
		if (bufsz > bufcap - GROWTH_FACTOR) {
			if (bufcap > SIZE_MAX / 2)
				errx(1, "out of memory");
			p = reallocarray(buf, bufcap * 2, 1);
			if (p == NULL)
				err(1, "out of memory");
			buf = p;
			bufcap *= 2;
		}

		n = fread(&buf[bufsz], 1, GROWTH_FACTOR, fp);
		if (ferror(fp))
			err(1, "fread");

		bufsz += n;
		if (feof(fp))
			break;
	}

	bcode = bcode_parse(buf, bufsz);
	if (bcode == NULL)
		errx(1, "bcode_parse: parse error");
	bcode_print(stdout, bcode);
	bcode_free(bcode);

	free(buf);
	if (fp != stdin)
		(void)fclose(fp);

	return 0;
}

static int
do_tracker(int argc, char *argv[])
{
	struct bttc_ctx		*ctx;
	const char		*errstr;
	struct btih		*btih;
	struct btt_scrape_stats	*stats;
	int			 i;

	if (argc < 2)
		usage();

	ctx = bttc_ctx_new(argv[0]);
	if (ctx == NULL)
		err(1, "out of memory");

	argc--;
	argv++;

	btih = reallocarray(NULL, argc, sizeof(*btih));
	stats = reallocarray(NULL, argc, sizeof(*stats));
	if (btih == NULL || stats == NULL)
		err(1, "out of memory");

	for (i = 0; i < argc; i++)
		if (!btih_parse(&btih[i], argv[i]))
			errx(1, "invalid info hash: %s", argv[i]);

	errno = 0;
	if (!bttc_scrape(ctx, stats, btih, argc, &errstr)) {
		if (errno)
			err(1, "announce failed: %s: %s",
			    bttc_get_tracker(ctx), errstr);
		else
			errx(1, "announce failed: %s: %s",
			    bttc_get_tracker(ctx), errstr);
	}

	for (i = 0; i < argc; i++)
		printf("%s\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\n",
		    argv[i], stats[i].seeders, stats[i].completed,
		    stats[i].leechers);
	free(btih);
	free(stats);

	return 0;
}

int
main(int argc, char *argv[])
{
	int	ch, bflag, tflag;

	bflag = tflag = 0;
	while ((ch = getopt(argc, argv, "bt")) != -1) {
		switch (ch) {
		case 'b':
			bflag = 1;
			break;
		case 't':
			tflag = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (bflag && tflag)
		errx(1, "-b and -t are mutually exclusive");
	if (!bflag && !tflag)
		usage();
	if (bflag)
		return do_bcode(argc, argv);
	else if (tflag)
		return do_tracker(argc, argv);

	/* UNREACHABLE */
	return 1;
}
