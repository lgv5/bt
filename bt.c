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
#include <stdio.h>
#include <stdlib.h>

#include "bt.h"


#define GROWTH_FACTOR	1024


static void
usage(void)
{
	fprintf(stderr, "Usage: %s [torrent-file]\n", getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct bcode	*bcode;
	uint8_t		*buf, *p;
	FILE		*fp;
	size_t		 n, bufcap, bufsz;

	argc--;
	argv++;
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
