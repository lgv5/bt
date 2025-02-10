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

#include <ctype.h>
#include <string.h>

#include "bt.h"


static inline unsigned int	xdigittonum(char c);


static inline unsigned int
xdigittonum(char c)
{
	return c >= 'a' ? c - 'a' + 10 : c >= 'A' ? c - 'A' + 10 : c - '0';
}

int
btih_parse(struct btih *btih, const char *s)
{
	const unsigned char	*us = s;
	struct btih		 h;
	size_t			 i;

	if (strlen(s) != 2 * BTIH_LEN)
		return 0;

	for (i = 0; i < BTIH_LEN; i++) {
		if (!isxdigit(us[2 * i]) || !isxdigit(us[2 * i + 1]))
			return 0;
		h.hash[i] = (xdigittonum(s[2 * i]) << 4) |
		    xdigittonum(s[2 * i + 1]);
	}
	memcpy(btih, &h, sizeof(h));

	return 1;
}
