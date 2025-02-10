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

#include <stdio.h>
#include <stdint.h>


/*
 * CONSTANTS
 */


#define BTIH_LEN	20


/*
 * STRUCTS
 */


struct bcode;

struct bttc_ctx;

struct btt_scrape_stats {
	uint32_t	seeders;
	uint32_t	completed;
	uint32_t	leechers;
};

struct btih {
	uint8_t	hash[BTIH_LEN];
} __packed;


/*
 * PROTOTYPES
 */


/* bencode */

struct bcode	*bcode_parse(const uint8_t *, size_t);
void		 bcode_free(struct bcode *);
void		 bcode_print(FILE *, const struct bcode *);


/* Tracker client */

struct bttc_ctx	*bttc_ctx_new(const char *);
void		 bttc_ctx_free(struct bttc_ctx *);
const char	*bttc_get_tracker(const struct bttc_ctx *);
int		 bttc_announce(struct bttc_ctx *, const uint8_t *,
		    const char **);
int		 bttc_scrape(struct bttc_ctx *, struct btt_scrape_stats *,
		    const struct btih *, size_t, const char **);


/* Utilities */

int	btih_parse(struct btih *, const char *);
