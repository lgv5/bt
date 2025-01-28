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
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <vis.h>

#include "bcode.h"


#define MIN(a, b)	((a) < (b) ? (a) : (b))

#define GROWTH_FACTOR	16


enum bcode_type {
	BCODE_UNASSIGNED,
	BCODE_STRING,
	BCODE_INTEGER,
	BCODE_LIST,
	BCODE_DICTIONARY,
};

struct bcode_string {
	size_t	 len;
	void	*data;
};

struct bcode_list {
	size_t		 sz;
	size_t		 cap;
	struct bcode	*elems;
};

struct bcode_dictionary {
	size_t		 sz;
	size_t		 cap;
	struct bcode_kv	*elems;
};

struct bcode {
	enum bcode_type	type;
	union {
		struct bcode_string	s;
		int64_t			i;
		struct bcode_list	l;
		struct bcode_dictionary	d;
	}		value;
};

/*
 * This struct is needed because the value isn't a pointer; inlining it in
 * bcode_dictionary leads to a compiler error because of the use of an
 * undeclared type.
 */
struct bcode_kv {
	struct bcode_string	k;
	struct bcode		v;
};


static int	kv_cmp(const void *, const void *);
static int	grow_list(struct bcode_list *);
static int	grow_dictionary(struct bcode_dictionary *);
static size_t	parse_string(struct bcode_string *, const uint8_t *, size_t);
static size_t	parse_integer(int64_t *, const uint8_t *, size_t);
static size_t	parse_list(struct bcode_list *, const uint8_t *, size_t);
static size_t	parse_dictionary(struct bcode_dictionary *, const uint8_t *,
		    size_t);
static size_t	parse_internal(struct bcode *, const uint8_t *, size_t);


static int
kv_cmp(const void *ap, const void *bp)
{
	const struct bcode_kv	*a = ap, *b = bp;
	size_t			 min;
	int			 r;

	min = MIN(a->k.len, b->k.len);
	r = memcmp(a->k.data, b->k.data, min);

	if (r != 0)
		return r;

	return a->k.len < b->k.len ? -1 : a->k.len > b->k.len ? 1 : 0;
}

static int
grow_list(struct bcode_list *l)
{
	void	*p;
	size_t	 newcap;

	if (l->sz < l->cap)
		return 1;
	if (l->cap > SIZE_MAX - GROWTH_FACTOR)
		return 0;
	newcap = l->cap + GROWTH_FACTOR;

	p = recallocarray(l->elems, l->cap, newcap, sizeof(*l->elems));
	if (p == NULL)
		return 0;
	l->elems = p;
	l->cap = newcap;

	return 1;
}

static int
grow_dictionary(struct bcode_dictionary *d)
{
	void	*p;
	size_t	 newcap;

	if (d->sz < d->cap)
		return 1;
	if (d->cap > SIZE_MAX - GROWTH_FACTOR)
		return 0;
	newcap = d->cap + GROWTH_FACTOR;

	p = recallocarray(d->elems, d->cap, newcap, sizeof(*d->elems));
	if (p == NULL)
		return 0;
	d->elems = p;
	d->cap = newcap;

	return 1;
}

static size_t
parse_string(struct bcode_string *s, const uint8_t *dp, size_t sz)
{
	const char	*begin;
	char		*end;
	size_t		 consumed = 0;
	uintmax_t	 umax;

	/* Shortest string is "0:". */
	if (sz < 2)
		return 0;

	/*
	 * dp might be a binary string, so it isn't safe to blindly call
	 * strtoumax.
	 */

	begin = dp;

	/* No leading zeros allowed. */
	if (*dp == '0' && sz != 2)
		return 0;

	while (sz > 0 && isdigit(*dp)) {
		sz--;
		dp++;
		consumed++;
	}
	if (sz == 0)
		return 0;

	errno = 0;
	umax = strtoumax(begin, &end, 10);
	if (begin == end)
		return 0;
	if (errno == ERANGE && umax == UINTMAX_MAX)
		return 0;
	if (umax > SIZE_MAX)
		return 0;
	if (*end != ':')
		return 0;

	sz--;
	dp++;
	consumed++;

	if ((size_t)umax > sz)
		return 0;

	if (umax > 0) {
		s->data = malloc(umax);
		if (s->data == NULL)
			return 0;
		memcpy(s->data, dp, umax);
		s->len = umax;
	} else {
		s->data = NULL;
		s->len = 0;
	}

	consumed += s->len;

	return consumed;
}

static size_t
parse_integer(int64_t *i, const uint8_t *dp, size_t sz)
{
	const char	*begin;
	char		*end;
	size_t		 consumed = 0;
	intmax_t	 imax;

	/* Shortest integer is "i0e". */
	if (sz < 3)
		return 0;

	if (*dp != 'i')
		return 0;
	sz--;
	dp++;
	consumed++;

	/*
	 * dp might be a binary string, so it isn't safe to blindly call
	 * strtoimax.
	 */

	begin = dp;

	/* No negative zeros allowed. */
	if (*dp == '-') {
		sz--;
		dp++;
		consumed++;
		if (*dp == '0')
			return 0;
	}

	/* No leading zeros allowed. */
	if (*dp == '0' && sz != 2)
		return 0;

	while (sz > 0 && isdigit(*dp)) {
		sz--;
		dp++;
		consumed++;
	}
	if (sz == 0)
		return 0;

	errno = 0;
	imax = strtoimax(begin, &end, 10);
	if (begin == end)
		return 0;
	if (errno == ERANGE && (imax == INTMAX_MAX || imax == INTMAX_MIN))
		return 0;
	if (imax > INT64_MAX || imax < INT64_MIN)
		return 0;

	if (*end != 'e')
		return 0;
	consumed++;

	*i = imax;

	return consumed;
}

static size_t
parse_list(struct bcode_list *l, const uint8_t *dp, size_t sz)
{
	size_t	n, consumed = 0;

	/* Shortest list is "le". */
	if (sz < 2)
		return 0;

	if (*dp != 'l')
		return 0;
	sz--;
	dp++;
	consumed++;

	while (*dp != 'e' && sz > 0) {
		grow_list(l);

		n = parse_internal(&l->elems[l->sz], dp, sz);
		if (n == 0)
			return 0;
		sz -= n;
		dp += n;
		consumed += n;

		l->sz++;
	}

	if (*dp != 'e')
		return 0;
	consumed++;

	return consumed;
}

static size_t
parse_dictionary(struct bcode_dictionary *d, const uint8_t *dp, size_t sz)
{
	size_t	n, consumed = 0;

	/* Shortest dictionary is "de". */
	if (sz < 2)
		return 0;

	if (*dp != 'd')
		return 0;
	sz--;
	dp++;
	consumed++;

	while (*dp != 'e' && sz > 0) {
		grow_dictionary(d);

		n = parse_string(&d->elems[d->sz].k, dp, sz);
		if (n == 0)
			return 0;
		sz -= n;
		dp += n;
		consumed += n;

		n = parse_internal(&d->elems[d->sz].v, dp, sz);
		if (n == 0)
			return 0;
		sz -= n;
		dp += n;
		consumed += n;

		d->sz++;
	}

	if (*dp != 'e')
		return 0;
	consumed++;

	return consumed;
}

static size_t
parse_internal(struct bcode *bcode, const uint8_t *dp, size_t sz)
{
	size_t	n;

	switch (*dp) {
	case 'i':
		n = parse_integer(&bcode->value.i, dp, sz);
		if (n > 0)
			bcode->type = BCODE_INTEGER;
		break;
	case 'l':
		n = parse_list(&bcode->value.l, dp, sz);
		if (n > 0)
			bcode->type = BCODE_LIST;
		break;
	case 'd':
		n = parse_dictionary(&bcode->value.d, dp, sz);
		if (n > 0) {
			struct bcode_dictionary	d = bcode->value.d;

			qsort(d.elems, d.sz, sizeof(*d.elems), &kv_cmp);
			bcode->type = BCODE_DICTIONARY;
		}
		break;
	default:
		n = parse_string(&bcode->value.s, dp, sz);
		if (n > 0)
			bcode->type = BCODE_STRING;
		break;
	}

	return n;
}

struct bcode *
bcode_parse(const uint8_t *dp, size_t sz)
{
	struct bcode	*bcode;

	bcode = calloc(1, sizeof(*bcode));
	if (bcode == NULL)
		return NULL;

	if (parse_internal(bcode, dp, sz) != sz) {
		bcode_free(bcode);
		return NULL;
	}

	return bcode;
}

void
bcode_free(struct bcode *bcode)
{
	if (bcode == NULL)
		return;

	free(bcode);
}

static void
print_string(const struct bcode_string *s, FILE *fp)
{
	char	buf[5];
	size_t	i;
	int	nextc;

	fputc('"', fp);
	for (i = 0; i < s->len; i++) {
		if (i + 1 == s->len)
			nextc = '"';
		else
			nextc = ((unsigned char *)s->data)[i + 1];
		vis(buf, ((unsigned char *)s->data)[i],
		    VIS_TAB|VIS_NL|VIS_CSTYLE, nextc);
		fputs(buf, fp);
	}
	fputc('"', fp);
}

static void
print_internal(const struct bcode *bcode, FILE *fp, size_t lvl)
{
	size_t	i, k;

	switch (bcode->type) {
	case BCODE_STRING:
		print_string(&bcode->value.s, fp);
		break;
	case BCODE_INTEGER:
		fprintf(fp, "%" PRIi64, bcode->value.i);
		break;
	case BCODE_LIST: {
		struct bcode_list	l = bcode->value.l;

		fputs("[\n", fp);
		lvl++;
		for (i = 0; i < l.sz; i++) {
			for (k = 0; k < lvl; k++)
				fputs("  ", fp);
			print_internal(&l.elems[i], fp, lvl);
			fputs(",\n", fp);
		}
		lvl--;
		for (k = 0; k < lvl; k++)
			fputs("  ", fp);
		fputc(']', fp);

		break;
	}
	case BCODE_DICTIONARY: {
		struct bcode_dictionary	d = bcode->value.d;

		fputs("{\n", fp);
		lvl++;
		for (i = 0; i < d.sz; i++) {
			for (k = 0; k < lvl; k++)
				fputs("  ", fp);
			print_string(&d.elems[i].k, fp);
			fputs(": ", fp);
			print_internal(&d.elems[i].v, fp, lvl);
			fputs(",\n", fp);
		}
		lvl--;
		for (k = 0; k < lvl; k++)
			fputs("  ", fp);
		fputc('}', fp);

		break;
	}
	default:
		/* Do nothing. */
		break;
	}
}

void
bcode_dump(const struct bcode *bcode, FILE *fp)
{
	print_internal(bcode, fp, 0);
	fputc('\n', fp);
}
