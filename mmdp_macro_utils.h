#define MMDP_EMPTY


#define _COUNT_0() \
	macro_count++;
#define _COUNT_1(_) \
	macro_count++;
#define _COUNT_2(_, __) \
	macro_count++;
#define _COUNT_3(_, __, ___) \
	macro_count++;
#define _COUNT_4(_, __, ___, ____) \
	macro_count++;
#define _COUNT_5(_, __, ___, ____, _____) \
	macro_count++;
#define _COUNT_6(_, __, ___, ____, _____, ______) \
	macro_count++;
#define _COUNT_7(_, __, ___, ____, _____, ______, _______) \
	macro_count++;
#define _COUNT_8(_, __, ___, ____, _____, ______, _______, ________) \
	macro_count++;

/* the function that calls this marco must have variable macro_count declared */
#define COUNT_1(what, arg_count) \
	macro_count=0; \
	what(_COUNT_##arg_count)

/* the function that calls this marco must have variable macro_count declared */
#define COUNT_2(what, arg_count, arg1) \
	macro_count=0; \
	what(_COUNT_##arg_count, arg1 )

/* return 0 on false, 1 on true */
#define IS_FLAG_ACTIVE(X, FLAG) \
	(((X) & (FLAG)) != 0 ? 1:0)

#define MAX(a, b) ((a) > (b) ? (a) : (b))
