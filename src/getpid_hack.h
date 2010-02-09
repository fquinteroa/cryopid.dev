#ifndef _GETPID_HACK_
#define _GETPID_HACK_

/* getpid_hack_w */
extern int libc_hack_fetch(const char *name, char **signature);
extern void write_chunk_getpid(void *fptr, struct cp_getpid *data);

/* getpid_hack_r */
extern void read_chunk_getpid(void *fptr, int action);

#endif /* _GETPID_HACK_ */
