/*
** xdmcp.c
**
** Copyright (c) 2005 Peter Eriksson <pen@lysator.liu.se>
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/wait.h>

#include "xdmcp.h"

#ifndef XAUTH
#define XAUTH "/usr/openwin/bin/xauth"
#endif

extern char version[];

int debug = 0;
int verbose = 0;
int keepalive = 0;

XDMCP_STATE state = XDMCP_STATE_START;
XDMCP_STATE newstate = XDMCP_STATE_START;
int statecount = 0;
int timeout = 1;

char *hostname, *status, *auname, *azname;
BYTE *audata, *azdata;
unsigned long session;
size_t audlen, azdlen;
int running;

char *authfile = NULL;
char *authprog = XAUTH;

char *display = "localhost:0";



unsigned int
card16_to_int(BYTE ** p)
{
    unsigned int v = (*p)[0] * 256 + (*p)[1];
    *p += 2;

    return v;
}

unsigned int
card32_to_int(BYTE ** p)
{
    unsigned int v = (*p)[0] * 256 * 256 * 256 + (*p)[1] * 256 * 256 + (*p)[2] * 256 + (*p)[3];
    *p += 4;

    return v;
}

int
int_to_card16(BYTE ** p, unsigned int v)
{
    if (v > 0xFFFF)
	return -1;

    (*p)[0] = (v >> 8) & 0xFF;
    (*p)[1] = (v & 0xFF);

    *p += 2;

    return v;
}

int
int_to_card32(BYTE ** p, unsigned long v)
{
    (*p)[0] = (v >> 24) & 0xFF;
    (*p)[1] = (v >> 16) & 0xFF;
    (*p)[2] = (v >> 8) & 0xFF;
    (*p)[3] = (v & 0xFF);

    *p += 4;

    return v;
}

int
str_to_array8(BYTE ** p, char *str)
{
    int len;

    if (str)
	len = strlen(str);
    else
	len = 0;

    int_to_card16(p, len);
    if (len > 0) {
	memcpy(*p, str, len);
	(*p) += len;
    }

    return len;
}

int
arr_to_array8(BYTE ** p, void *buf, size_t len)
{
    int_to_card16(p, len);
    memcpy(*p, buf, len);
    (*p) += len;

    return len;
}


char *
array8_to_str(BYTE ** p)
{
    char *str;
    int len = card16_to_int(p);

    str = malloc(len + 1);
    memcpy(str, (*p), len);
    str[len] = '\0';

    *p += len;

    return str;
}


void *
array8_to_arr(BYTE ** p, size_t * len)
{
    char *buf = NULL;

    *len = card16_to_int(p);

    if (*len > 0) {
	buf = malloc(*len);
	memcpy(buf, (*p), *len);
	*p += *len;
    }

    return buf;
}

int
xdmcp_send(int fd, int op, void *buf, size_t len)
{
    BYTE msgbuf[8192], *cp;
    int rc;


    if (debug > 1)
	fprintf(stderr, "xdmcp_send: fd=%d, op=%d, len=%ld\n", fd, op, (long int) len);

    if (len + 6 > sizeof(msgbuf))
	return -1;

    cp = msgbuf;
    int_to_card16(&cp, 1);
    int_to_card16(&cp, op);
    int_to_card16(&cp, len);
    memcpy(cp, buf, len);

    while ((rc = send(fd, msgbuf, len + 6, 0)) < 0 && errno == EINTR);

    return rc;
}


int
xdmcp_recv(int fd, int *op, void *buf, size_t len, int timeout)
{
    BYTE msgbuf[8192], *cp;
    int rc;
    ssize_t rlen;
    size_t mlen;
    struct pollfd fds[1];


    if (debug > 1)
	fprintf(stderr, "xdmcp_recv: fd=%d, maxlen=%ld\n", fd, (long int) len);

    fds[0].fd = fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    while ((rc = poll(fds, 1, timeout * 1000)) < 0 && errno == EINTR);

    if (rc == 0)
	return 0;

    while ((rlen = recv(fd, msgbuf, sizeof(msgbuf), 0)) < 0 && errno == EINTR);

    if (debug > 2)
	fprintf(stderr, "\trecv: fd=%d, rlen=%ld, errno=%d\n", fd, (long int) rlen, errno);

    if (rlen < 0)
	return -1;

    if (rlen < 6)
	return -2;

    cp = msgbuf;

    if (card16_to_int(&cp) != 1)
	return -3;

    *op = card16_to_int(&cp);
    if (*op >= XDMCP_OP_LAST)
	return -4;

    mlen = card16_to_int(&cp);
    if (mlen + 6 != rlen)
	return -5;

    if (mlen > len)
	return -6;

    memcpy(buf, cp, mlen);

    if (debug > 1)
	fprintf(stderr, "xdmcp_recv: fd=%d, op=%u, len=%ld\n", fd, *op, (long int) mlen);

    return mlen;
}



char *
data_to_str(BYTE * data, size_t len)
{
    char *buf = malloc(3 * len + 10);
    char *cp;

    cp = buf;
    while (len-- > 0) {
	sprintf(cp, "%02x", *data);
	++data;
	cp += 2;
    }
    *cp = '\0';

    return buf;
}


int
get_addr(char *str, unsigned long *ip, size_t * alen)
{
    struct hostent *hep;
    unsigned long tip;


    hep = gethostbyname(str);
    if (hep && hep->h_addr_list && hep->h_addr_list[0]) {
	tip = *(unsigned long *) (hep->h_addr_list[0]);
	*ip = ntohl(tip);
	*alen = sizeof(unsigned long);
	return 1;
    }

    return inet_pton(AF_INET, str, ip);
}


int
xdmcp_query(int fd, int op, int ac, char **av)
{
    BYTE buf[8192], *cp;
    int i;


    if (debug) {
	fprintf(stderr, "xdmcp_query: fd=%d, op=%d, ac=%d:\n", fd, op, ac);
	for (i = 0; i < ac; i++)
	    fprintf(stderr, "\t%d: %s\n", i, av[i]);
    }

    cp = buf;
    *cp++ = ac;

    for (i = 0; i < ac; i++)
	str_to_array8(&cp, av[i]);

    return xdmcp_send(fd, op, buf, cp - buf);

}


int
xdmcp_request(int fd,
	      int dpy,
	      int ctc,
	      short *ctv,
	      int cac,
	      size_t * cal,
	      void **cav, char *authname, char *authdata, int anc, char **anv, char *mdid)
{
    BYTE buf[8192], *cp;
    int i;


    if (debug) {
	fprintf(stderr,
		"xdmcp_request: fd=%d, dpy=%d, ctc=%d, cac=%d, authname=%s, authdata=%s, anc=%d, mdid=%s:\n",
		fd, dpy, ctc, cac,
		authname ? authname : "<null>", authdata ? authdata : "<null>", anc, mdid);

	for (i = 0; i < anc; i++)
	    fprintf(stderr, "\tAN %d: %s\n", i, anv[i]);
    }

    cp = buf;
    int_to_card16(&cp, dpy);
    *cp++ = ctc;
    for (i = 0; i < ctc; i++)
	int_to_card16(&cp, ctv[i]);
    *cp++ = cac;
    for (i = 0; i < cac; i++)
	arr_to_array8(&cp, cav[i], cal[i]);

    str_to_array8(&cp, authname);
    str_to_array8(&cp, authdata);

    *cp++ = anc;
    for (i = 0; i < anc; i++)
	str_to_array8(&cp, anv[i]);

    str_to_array8(&cp, mdid);

    return xdmcp_send(fd, XDMCP_OP_REQUEST, buf, cp - buf);

}


int
xdmcp_manage(int fd, unsigned long session, int dpy, char *dpyclass)
{
    BYTE buf[8192], *cp;


    if (debug)
	fprintf(stderr, "xdmcp_manage: fd=%d, session=%lu, dpy=%d, dpyclass=%s\n",
		fd, session, dpy, dpyclass);

    cp = buf;

    int_to_card32(&cp, session);
    int_to_card16(&cp, dpy);
    str_to_array8(&cp, dpyclass);

    return xdmcp_send(fd, XDMCP_OP_MANAGE, buf, cp - buf);
}




int
xdmcp_keepalive(int fd, int dpy, unsigned long session)
{
    BYTE buf[8192], *cp;


    if (debug)
	fprintf(stderr, "xdmcp_keepalive: fd=%d, dpy=%d, session=%lu\n", fd, dpy, session);

    cp = buf;

    int_to_card16(&cp, dpy);
    int_to_card32(&cp, session);

    return xdmcp_send(fd, XDMCP_OP_KEEPALIVE, buf, cp - buf);
}



int
xdmcp_dispatch(int fd, int timeout)
{
    BYTE buf[8192], *cp;
    int rc, op = 0;
    unsigned long sid;


    if (debug > 1)
	fprintf(stderr, "xdmcp_dispatch: fd=%d\n", fd);

    rc = xdmcp_recv(fd, &op, buf, sizeof(buf), timeout);
    if (rc < 0) {
	if (debug > 1)
	    fprintf(stderr, "xdmcp_recv: rc=%d\n", rc);
	return -1;
    }

    if (rc == 0)
	return 0;

    if (debug > 2)
	fprintf(stderr, "xdmcp_dispatch: Got packet with OP=%d\n", op);

    cp = buf;
    switch (op) {
    case XDMCP_OP_WILLING:
	auname = array8_to_str(&cp);
	hostname = array8_to_str(&cp);
	status = array8_to_str(&cp);

	if (debug)
	    fprintf(stderr, "xdmcp_dispatch: op=WILLING, auname=%s, hostname=%s, status=%s\n",
		    auname, hostname, status);

	if (state == XDMCP_STATE_COLLECT_QUERY)
	    newstate = XDMCP_STATE_START_CONNECTION;
	return op;


    case XDMCP_OP_UNWILLING:
	hostname = array8_to_str(&cp);
	status = array8_to_str(&cp);

	if (debug)
	    fprintf(stderr, "xdmcp_dispatch: op=UNWILLING, hostname=%s, status=%s\n",
		    hostname, status);

	if (state == XDMCP_STATE_COLLECT_QUERY)
	    newstate = XDMCP_STATE_STOP_CONNECTION;
	return op;


    case XDMCP_OP_ACCEPT:
	session = card32_to_int(&cp);
	auname = array8_to_str(&cp);
	audata = array8_to_arr(&cp, &audlen);
	azname = array8_to_str(&cp);
	azdata = array8_to_arr(&cp, &azdlen);

	if (debug)
	    fprintf(stderr,
		    "xdmcp_dispatch: op=ACCEPT, session=%lu, auname=%s, audata=%s, azname=%s, azdata=%s\n",
		    session, auname, data_to_str(audata, audlen), azname, data_to_str(azdata,
										      azdlen));

	if (state == XDMCP_STATE_AWAIT_REQUEST_RESPONSE) {
	    if (authprog && authfile) {
		int pid = fork();
		if (!pid) {
		    /* In child */
		    execl(authprog, authprog, "-f", authfile,
			  "add", display, "MIT-MAGIC-COOKIE-1", data_to_str(azdata, azdlen), NULL);

		    _exit(1);
		}
		else {
		    int sv;
		    while (waitpid(pid, &sv, 0) < 0 && errno == EINTR);
		}
	    }
	    newstate = XDMCP_STATE_MANAGE;
	}
	return op;


    case XDMCP_OP_DECLINE:
	status = array8_to_str(&cp);
	auname = array8_to_str(&cp);
	audata = array8_to_arr(&cp, &audlen);

	if (debug)
	    fprintf(stderr, "xdmcp_dispatch: op=DECLINE, auname=%s, status=%s\n", auname, status);

	if (state == XDMCP_STATE_AWAIT_REQUEST_RESPONSE)
	    newstate = XDMCP_STATE_STOP_CONNECTION;
	return op;


    case XDMCP_OP_REFUSE:
	sid = card32_to_int(&cp);

	if (debug)
	    fprintf(stderr, "xdmcp_dispatch: op=REFUSE, session=%lu (saved session=%lu)\n",
		    sid, session);

	if (state == XDMCP_STATE_AWAIT_MANAGE_RESPONSE) {
	    if (session == sid)
		newstate = XDMCP_STATE_START_CONNECTION;	/* XXX: Hmmm. Is this really ideal? */

	}
	return op;


    case XDMCP_OP_FAILED:
	sid = card32_to_int(&cp);

	if (debug)
	    fprintf(stderr,
		    "xdmcp_dispatch: op=FAILED, session=%lu, status=%s (saved session=%lu)\n", sid,
		    status, session);

	if (state == XDMCP_STATE_AWAIT_MANAGE_RESPONSE || state == XDMCP_STATE_AWAIT_ALIVE) {
	    if (session == sid) {
		status = array8_to_str(&cp);
		newstate = XDMCP_STATE_STOP_CONNECTION;

	    }
	}
	return op;


    case XDMCP_OP_ALIVE:
	running = *cp++;
	sid = card32_to_int(&cp);

	if (debug)
	    fprintf(stderr, "xdmcp_dispatch: op=ALIVE, session=%lu, running=%d (session=%lu)\n",
		    sid, running, session);

	if (sid == session || 1) {
	    if (!running && keepalive > 1)
		newstate = XDMCP_STATE_STOP_CONNECTION;
	    else
		newstate = XDMCP_STATE_AWAIT_MANAGE_RESPONSE;
	}
	return op;
    }

    return -2;
}


int
main(int argc, char *argv[])
{
    int i, fd, rc;
    char *cp;

    char *xdmhost = "localhost";
    int port = 177;

    char *dpyhost;
    int dpy = 0;
    char *dpyclass = "";

    unsigned long addr;
    size_t alen;
    struct sockaddr_in sin;

    char *authname, *authdata;



    short ctv[2];
    void *cav[2];
    size_t cal[2];
    char *anv[3];


    display = getenv("DISPLAY");
    authfile = getenv("XAUTHORITY");

    for (i = 1; i < argc && argv[i][0] == '-'; ++i)
	switch (argv[i][1]) {
	case 'k':
	    if (sscanf(argv[i] + 2, "%u", &keepalive) != 1)
		++debug;
	    break;

	case 'd':
	    if (sscanf(argv[i] + 2, "%u", &debug) != 1)
		++debug;
	    break;

	case 'v':
	    if (sscanf(argv[i] + 2, "%u", &verbose) != 1)
		++verbose;
	    break;

	case 'D':
	    display = strdup(argv[i] + 2);
	    break;

	case 'A':
	    authfile = strdup(argv[i] + 2);
	    break;

	case 'a':
	    authprog = strdup(argv[i] + 2);
	    break;

	case 'h':
	    printf
		("Usage: %s [-h] [-V] [-d[<level>]] [-v[<level>]] [-D<display>] [-a<authfile>] [-A<xauthprog>]\n",
		 argv[0]);
	    exit(0);

	case 'V':
	    printf("[xdmcp, version %s - Copyright (c) 2005 Peter Eriksson <pen@lysator.liu.se>]\n",
		   version);
	    exit(0);

	default:
	    fprintf(stderr, "%s: invalid switch: %s\n", argv[0], argv[i]);
	    exit(1);
	}

    if (!display) {
	fprintf(stderr, "%s: need a valid display\n", argv[0]);
	exit(1);
    }

    dpyhost = strdup(display);
    cp = strchr(dpyhost, ':');
    if (cp) {
	*cp++ = '\0';
	if (sscanf(cp, "%u", &dpy) != 1) {
	    fprintf(stderr, "%s: invalid display: %s\n", argv[0], display);
	    exit(1);
	}
    }
    else {
	fprintf(stderr, "%s: invalid display: %s\n", argv[0], display);
	exit(1);
    }

    if (!*dpyhost) {
	char buf[1024];
	if (gethostname(buf, sizeof(buf) - 1) != 0) {
	    fprintf(stderr, "%s: unable to get our hostname: %s\n", argv[0], strerror(errno));
	    exit(1);
	}

	dpyhost = strdup(buf);
    }

    if (i < argc)
	xdmhost = argv[i++];

    if (get_addr(xdmhost, &addr, &alen) != 1) {
	fprintf(stderr, "%s: invalid xdm hostname: %s\n", argv[0], xdmhost);
	exit(1);
    }

    if (i < argc)
	if (sscanf(argv[i], "%u", &port) != 1) {
	    fprintf(stderr, "%s: invalid port: %s\n", argv[0], argv[i]);
	    exit(1);
	}

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
	fprintf(stderr, "%s: socket() failed: %s\n", argv[0], strerror(errno));
	exit(1);
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = htonl(addr);

    while ((rc = connect(fd, (struct sockaddr *) &sin, sizeof(sin))) < 0 && errno == EINTR);

    if (get_addr(dpyhost, &addr, &cal[0]) != 1) {
	fprintf(stderr, "%s: invalid server hostname: %s\n", argv[0], dpyhost);
	exit(1);
    }

    if (debug > 1) {
	fprintf(stderr, "DISPLAY=%s\n", display);
	fprintf(stderr, "XAUTHORITY=%s\n", authfile);
    }

    state = XDMCP_STATE_START;
    newstate = 0;

    if (verbose)
	printf("XDMCP: %s: Initiating new session for display %s.\n", xdmhost, display);

    while (state != XDMCP_STATE_STOP_CONNECTION) {
	switch (state) {
	case XDMCP_STATE_START:
#if 0
	    anv[0] = "Gurka";
	    anv[1] = "Tomat";
#endif
	    rc = xdmcp_query(fd, XDMCP_OP_QUERY, 0, anv);
	    if (rc < 0)
		goto End;

	    newstate = XDMCP_STATE_COLLECT_QUERY;
	    break;

	case XDMCP_STATE_START_CONNECTION:
	    ctv[0] = 0x0000;
	    cav[0] = (void *) &addr;

	    anv[0] = "MIT-MAGIC-COOKIE-1";
#if 0
	    anv[1] = "SUN-DES-1";
#endif

	    authname = NULL;
	    authdata = NULL;

	    if (verbose)
		printf("XDMCP: %s: Willing to host session for display %s, requesting session.\n",
		       xdmhost, display);

	    rc = xdmcp_request(fd, dpy, 1, ctv, 1, cal, cav, authname, authdata, 1, anv,
			       "xdmcp client");
	    if (rc < 0)
		goto End;

	    newstate = XDMCP_STATE_AWAIT_REQUEST_RESPONSE;
	    break;

	case XDMCP_STATE_MANAGE:
	    if (verbose)
		printf("XDMCP: %s: Session accepted, requesting server to manage display %s.\n",
		       xdmhost, display);

	    rc = xdmcp_manage(fd, session, dpy, dpyclass);
	    if (rc < 0)
		goto End;

	    newstate = XDMCP_STATE_AWAIT_MANAGE_RESPONSE;
	    break;

	case XDMCP_STATE_KEEP_ALIVE:
	    rc = xdmcp_keepalive(fd, dpy, session);
	    if (rc < 0)
		goto End;

	    newstate = XDMCP_STATE_AWAIT_ALIVE;
	    break;

	default:
	    break;
	}

	if (state == XDMCP_STATE_AWAIT_MANAGE_RESPONSE && statecount >= 3 && keepalive > 0) {
	    newstate = XDMCP_STATE_KEEP_ALIVE;
	}

	if (newstate != state) {
	    state = newstate;
	    timeout = 1;
	    statecount = 0;
	}
	else
	    statecount++;

	rc = xdmcp_dispatch(fd, timeout);
	if (rc < 0)
	    goto End;

	if (timeout < 8)
	    timeout <<= 1;
    }

    if (verbose)
	fprintf(stderr, "XDMCP: %s: Session closed for display %s\n", xdmhost, display);

    exit(0);

  End:
    fprintf(stderr, "%s: Failed at state %d with code %d\n", argv[0], state, rc);
    exit(1);
}
