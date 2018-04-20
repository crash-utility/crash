/* remote.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005, 2009, 2011, 2018 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005, 2009, 2011, 2018 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "defs.h"
#include <netinet/in.h>
#include <netdb.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <elf.h>

#define FAILMSG "FAIL "
#define DONEMSG "DONE "
#define DATAMSG "DATA "

#define DATA_HDRSIZE (13)   /* strlen("XXXX ") + strlen("0131072") + NULL */

#define MAXRECVBUFSIZE (131072) 
#define READBUFSIZE    (MAXRECVBUFSIZE+DATA_HDRSIZE)

#ifdef DAEMON
/*
 *  The remote daemon.  
 */

static int daemon_init(void);
static ulong daemon_htol(char *);
static int daemon_is_elf_file(char *);
static int daemon_mount_point(char *);
static int daemon_find_booted_kernel(char *);
static char **daemon_build_searchdirs(int);
static int daemon_is_directory(char *);
static int daemon_file_readable(char *);
static int daemon_parse_line(char *, char **);
static char *daemon_clean_line(char *);
int console(char *, ...);
static void daemon_socket_options(int);
static char *no_debugging_symbols_found(char *);
static ulong daemon_filesize(int);
static int daemon_find_module(char *, char *, char *);
static int daemon_search_directory_tree(char *, char *, char *);
static int daemon_file_exists(char *, struct stat *);
static int daemon_checksum(char *, long *);
static void daemon_send(void *, int);
static int daemon_proc_version(char *);
static void handle_connection(int);

struct remote_context {
        int sock;
        int remdebug; 
        char *remdebugfile;
} remote_context = { 0, 0, "/dev/null" };

struct remote_context *rc = &remote_context;

int
main(int argc, char **argv)
{
        int c, sockfd, newsockfd, clilen;
        struct sockaddr_in serv_addr, cli_addr;
        struct hostent *hp;
        ushort tcp_port;
        char hostname[MAXHOSTNAMELEN];

	tcp_port = 0;
        optind = 0;
        while ((c = getopt(argc, argv, "vd:")) > 0) {
                switch (c)
                {
		case 'v':
			printf("%s %s\n", basename(argv[0]), 
				/* BASELEVEL_REVISION */ "(deprecated)");
			exit(0);

                case 'd':
			rc->remdebug++;
			rc->remdebugfile = optarg;
			break;
		}
	}

	console("<parent daemon %d initiated>\n", getpid());

	while (argv[optind]) {
		if (!tcp_port)
                	tcp_port = (ushort)atoi(argv[optind]); 
		optind++;
	}

	console("port: %d\n", tcp_port);

        if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
		console("gethostname failed: %s\n", strerror(errno));
                perror("gethostname");
                exit(1);
        }

	console("hostname: %s\n", hostname);

        if ((hp = gethostbyname(hostname)) == NULL) {
		console("gethostbyname failed: %s\n", hstrerror(h_errno));
                perror("gethostbyname");
                exit(1);
        }

	console("attempting daemon_init...\n");

        if (!daemon_init())
                exit(1);

	console("<daemon %d initiated>\n", getpid());

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
                exit(1);

        BZERO((char *)&serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        BCOPY(hp->h_addr, (char *)&serv_addr.sin_addr, hp->h_length);
        serv_addr.sin_port = htons(tcp_port);

        daemon_socket_options(sockfd);

        if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
		console("%d: bind failed: %s\n", getpid(), strerror(errno));
                exit(1);
	}

        if (listen(sockfd, 5) < 0) {
		console("%d: listen failed: %s\n", getpid(), strerror(errno));
                exit(1);
	}

        for (;;) {
                clilen = sizeof(cli_addr);

                if ((newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr,
                    &clilen)) < 0) {
			console("%d: accept failed: %s\n", getpid(), 
				strerror(errno));
                        exit(1);
		}

                switch (fork())
                {
                case -1: exit(1);

                case 0:  close(sockfd);
                         handle_connection(newsockfd);
                         exit(0);

                default:
                         close(newsockfd);
                         break;
                }

                close(newsockfd);
        }
}

/*
 *  This probably doesn't do much, but it might reduce the acknowledge
 *  negotiations somewhat. (?)
 */
static void
daemon_socket_options(int sockfd)
{
        int nodelay;

        if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY,
            (char *)&nodelay, sizeof(nodelay)) < 0) 
                console("TCP_NODELAY setsockopt error\n");
}

/*
 *  This is the child daemon that handles the incoming requests.
 */
#define MAX_REMOTE_FDS  (10)

static void
handle_connection(int sock)
{
	int i;
	char recvbuf[BUFSIZE];
	char savebuf[BUFSIZE];
	char sendbuf[BUFSIZE];
	char buf1[BUFSIZE];
	char readbuf[READBUFSIZE+1];
	char *file;
	FILE *tmp, *pipe;
	char *p1, *p2, *p3;
	size_t cnt;
	int fds[MAX_REMOTE_FDS];
	int mfd;
	ulong addr, total, reqsize, bufsize;
        fd_set rfds;
        int len, first, retval, done;
	struct stat sbuf;

	rc->sock = sock;

	console("< new connection >\n");

	for (i = 0; i < MAX_REMOTE_FDS; i++)
		fds[i] = -1;

	while (TRUE) {

                FD_ZERO(&rfds);
                FD_SET(sock, &rfds);
                retval = select(sock+1, &rfds, NULL, NULL, NULL);

		BZERO(sendbuf, BUFSIZE);
		BZERO(recvbuf, BUFSIZE);

		switch (read(sock, recvbuf, BUFSIZE-1))
		{
		case -1:
			console("[read returned -1]\n");
			continue;
		case 0:
			console("[read returned 0]\n");
			return;
		default:
			console("[%s]: ", recvbuf);
			break;
		}

		if (STRNEQ(recvbuf, "OPEN ")) {

			strcpy(sendbuf, recvbuf);
			p1 = strtok(recvbuf, " ");  /* OPEN */
			file = strtok(NULL, " ");   /* filename */
			
			for (i = 0; i < MAX_REMOTE_FDS; i++) {
				if (fds[i] == -1)
					break;
			}

			if (i < MAX_REMOTE_FDS) { 
	        		if ((fds[i] = open(file, O_RDWR)) < 0) {
				        if ((fds[i] = open(file, O_RDONLY)) < 0)
						strcat(sendbuf, " <FAIL>");
					else {
						sprintf(buf1, 
						    " %d O_RDONLY %ld", fds[i], 
						    daemon_filesize(fds[i]));
						strcat(sendbuf, buf1);
					}
				} else {
					sprintf(buf1, " %d O_RDWR %ld", fds[i], 
						daemon_filesize(fds[i]));
					strcat(sendbuf, buf1);
				}
			} else 
				strcat(sendbuf, " <FAIL>");

			console("[%s]\n", sendbuf);

                        daemon_send(sendbuf, strlen(sendbuf));
			continue;

                } else if (STRNEQ(recvbuf, "READ_LIVE ")) {

                        strcpy(savebuf, recvbuf);

                        p1 = strtok(recvbuf, " ");   /* READ_LIVE */
                        p1 = strtok(NULL, " ");      /* filename id */
                        p2 = strtok(NULL, " ");      /* address */
                        p3 = strtok(NULL, " ");      /* length */

                        addr = daemon_htol(p2);
                        len = atoi(p3);
                        mfd = atoi(p1);
			errno = 0;

                        BZERO(readbuf, READBUFSIZE);

                        if (lseek(mfd, addr, SEEK_SET) == -1) 
                                len = 0;        
                        else if (read(mfd, &readbuf[DATA_HDRSIZE], len) != len) 
                                len = 0;

                        if (!len) {
				sprintf(readbuf, "%s%07ld", FAILMSG, 
					(ulong)errno);
                                console("[%s]\n", readbuf);
                        } else {
				sprintf(readbuf, "%s%07ld", DONEMSG,(ulong)len);
                                console("(%ld)\n", len);
			}

                        daemon_send(readbuf, len+DATA_HDRSIZE);

                        continue;

                } else if (STRNEQ(recvbuf, "READ_NETDUMP ")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* READ_NETDUMP */
                        p2 = strtok(NULL, " ");      /* address */
                        p3 = strtok(NULL, " ");      /* length */

                        addr = daemon_htol(p2);
                        len = atoi(p3);

                        BZERO(readbuf, READBUFSIZE);
                        errno = 0;

                        if ((len = read_netdump(UNUSED,
                            &readbuf[DATA_HDRSIZE], len, UNUSED, addr)) < 0)
                                len = 0;

                        if (len) {
                                sprintf(readbuf, "%s%07ld", DONEMSG,(ulong)len);                                console("(%ld)\n", (ulong)len);
                        } else {
                                sprintf(readbuf, "%s%07ld", FAILMSG,
                                        (ulong)errno);
                                console("[%s]\n", readbuf);
                        }

                        daemon_send(readbuf, len+DATA_HDRSIZE);
                        continue;

                } else if (STRNEQ(recvbuf, "READ_MCLXCD ")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* READ_MCLXCD */
                        p2 = strtok(NULL, " ");      /* address */
                        p3 = strtok(NULL, " ");      /* length */

                        addr = daemon_htol(p2);
                        len = atoi(p3);
			errno = 0;

                        BZERO(readbuf, READBUFSIZE);

        		if (vas_lseek(addr, SEEK_SET))
				len = 0;
        		else if (vas_read((void *)
				&readbuf[DATA_HDRSIZE], len) != len)
				len = 0;

                        if (len) {
				sprintf(readbuf, "%s%07ld", DONEMSG, 
					(ulong)len);
                                console("(%ld)\n", (ulong)len);
			} else {
				sprintf(readbuf, "%s%07ld", FAILMSG, 
					(ulong)errno);
                                console("[%s]\n", readbuf);
                        } 

                        daemon_send(readbuf, len+DATA_HDRSIZE);

                        continue;

                } else if (STRNEQ(recvbuf, "CLOSE ")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* SIZE */
                        p1 = strtok(NULL, " ");      /* filename id */
                        mfd = atoi(p1);

                        for (i = retval = 0; i < MAX_REMOTE_FDS; i++) {
                                if (fds[i] == mfd) {
					close(mfd);
					fds[i] = -1;
					retval = TRUE;
                                        break;
				}
                        }

			sprintf(sendbuf, "%s%s", savebuf, 
				retval ? " OK" : " <FAIL>");
                        console("[%s]\n", sendbuf);

                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

		} else if (STRNEQ(recvbuf, "READ ")) {

			strcpy(savebuf, recvbuf);

			p1 = strtok(recvbuf, " ");   /* READ */
			p1 = strtok(NULL, " ");      /* filename id */
			p2 = strtok(NULL, " ");      /* address */
			p3 = strtok(NULL, " ");      /* length */

			addr = daemon_htol(p2);
			len = atoi(p3);
			mfd = atoi(p1);

			BZERO(readbuf, READBUFSIZE);

			if (lseek(mfd, addr, SEEK_SET) == -1) 
				len = 0;	
			else if (read(mfd, readbuf, len) != len) 
				len = 0;
			
			if (!len) {
				sprintf(readbuf, "%s <FAIL>", savebuf);
				len = strlen(readbuf);
				console("[%s]\n", readbuf);
			} else
				console("(%ld)\n", len);

			daemon_send(readbuf, len);

			continue;

		} else if (STRNEQ(recvbuf, "MACHINE_PID")) {

                        sprintf(sendbuf, "%s %s %d", 
				recvbuf, MACHINE_TYPE, getpid());
                        console("[%s]\n", sendbuf);
                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

		} else if (STRNEQ(recvbuf, "TYPE ")) {

			strcpy(savebuf, recvbuf);
			p1 = strtok(recvbuf, " ");   /* TYPE */
			file = strtok(NULL, " ");    /* filename */

        		if (stat(file, &sbuf) < 0)
				sprintf(sendbuf, "%s <FAIL>", savebuf);
			else if (daemon_is_elf_file(file))
				sprintf(sendbuf, "%s ELF", savebuf);
			else if (STREQ(file, "/dev/mem"))
				sprintf(sendbuf, "%s DEVMEM", savebuf);
			else if (is_netdump(file, NETDUMP_REMOTE))
				sprintf(sendbuf, "%s NETDUMP", savebuf);
			else if (is_mclx_compressed_dump(file))
				sprintf(sendbuf, "%s MCLXCD", savebuf);
			else if (is_lkcd_compressed_dump(file))
				sprintf(sendbuf, "%s LKCD", savebuf);
                        else if (is_s390_dump(file))
                                sprintf(sendbuf, "%s S390D", savebuf);
			else
				sprintf(sendbuf, "%s UNSUPPORTED", savebuf);

			console("[%s]\n", sendbuf);
			
                        daemon_send(sendbuf, strlen(sendbuf));
			continue;

                } else if (STRNEQ(recvbuf, "LINUX_VERSION ")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* LINUX_VERSION */
                        file = strtok(NULL, " ");    /* filename */

			sprintf(readbuf, 
			    "/usr/bin/strings %s | grep 'Linux version'", 
				file);

        		if ((pipe = popen(readbuf, "r"))) {
				BZERO(readbuf, BUFSIZE);
        			if (fread(readbuf, sizeof(char), BUFSIZE-1,
				    pipe) > 0) 
					strcpy(sendbuf, readbuf);
				else
					sprintf(sendbuf, "%s <FAIL>", savebuf);
				pclose(pipe);
			} else 
				sprintf(sendbuf, "%s <FAIL>", savebuf);

                        console("[%s] (%d)\n", sendbuf, strlen(sendbuf));

                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

		} else if (STRNEQ(recvbuf, "READ_GZIP ")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* READ_GZIP */
			p1 = strtok(NULL, " ");      /* bufsize */
			bufsize = atol(p1);
                        file = strtok(NULL, " ");    /* filename */

			errno = 0;
			reqsize = bufsize - DATA_HDRSIZE;

                        sprintf(readbuf, "/usr/bin/gzip -c %s", file);

                        if ((pipe = popen(readbuf, "r")) == NULL) {
				sprintf(readbuf, "%s%07ld", FAILMSG, 
					(ulong)errno);
                                console("[%s]\n", readbuf);
                        	daemon_send(readbuf, DATA_HDRSIZE);
				continue;
			}

			errno = cnt = done = total = first = 0;

        		while (!done) {
                        	BZERO(readbuf, READBUFSIZE);

				cnt = fread(&readbuf[DATA_HDRSIZE], 
					sizeof(char), reqsize, pipe);

				total += cnt;

				if (feof(pipe)) {
					sprintf(readbuf, "%s%07ld", 
						DONEMSG, (ulong)cnt);
					done = TRUE;
				} else if (ferror(pipe)) {
					sprintf(readbuf, "%s%07ld", FAILMSG,
						(ulong)errno);
					done = TRUE;
				} else
					sprintf(readbuf, "%s%07ld", 
						DATAMSG, (ulong)cnt);

				console("%s[%s]\n", !first++ ? "\n" : "",
					readbuf);

				daemon_send(readbuf, bufsize);
			}

			console("GZIP total: %ld\n", total);

			pclose(pipe);
			continue;

		} else if (STRNEQ(recvbuf, "PROC_VERSION")) {

			BZERO(readbuf, READBUFSIZE);

			if (!daemon_proc_version(readbuf))
				sprintf(readbuf, "%s <FAIL>", recvbuf);

			console("[%s]\n", readbuf);

                        daemon_send(readbuf, strlen(readbuf));
			continue;

                } else if (STRNEQ(recvbuf, "DEBUGGING_SYMBOLS ")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* DEBUGGING */
                        p2 = strtok(NULL, " ");      /* filename */

			sprintf(sendbuf, "%s %s", savebuf, 
				no_debugging_symbols_found(p2));
                        console("[%s]\n", sendbuf);

                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

                } else if (STRNEQ(recvbuf, "PAGESIZE ")) {

			if (strstr(recvbuf, "LIVE")) 
                        	sprintf(sendbuf, "%s %d", recvbuf, 
					(uint)getpagesize());
                        else if (strstr(recvbuf, "NETDUMP"))
                                sprintf(sendbuf, "%s %d", recvbuf,
                                        (uint)netdump_page_size());
			else if (strstr(recvbuf, "MCLXCD")) 
                        	sprintf(sendbuf, "%s %d", recvbuf, 
					(uint)mclx_page_size());
                        else if (strstr(recvbuf, "LKCD")) 
                                sprintf(sendbuf, "%s %d", recvbuf,
                                        (uint)lkcd_page_size());
                        else if (strstr(recvbuf, "S390D"))
                                sprintf(sendbuf, "%s %d", recvbuf,
                                        s390_page_size());

                        console("[%s]\n", sendbuf);
                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

                } else if (STRNEQ(recvbuf, "FIND_BOOTED_KERNEL")) {

			BZERO(readbuf, READBUFSIZE);
			if (daemon_find_booted_kernel(readbuf))
				sprintf(sendbuf, "%s %s", recvbuf, readbuf);
			else
				sprintf(sendbuf, "%s <FAIL>", recvbuf);

			console("[%s]\n", sendbuf);
                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

		} else if (STRNEQ(recvbuf, "FIND_MODULE ")) {

                        strcpy(savebuf, recvbuf);

        		strtok(recvbuf, " ");           /* FIND_MODULE */
        		p1 = strtok(NULL, " ");         /* release */
        		p2 = strtok(NULL, " ");         /* module */

			if (daemon_find_module(p1, p2, buf1)) {
				if (daemon_checksum(buf1, &total))
					sprintf(sendbuf, "%s %s %lx", 
						savebuf, buf1, total);
				else
					sprintf(sendbuf, "%s %s %lx", 
						savebuf, buf1, 
						(ulong)0xdeadbeef);
			} else
				sprintf(sendbuf, "%s <FAIL>", savebuf);

			console("[%s]\n", sendbuf);
                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

                } else if (STRNEQ(recvbuf, "SUM ")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* SUM */
                        p2 = strtok(NULL, " ");      /* filename */

			if (daemon_checksum(p2, &total))
                        	sprintf(sendbuf, "%s %lx", savebuf, total);
			else
                        	sprintf(sendbuf, "%s <FAIL>", savebuf);

                        console("[%s]\n", sendbuf);
                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

                } else if (STRNEQ(recvbuf, "MEMORY ")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* MEMORY */
                        p2 = strtok(NULL, " ");      /* USED or FREE */
                        p3 = strtok(NULL, " ");      /* MCLXCD, LKCD, etc. */

			if (STREQ(p2, "FREE")) {
                                if (STREQ(p3, "NETDUMP")) 
                                        retval = netdump_free_memory();
				else if (STREQ(p3, "MCLXCD"))
					retval = vas_free_memory(NULL);
				else if (STREQ(p3, "LKCD")) 
					retval = lkcd_free_memory();
                                else if (STREQ(p3, "S390D")) 
                                        retval = s390_free_memory();
			}

			if (STREQ(p2, "USED")) {
				if (STREQ(p3, "NETDUMP"))
					retval = netdump_memory_used();
				else if (STREQ(p3, "MCLXCD"))
					retval = vas_memory_used();
				else if (STREQ(p3, "LKCD"))
					retval = lkcd_memory_used();
                                else if (STREQ(p3, "S390D"))
                                        retval = s390_memory_used();
			}

			sprintf(sendbuf, "%s %d", savebuf, retval);
			console("[%s]\n", sendbuf);
			daemon_send(sendbuf, strlen(sendbuf));
			continue;

                } else if (STRNEQ(recvbuf, "MEMORY_DUMP")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* MEMORY_DUMP */
                        p1 = strtok(NULL, " ");      /* bufsize */
                        p2 = strtok(NULL, " ");      /* MCLXCD, LKCD, etc. */
                        bufsize = atol(p1);

			reqsize = bufsize - DATA_HDRSIZE;
			errno = 0;

			if ((tmp = tmpfile()) == NULL) {
				sprintf(readbuf, "%s%07ld", FAILMSG, 
					(ulong)errno);
                                console("[%s]\n", readbuf);
                                daemon_send(readbuf, DATA_HDRSIZE);
                                continue;
			}

			if (STREQ(p2, "NETDUMP")) 
				retval = netdump_memory_dump(tmp);
			else if (STREQ(p2, "MCLXCD"))
				vas_memory_dump(tmp);
			else if (STREQ(p2, "LKCD")) 
				lkcd_memory_dump(tmp);
			else if (STREQ(p2, "LKCD_VERBOSE")) {
				set_lkcd_fp(tmp);
				dump_lkcd_environment(0);
				set_lkcd_fp(NULL);
			} else if (STREQ(p2, "S390D"))
                                s390_memory_dump(tmp);

			rewind(tmp);
			errno = cnt = done = total = first = 0;

        		while (!done) {
                        	BZERO(readbuf, READBUFSIZE);

				cnt = fread(&readbuf[DATA_HDRSIZE], 
					sizeof(char), reqsize, tmp);

				total += cnt;

				if (feof(tmp)) {
					sprintf(readbuf, "%s%07ld", 
						DONEMSG, (ulong)cnt);
					done = TRUE;
				} else if (ferror(tmp)) {
					sprintf(readbuf, "%s%07ld", FAILMSG, 
						(ulong)errno);
					done = TRUE;
				} else
					sprintf(readbuf, "%s%07ld", 
						DATAMSG, (ulong)cnt);

				console("%s[%s]\n", !first++ ? "\n" : "",
					readbuf);
                        	daemon_send(readbuf, bufsize);
			}

			console("MEMORY_DUMP total: %ld\n", total);

			fclose(tmp);
			continue;

               } else if (STRNEQ(recvbuf, "NETDUMP_INIT ")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* NETDUMP_INIT */
                        p2 = strtok(NULL, " ");      /* fd */
                        p3 = strtok(NULL, " ");      /* dumpfile */

                        mfd = atoi(p2);
                        for (i = 0; i < MAX_REMOTE_FDS; i++) {
                                if (fds[i] == mfd) {
                                        close(mfd);
                                        fds[i] = -1;
                                        break;
                                }
                        }

                        sprintf(sendbuf, "%s %s", savebuf,
                            netdump_init(p3, NULL) ? "OK" : "<FAIL>");

                        if ((addr = get_netdump_panic_task())) {
                                sprintf(readbuf, "\npanic_task: %lx\n", addr);
                                strcat(sendbuf, readbuf);
                        }

                        console("[%s]\n", sendbuf);
                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

                } else if (STRNEQ(recvbuf, "LKCD_DUMP_INIT ")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* LKCD_DUMP_INIT */
                        p2 = strtok(NULL, " ");      /* fd */
                        p3 = strtok(NULL, " ");      /* dumpfile */

			sprintf(sendbuf, "%s %s", savebuf,
			    lkcd_dump_init(NULL, atoi(p2), p3) ? 
				"OK" : "<FAIL>");

			if ((addr = get_lkcd_panic_task())) {
				sprintf(readbuf, "\npanic_task: %lx\n", addr);
				strcat(sendbuf, readbuf);
			}
			readbuf[0] = NULLCHAR;
			get_lkcd_panicmsg(readbuf);
			if (strlen(readbuf)) {
				strcat(sendbuf, "panicmsg: ");
				strcat(sendbuf, readbuf);
			}

                        console("[%s]\n", sendbuf);
                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

                } else if (STRNEQ(recvbuf, "READ_LKCD ")) {

                        strcpy(savebuf, recvbuf);

                        p1 = strtok(recvbuf, " ");   /* READ_LKCD */
                        p1 = strtok(NULL, " ");      /* filename id */
                        p2 = strtok(NULL, " ");      /* address */
                        p3 = strtok(NULL, " ");      /* length */

                        mfd = atoi(p1);
                        addr = daemon_htol(p2);
                        len = atoi(p3);

                        BZERO(readbuf, READBUFSIZE);
			errno = 0;

                        if (!lkcd_lseek(addr))
                                len = 0;         
                        else if (lkcd_read((void *)
				&readbuf[DATA_HDRSIZE], len) != len)
                                len = 0;

			if (len) {
				sprintf(readbuf, "%s%07ld", DONEMSG,(ulong)len);
                                console("(%ld)\n", (ulong)len);
			} else {
				sprintf(readbuf, "%s%07ld", FAILMSG, 
					(ulong)errno);
                                console("[%s]\n", readbuf);
                        }

                        daemon_send(readbuf, len+DATA_HDRSIZE);
                        continue;

                } else if (STRNEQ(recvbuf, "S390_DUMP_INIT ")) {
                        
                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* S390_DUMP_INIT */
                        p2 = strtok(NULL, " ");      /* fd */ 
                        p3 = strtok(NULL, " ");      /* filename */

			mfd = atoi(p2);
			for (i = 0; i < MAX_REMOTE_FDS; i++) {
                                if (fds[i] == mfd) {
                                        close(mfd);
                                        fds[i] = -1;
                                        break;
                                }
                        }
                        
                        sprintf(sendbuf, "%s %s", savebuf,
                            s390_dump_init(p3) ? "OK" : "<FAIL>");

                        if ((addr = get_s390_panic_task())) {
                                sprintf(readbuf, "\npanic_task: %lx\n", addr);
                                strcat(sendbuf, readbuf);
                        }
                        readbuf[0] = NULLCHAR;
                        get_s390_panicmsg(readbuf);
                        if (strlen(readbuf)) {
                                strcat(sendbuf, "panicmsg: ");
                                strcat(sendbuf, readbuf);
                        }

                        console("[%s]\n", sendbuf);
                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

                } else if (STRNEQ(recvbuf, "S390X_DUMP_INIT ")) {
                        
                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* S390X_DUMP_INIT */
                        p2 = strtok(NULL, " ");      /* fd */ 
			p3 = strtok(NULL, " ");      /* filename */

                        mfd = atoi(p2);
                        for (i = 0; i < MAX_REMOTE_FDS; i++) {
                                if (fds[i] == mfd) {
                                        close(mfd);
                                        fds[i] = -1;
                                        break;
                                }
                        }
                        
                        sprintf(sendbuf, "%s %s", savebuf,
                            s390x_dump_init(p3) ? "OK" : "<FAIL>");

                        if ((addr = get_s390x_panic_task())) {
                                sprintf(readbuf, "\npanic_task: %lx\n", addr);
                                strcat(sendbuf, readbuf);
                        }
                        readbuf[0] = NULLCHAR;
                        get_s390x_panicmsg(readbuf);
                        if (strlen(readbuf)) {
                                strcat(sendbuf, "panicmsg: ");
                                strcat(sendbuf, readbuf);
                        }

                        console("[%s]\n", sendbuf);
                        daemon_send(sendbuf, strlen(sendbuf));
                        continue;

                } else if (STRNEQ(recvbuf, "READ_S390D ")) {

                        strcpy(savebuf, recvbuf);

                        p1 = strtok(recvbuf, " ");   /* READ_S390D */
                        p1 = strtok(NULL, " ");      /* filename id */
                        p2 = strtok(NULL, " ");      /* address */
                        p3 = strtok(NULL, " ");      /* length */

                        mfd = atoi(p1);
                        addr = daemon_htol(p2);
                        len = atoi(p3);

                        BZERO(readbuf, READBUFSIZE);
                        errno = 0;

			if ((len = read_s390_dumpfile(UNUSED, 
			    &readbuf[DATA_HDRSIZE], len, UNUSED, addr)) < 0)
                                len = 0;

                        if (len) {
                                sprintf(readbuf, "%s%07ld", DONEMSG,(ulong)len);
                                console("(%ld)\n", (ulong)len);
                        } else {
                                sprintf(readbuf, "%s%07ld", FAILMSG,
                                        (ulong)errno);
                                console("[%s]\n", readbuf);
                        }

                        daemon_send(readbuf, len+DATA_HDRSIZE);
                        continue;

                } else if (STRNEQ(recvbuf, "EXECUTE ")) {

                        strcpy(savebuf, recvbuf);
                        p1 = strtok(recvbuf, " ");   /* EXECUTE */
                        p1 = strtok(NULL, " ");      /* bufsize */
                        p2 = strtok(NULL, " ");      /* MCLXCD or LKCD */
			p3 = strstr(savebuf, p2);
                        bufsize = atol(p1);

			reqsize = bufsize - DATA_HDRSIZE;

			sprintf(readbuf, "echo  | %s", p3);

                        if ((pipe = popen(readbuf, "r")) == NULL) {
                        	BZERO(readbuf, READBUFSIZE);
                                sprintf(readbuf, "%s%07ld", FAILMSG, 
					(ulong)errno);
                                console("[%s]\n", readbuf);
                                daemon_send(readbuf, bufsize);
                                continue;
                        }

			errno = cnt = done = total = first = 0;

        		while (!done) {
                        	BZERO(readbuf, READBUFSIZE);

				cnt = fread(&readbuf[DATA_HDRSIZE], 
					sizeof(char), reqsize, pipe);

				total += cnt;

				if (feof(pipe)) {
					sprintf(readbuf, "%s%07ld", 
						DONEMSG, (ulong)cnt);
					done = TRUE;
				} else if (ferror(pipe)) {
					sprintf(readbuf, "%s%07ld", FAILMSG, 
						(ulong)errno);
					done = TRUE;
				} else
					sprintf(readbuf, "%s%07ld", 
						DATAMSG, (ulong)cnt);

				console("%s[%s]\n", !first++ ? "\n" : "",
					readbuf);
                        	daemon_send(readbuf, bufsize);
			}

			console("EXECUTE total: %ld\n", total);

			pclose(pipe);
			continue;

		} else if (STRNEQ(recvbuf, "EXIT")) {

			sprintf(sendbuf, "%s OK", recvbuf);
			console("[%s]\n", sendbuf);
			daemon_send(sendbuf, strlen(sendbuf));
			return;

		} else {
			sprintf(sendbuf, "%s <FAIL>", recvbuf);
			console("[%s]\n", sendbuf);
			daemon_send(sendbuf, strlen(sendbuf));
		}
	}
}

/*
 *  Common error-checking send routine.
 */
#define MINSENDSIZE  (1448)

static void
daemon_send(void *buffer, int len)
{
        int remaining, count, ret;
        char *bufptr;

        remaining = len;
        bufptr = buffer;
 
        while (remaining) {
                count = MIN(MINSENDSIZE, remaining);

                switch (ret = send(rc->sock, bufptr, count, 0))
		{
		case -1:
			switch (errno)
			{
			case ENOBUFS:
			case ENOMEM:
				sleep(1);
				continue;
			default:
				exit(1);
			}
			break;

		default:
			remaining -= ret;
                	bufptr += ret;
			break;
		}
        }

	console("daemon_send: sent %d\n", len);
}
 
/*
 *  debug print if the -d command line option was used.
 */

int
console(char *fmt, ...)
{
        char output[BUFSIZE*2];
        va_list ap;
        int retval;
	FILE *fp;

        if (!rc->remdebug || !fmt || !strlen(fmt))
                return 0;

        va_start(ap, fmt);
        (void)vsnprintf(output, BUFSIZE*2, fmt, ap);
        va_end(ap);

        if ((fp = fopen(rc->remdebugfile, "a")) == NULL)
                return 0;

        retval = fprintf(fp, "%s", output);
        fclose(fp);

	return retval;
}

/*
 *  Fill in the file size of a freshly opened file.
 */
ulong
daemon_filesize(int fd)
{
	struct stat sbuf;

        if (fstat(fd, &sbuf) == 0)
		return(sbuf.st_size);
        else
                return 0;
}


/*
 *  Check for gdb output stating "(no debugging symbols found)".
 */
char *
no_debugging_symbols_found(char *file)
{
	FILE *pipe;
	char buf[BUFSIZE];

	sprintf(buf, "echo 'q' | /usr/bin/gdb %s", file);
	if ((pipe = popen(buf, "r")) == NULL)
		return "NO_GDB";

	while (fgets(buf, BUFSIZE, pipe)) {
		if (strstr(buf, "(no debugging symbols found)")) {
			pclose(pipe);
			return "NO_DEBUG";
		}
	}
	pclose(pipe);

	return "DEBUG_OK";
}

/*
 *  Read /proc/version into a buffer.
 */
static int
daemon_proc_version(char *buf)
{
        FILE *pipe; 
        struct stat sbuf;
                
        if (stat("/proc/version", &sbuf) == -1)
                return FALSE;

        if ((pipe = popen("/bin/cat /proc/version", "r")) == NULL)
                return FALSE;

        if (fread(buf, sizeof(char),
                BUFSIZE-1, pipe) <= 0) {
		pclose(pipe);
                return FALSE;
	}

        pclose(pipe);

        return TRUE;
}

/*
 *  c/o W. Richard Stevens...
 */

#define OPEN_MAX_GUESS (256)

static int
daemon_init(void)
{
        int i;
        pid_t pid;
        int open_max; 
                
        if ((pid = fork()) < 0)
                return FALSE;
        else if (pid != 0)
                exit(0);

        setsid();
        chdir("/");
        umask(0);

        if ((open_max = sysconf(_SC_OPEN_MAX)) < 0)
                open_max = OPEN_MAX_GUESS;

        for (i = 0; i < open_max; i++)
                close(i);

        signal(SIGCLD, SIG_IGN);

	unsetenv("DISPLAY");

        return TRUE;
}

/*
 *  Determine whether a file is in ELF format by checking the magic number
 *  in the first EI_NIDENT characters of the file.  If it's there, further
 *  qualify it by doing a "file" operation on it.
 */
static int
daemon_is_elf_file(char *s)
{
        int fd, is_elf;
        char magic[EI_NIDENT];
	char buf[BUFSIZE];
	FILE *pipe;

        if ((fd = open(s, O_RDONLY)) < 0) 
                return FALSE;
        
        if (read(fd, magic, EI_NIDENT) != EI_NIDENT) {
                close(fd);
                return FALSE;
        }
        close(fd);

        magic[EI_CLASS] = NULLCHAR;

        if (!STREQ(magic, ELFMAG))
                return FALSE;

	sprintf(buf, "/usr/bin/file -L %s", s);
        if ((pipe = popen(buf, "r")) == NULL) {
        	console("/usr/bin/strings popen failed\n");
                return TRUE;
        } 

	is_elf = FALSE;
        while (fgets(buf, BUFSIZE-1, pipe)) {
                if (strstr(buf, " ELF ") && strstr(buf, "executable")) {
                        is_elf = TRUE;
                        break;
                }
        }
        pclose(pipe);

	return is_elf;
}

/*
 *  Translate ASCII hex addresses.
 */
static ulong
daemon_htol(char *s)
{
    	long i, j; 
	ulong n;

    	if (strlen(s) > MAX_HEXADDR_STRLEN) 
		exit(1);

    	for (n = i = 0; s[i] != 0; i++) {
	        switch (s[i]) 
	        {
	            case 'a':
	            case 'b':
	            case 'c':
	            case 'd':
	            case 'e':
	            case 'f':
	                j = (s[i] - 'a') + 10;
	                break;
	            case 'A':
	            case 'B':
	            case 'C':
	            case 'D':
	            case 'E':
	            case 'F':
	                j = (s[i] - 'A') + 10;
	                break;
	            case '1':
	            case '2':
	            case '3':
	            case '4':
	            case '5':
	            case '6':
	            case '7':
	            case '8':
	            case '9':
	            case '0':
	                j = s[i] - '0';
	                break;
		    case 'x':
		    case 'X':
			continue;
	            default:
			exit(0);
	        }
	        n = (16 * n) + j;
    	}

    	return(n);
}


/*
 *  Adapted from filesys.c, seach the default directories for a kernel
 *  that matches /proc/version.  daemon_build_searchdirs() builds an
 *  array of directory names.
 */

#define CREATE  1
#define DESTROY 0
#define DEFAULT_SEARCHDIRS 4

static int
daemon_find_booted_kernel(char *namelist)
{
	char kernel[BUFSIZE];
	char command[BUFSIZE];
	char buffer[BUFSIZE];
	char proc_version[BUFSIZE];
	char *version;
	char **searchdirs;
	int i;
        DIR *dirp;
        struct dirent *dp;
	FILE *pipe;
	int found;
	struct stat sbuf;

	console("\n");

	if (stat("/proc/version", &sbuf) < 0) {
		console("/proc/version not found\n");
		return FALSE;
	}

	if (!daemon_proc_version(proc_version)) {
                console("cannot read /proc/version\n");
                return FALSE;
	}

	version = proc_version;

        searchdirs = daemon_build_searchdirs(CREATE);

	for (i = 0, found = FALSE; !found && searchdirs[i]; i++) { 
	        dirp = opendir(searchdirs[i]);
		if (!dirp)
			continue;
	        for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
			sprintf(kernel, "%s%s", searchdirs[i], dp->d_name);

			if (daemon_mount_point(kernel) ||
			    !daemon_file_readable(kernel) || 
                            !daemon_is_elf_file(kernel))
				continue;

			sprintf(command, "/usr/bin/strings %s", kernel);
	        	if ((pipe = popen(command, "r")) == NULL) {
				console("/usr/bin/strings popen failed\n");
				continue;
			}

			while (fgets(buffer, BUFSIZE-1, pipe)) {
				if (STREQ(buffer, version)) {
					found = TRUE;
					break;
				}
			}
			pclose(pipe);
	
			if (found)
				break;
	        }
		closedir(dirp);
	}

	daemon_mount_point(DESTROY);
	daemon_build_searchdirs(DESTROY);

	if (found) {
		console("booted kernel: %s\n", kernel);
		strcpy(namelist, kernel);
                return TRUE;
	}

	console("cannot find booted kernel\n");
	return FALSE;
}

static char **
daemon_build_searchdirs(int create)
{
	int i;
	int cnt;
	DIR *dirp;
        struct dirent *dp;
	char dirbuf[BUFSIZE];
	static char **searchdirs = { 0 };
	static char *default_searchdirs[DEFAULT_SEARCHDIRS+1] = {
        	"/usr/src/linux/",
        	"/boot/",
		"/boot/efi/",
        	"/",
        	NULL
	};

	if (!create) {
		if (searchdirs) {
			for (i = DEFAULT_SEARCHDIRS; searchdirs[i]; i++) 
				free(searchdirs[i]);
			free(searchdirs);
		}
		return NULL;
	}

	cnt = DEFAULT_SEARCHDIRS;   

        if ((dirp = opendir("/usr/src"))) {
                for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) 
			cnt++;

		if ((searchdirs = (char **)malloc(cnt * sizeof(char *))) 
		    == NULL) {
			console("/usr/src/ directory list malloc failed: %s\n",
				strerror(errno));
			closedir(dirp);
			return default_searchdirs;
		} 

		for (i = 0; i < DEFAULT_SEARCHDIRS; i++) 
			searchdirs[i] = default_searchdirs[i];
		cnt = DEFAULT_SEARCHDIRS;

		rewinddir(dirp);

        	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
			if (STREQ(dp->d_name, "linux") ||
			    STREQ(dp->d_name, ".") ||
			    STREQ(dp->d_name, ".."))
				continue;

			sprintf(dirbuf, "/usr/src/%s", dp->d_name);
			if (daemon_mount_point(dirbuf))
				continue;
			if (!daemon_is_directory(dirbuf))
				continue;

			if ((searchdirs[cnt] = (char *)
			    malloc(strlen(dirbuf)+2)) == NULL) {
				console("/usr/src/ directory entry malloc failed: %s\n",
					strerror(errno));
				break;
			}
			sprintf(searchdirs[cnt], "%s/", dirbuf); 
			cnt++;
		}
		searchdirs[cnt] = NULL;
		closedir(dirp);
	}

	for (i = 0; searchdirs[i]; i++) 
		console("searchdirs[%d]: %s\n", i, searchdirs[i]);

	return searchdirs;
}

/*
 *  Determine whether a file is a mount point, without the benefit of stat().
 *  This horrendous kludge is necessary to avoid uninterruptible stat() or 
 *  fstat() calls on nfs mount-points where the remote directory is no longer 
 *  available.
 */
static int
daemon_mount_point(char *name)
{
	int i;
	static int mount_points_gathered = -1;
	static char **mount_points;
        char *arglist[MAXARGS];
	char buf[BUFSIZE];
	char cmd[BUFSIZE];
	int argc, found;
	struct stat sbuf;
        FILE *pipe;

	/*
	 *  The first time through, stash a list of mount points.
	 */

	if (mount_points_gathered < 0) {
		found = mount_points_gathered = 0; 

        	if (stat("/proc/mounts", &sbuf) == 0)
			sprintf(cmd, "/bin/cat /proc/mounts");
		else if (stat("/etc/mtab", &sbuf) == 0)
			sprintf(cmd, "/bin/cat /etc/mtab");
		else
                	return FALSE;

        	if ((pipe = popen(cmd, "r")) == NULL)
                	return FALSE;

		while (fgets(buf, BUFSIZE, pipe)) {
        		argc = daemon_parse_line(buf, arglist);
			if (argc < 2)
				continue;
			found++;
		}
		pclose(pipe);

		if (!(mount_points = (char **)malloc(sizeof(char *) * found)))
			return FALSE;

                if ((pipe = popen(cmd, "r")) == NULL) 
                        return FALSE;

		i = 0;
                while (fgets(buf, BUFSIZE, pipe) && 
		       (mount_points_gathered < found)) {
                        argc = daemon_parse_line(buf, arglist);
                        if (argc < 2)
                                continue;
			if ((mount_points[i] = (char *)
			     malloc(strlen(arglist[1])*2))) { 
				strcpy(mount_points[i], arglist[1]);
                        	mount_points_gathered++, i++;
			}
                }
        	pclose(pipe);
	}

	/*
	 *  A null name string means we're done with this routine forever,
	 *  so the malloc'd memory can be freed.
	 */
        if (!name) {   
                for (i = 0; i < mount_points_gathered; i++) 
                        free(mount_points[i]);
                free(mount_points);
                return FALSE;
        }


	for (i = 0; i < mount_points_gathered; i++) {
		if (STREQ(name, mount_points[i]))
			return TRUE;
	}


        return FALSE;
}

/*
 *  Check whether a file is a directory.
 */
static int
daemon_is_directory(char *file)
{
    struct stat sbuf;

    if (!file || !strlen(file))
        return(FALSE);

    if (stat(file, &sbuf) == -1)
        return(FALSE);                         /* This file doesn't exist. */

    return((sbuf.st_mode & S_IFMT) == S_IFDIR ? TRUE : FALSE);
}

/*
 *  Check whether a file is readable.
 */
static int
daemon_file_readable(char *file)
{
        struct stat sbuf;
        long tmp;
        int fd;

        if (stat(file, &sbuf) < 0)
                return FALSE;

        if ((fd = open(file, O_RDONLY)) < 0)
                return FALSE;

        if (read(fd, &tmp, sizeof(tmp)) != sizeof(tmp)) {
                close(fd);
                return FALSE;
        }
        close(fd);

        return TRUE;
}

/*
 *  Parse a line into tokens, populate the passed-in argv[] array, and return
 *  the count of arguments found.  This function modifies the passed-string 
 *  by inserting a NULL character at the end of each token.  Expressions 
 *  encompassed by parentheses, and strings encompassed by apostrophes, are 
 *  collected into single tokens.
 */
int
daemon_parse_line(char *str, char *argv[])
{
	int i, j;
    	int string;
	int expression;

	for (i = 0; i < MAXARGS; i++)
		argv[i] = NULL;

	daemon_clean_line(str);

        if (str == NULL || strlen(str) == 0)
                return(0);

        i = j = 0;
        string = expression = FALSE;
        argv[j++] = str;

    	while (TRUE) {
		if (j == MAXARGS) {
			console("too many arguments in string!\n");
			return 0;
		}

        	while (str[i] != ' ' && str[i] != '\t' && str[i] != NULLCHAR) {
            		i++;
        	}

	        switch (str[i])
	        {
	        case ' ':
	        case '\t':
	            str[i++] = NULLCHAR;
	
	            if (str[i] == '"') {    
	                str[i] = ' ';
	                string = TRUE;
	                i++;
	            }

                    if (str[i] == '(') {     
                        expression = TRUE;
                    }
	
	            while (str[i] == ' ' || str[i] == '\t') {
	                i++;
	            }
	
	            if (str[i] != NULLCHAR && str[i] != '\n') {
	                argv[j++] = &str[i];
	                if (string) {
	                        string = FALSE;
	                        while (str[i] != '"' && str[i] != NULLCHAR)
	                                i++;
	                        if (str[i] == '"')
	                                str[i] = ' ';
	                }
                        if (expression) {
                                expression = FALSE;
                                while (str[i] != ')' && str[i] != NULLCHAR)
                                        i++;
                        }
	                break;
	            }
	                        /* else fall through */
	        case '\n':
	            str[i] = NULLCHAR;
	                        /* keep falling... */
	        case NULLCHAR:
	            argv[j] = NULLCHAR;
	            return(j);
	        }
    	}  
}

/*
 *  Strip line-beginning and line-ending whitespace and linefeeds.
 */

char *strip_linefeeds(char *line)
{
	return(daemon_clean_line(line));
}

static char *
daemon_clean_line(char *line)
{
        char buf[BUFSIZE];
        char *p;

        if (line == NULL || strlen(line) == 0)
                return(line);

        strcpy(buf, line);
        p = &buf[0];
        while (*p == ' ' || *p == '\t')
                p++;
        strcpy(line, p);

        if (line == NULL || strlen(line) == 0)
                return(line);

        p = &LASTCHAR(line);

        while (*p == '\n')
                *p = NULLCHAR;

        if (line == NULL || strlen(line) == 0)
                return(line);

        p = &LASTCHAR(line);

        while (*p == ' ' || *p == '\t') {
                *p = NULLCHAR;
                if (p == line)
                        break;
                p--;
        }

        return(line);
}


/*
 *  Service not offered by the daemon.
 */

int
monitor_memory(long *a1, long *a2, long *a3, long *a4)
{
	return FALSE;
}

static int
daemon_find_module(char *release, char *filename, char *retbuf)
{
	char dir[BUFSIZE];
	int found;

	found = FALSE;

	sprintf(dir, "%s/%s", DEFAULT_REDHAT_DEBUG_LOCATION, release);
	found = daemon_search_directory_tree(dir, filename, retbuf);

	if (!found) {
        	sprintf(dir, "/lib/modules/%s", release);
		found = daemon_search_directory_tree(dir, filename, retbuf);
	}

	return found;
}


int
daemon_search_directory_tree(char *directory, char *file, char *retbuf)
{
	char command[BUFSIZE];
	char buf[BUFSIZE];
	FILE *pipe;
	int found;

	if (!daemon_file_exists("/usr/bin/find", NULL) || 
	    !daemon_file_exists("/bin/echo", NULL) ||
	    !daemon_is_directory(directory)) 
		return FALSE;

	sprintf(command, 
            "/usr/bin/find %s -name %s -print; /bin/echo search done",
		directory, file);

        if ((pipe = popen(command, "r")) == NULL) 
                return FALSE;

	found = FALSE;

        while (fgets(buf, BUFSIZE-1, pipe) || !found) {
                if (STREQ(buf, "search done\n")) 
                        break;
                
                if (!found &&
                    STREQ((char *)basename(strip_linefeeds(buf)), file)) {
                        strcpy(retbuf, buf);
			found = TRUE;
                }
        }

        pclose(pipe);

	return found;
}

static int
daemon_file_exists(char *file, struct stat *sp)
{
        struct stat sbuf;

        if (stat(file, sp ? sp : &sbuf) == 0)
                return TRUE;

        return FALSE;
}


static int 
daemon_checksum(char *file, long *retsum)
{
        int i; 
        int fd; 
        ssize_t cnt;
        char buf[MIN_PAGE_SIZE];
        long csum; 
                                
        if ((fd = open(file, O_RDONLY)) < 0)
                return FALSE;
   
        csum = 0;
        BZERO(buf, MIN_PAGE_SIZE);
        while ((cnt = read(fd, buf, MIN_PAGE_SIZE)) > 0) {
                for (i = 0; i < cnt; i++)
                        csum += buf[i];
                BZERO(buf, MIN_PAGE_SIZE);
        }
        close(fd);

        *retsum = csum;

        return TRUE;
}

#else

static void copy_to_local_namelist(struct remote_file *);
static char *create_local_namelist(struct remote_file *);
static int remote_find_booted_kernel(struct remote_file *);
static int remote_proc_version(char *);
static int validate_phys_base(physaddr_t, physaddr_t, physaddr_t);
static int remote_file_open(struct remote_file *);
static int remote_file_close(struct remote_file *);
static int identical_namelist(char *, struct remote_file *);
void remote_socket_options(int);
static int copy_remote_file(struct remote_file *, int, char *, char *);
static void copy_remote_gzip_file(struct remote_file *, char *, char *);
static int remote_file_checksum(struct remote_file *);
static int remote_file_type(char *);
static int remote_lkcd_dump_init(void);
static int remote_s390_dump_init(void);
static int remote_netdump_init(void);
static int remote_tcp_read(int, const char *, size_t);
static int remote_tcp_read_string(int, const char *, size_t, int);
static int remote_tcp_write(int, const void *, size_t);
static int remote_tcp_write_string(int, const char *);

struct _remote_context {
        uint flags;
        int n_cpus;
        int vfd;
        char remote_type[10];
} remote_context;

#define NIL_FLAG       (0x01U)

#define NIL_MODE() (rc->flags & NIL_FLAG)

struct _remote_context *rc = &remote_context;

/*
 *  Parse, verify and establish a connection with the network daemon
 *  specified on the crash command line.
 *
 *  The format is: [remote-hostname]:port[,remote-namelist][,remote-dumpfile]
 *
 *  where everything but the port number is optional, and the remote-namelist
 *  and remote-dumpfile can be reversed.
 *
 *    1. The default remote host is the local host. 
 *    2. The default dumpfile is /dev/mem. 
 *    3. If no remote-namelist and remote-dumpfile are given, the daemon
 *       is queried for a kernel that matches the remote /proc/version.
 *       If no local kernel namelist is entered, the remote version will
 *       be copied locally when fd_init() is called.
 *    4. If a remote-dumpfile is given with no remote namelist, it is presumed
 *       that the kernel namelist will be entered locally.
 */

int
is_remote_daemon(char *dp)
{
	char *p1;
	static char defaulthost[MAXHOSTNAMELEN+1];
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	char *portp, *filep, *file1, *file2;
	struct hostent *hp;
        struct sockaddr_in serv_addr;

	if (!strstr(dp, ":") || file_exists(dp, NULL))
		return FALSE;

	pc->port = 0;
	pc->server = pc->server_memsrc = NULL;
	rc->vfd = pc->rmfd = pc->rkfd = -1;
	file1 = file2 = NULL;

	if ((filep = strstr(dp, ","))) {
		*filep = NULLCHAR;
		filep++;
	}

	if (*dp == ':') {
        	BZERO(defaulthost, MAXHOSTNAMELEN+1);
        	gethostname(defaulthost, MAXHOSTNAMELEN);
        	pc->server = defaulthost;
		portp = dp+1;
	} else {
		pc->server = strtok(dp, ":");	
		portp = strtok(NULL, ":");
	}

	if (portp == NULL) 
		return FALSE;

        if (decimal(portp, 0))
                pc->port = (ushort)atoi(portp);
        else
        	return FALSE;

	if (filep) {
		file1 = strtok(filep, ",");
		file2 = strtok(NULL, ",");
	}

	if (!pc->server || !pc->port) 
		return FALSE;

	if (CRASHDEBUG(1)) {
		fprintf(fp, "server: [%s]\n", pc->server);
		fprintf(fp, "  port: [%d]\n", pc->port);
		fprintf(fp, " file1: [%s]\n", file1);
		fprintf(fp, " file2: [%s]\n", file2);
	}

        if ((hp = gethostbyname(pc->server)) == NULL) {
                herror(pc->server);
                error(FATAL, "gethostbyname [%s] failed\n", pc->server);
        }

	if (CRASHDEBUG(1)) {
		struct in_addr *ip;
        	char **listptr;

        	listptr = hp->h_addr_list;
        	while ((ip = (struct in_addr *) *listptr++) != NULL)
                	printf("%s\n", inet_ntoa(*ip));
	}

        if ((pc->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                perror("socket");
                error(FATAL, "socket call failed\n");
        }

        BZERO((char *)&serv_addr, sizeof(struct sockaddr_in));
        serv_addr.sin_family = AF_INET;
        BCOPY(hp->h_addr, (char *)&serv_addr.sin_addr, hp->h_length);
        serv_addr.sin_port = htons(pc->port);

        if (connect(pc->sockfd, (struct sockaddr *)&serv_addr,
            sizeof(struct sockaddr_in)) < 0) {
                herror(hp->h_name);
                error(FATAL, "connect [%s:%d] failed\n", hp->h_name, pc->port);
                clean_exit(1);
        }

	if (CRASHDEBUG(1))
        	printf("connect [%s:%d]: success\n", hp->h_name, pc->port);

	remote_socket_options(pc->sockfd);

	/*
	 * Try and use NIL mode.
	 */
	BZERO(sendbuf, BUFSIZE);
	BZERO(recvbuf, BUFSIZE);
	sprintf(sendbuf, "NIL");
	remote_tcp_write_string(pc->sockfd, sendbuf);
	remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, 0);
	if (!strstr(recvbuf, "<FAIL>")) {
		rc->flags |= NIL_FLAG;
		p1 = strtok(recvbuf, " ");  /* NIL */
		p1 = strtok(NULL, " ");     /* remote type */
		if (p1 && p1[0] != 'L')
			pc->flags2 |= REM_PAUSED_F;
	}
        /*
         *  Get the remote machine type and verify a match.  The daemon pid
         *  is also used as a live system initial context.
         */
        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);
        sprintf(sendbuf, "MACHINE_PID");
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
        p1 = strtok(recvbuf, " ");  /* MACHINE */
        p1 = strtok(NULL, " ");     /* machine type */
	if (CRASHDEBUG(1))
        	printf("remote MACHINE: %s\n", p1);
	if (!STREQ(pc->machine_type, p1))
		error(FATAL, "machine type mismatch: local: %s remote: %s\n",
			pc->machine_type, p1);
        p1 = strtok(NULL, " ");     /* pid */
        pc->server_pid = atol(p1);

	if (file1) {
		switch (remote_file_type(file1))
		{
		case TYPE_ELF:
			pc->server_namelist = file1; 
			break;
		case TYPE_NETDUMP:
                        pc->server_memsrc = file1;
                        pc->flags |= REM_NETDUMP;
                        break;
		case TYPE_MCLXCD:
			pc->server_memsrc = file1;
			pc->flags |= REM_MCLXCD;
			break;
		case TYPE_DEVMEM:
			pc->server_memsrc = file1;
			break;
		case TYPE_LKCD:
			pc->server_memsrc = file1;
			pc->flags |= REM_LKCD;
			break;
                case TYPE_S390D:
                        pc->server_memsrc = file1;
                        pc->flags |= REM_S390D;
                        break;
		}
	}

        if (file2) {
                switch (remote_file_type(file2))
                {
                case TYPE_ELF:
                        if (pc->server_namelist)
                                error(FATAL,
                                    "two remote namelists entered: %s and %s\n",
                                         file1, file2);
                        pc->server_namelist = file2;
                        break;
                case TYPE_NETDUMP:
                        if (pc->server_memsrc)
                                error(FATAL,
                                    "neither %s or %s is an ELF file\n",
                                         file1, file2);
                        pc->server_memsrc = file2;
                        pc->flags |= REM_NETDUMP;
                        break;
                case TYPE_MCLXCD:
                        if (pc->server_memsrc)
                                error(FATAL,
                                    "neither %s or %s is an ELF file\n",
                                         file1, file2);
                        pc->server_memsrc = file2;
                        pc->flags |= REM_MCLXCD;
                        break;
		case TYPE_LKCD:
                        if (pc->server_memsrc)
                                error(FATAL,
                                    "neither %s or %s is an ELF file\n",
                                         file1, file2);
                        pc->server_memsrc = file2;
                        pc->flags |= REM_LKCD;
                        break;
                case TYPE_S390D:
                        if (pc->server_memsrc)
                                error(FATAL,
                                    "neither %s or %s is an ELF file\n",
                                         file1, file2);
                        pc->server_memsrc = file2;
                        pc->flags |= REM_S390D;
                        break;
                case TYPE_DEVMEM:
                        pc->server_memsrc = file2;
                        break;
                }

        }

	return TRUE;
}

/*
 *  Determine whether a file is a kernel or a memory source.
 */
static int
remote_file_type(char *file)
{
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];

        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);
        sprintf(sendbuf, "TYPE %s", file);
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());

        if (strstr(recvbuf, "<FAIL>"))
                error(FATAL, "invalid remote file name: %s\n", file);
        else if (strstr(recvbuf, " UNSUPPORTED"))
                error(FATAL, "unsupported remote file type: %s\n", file);
	else if (strstr(recvbuf, " NETDUMP"))
		return TYPE_NETDUMP;
        else if (strstr(recvbuf, " ELF")) 
                return TYPE_ELF;        
        else if (strstr(recvbuf, " MCLXCD")) 
		return TYPE_MCLXCD;
        else if (strstr(recvbuf, " DEVMEM")) 
		return TYPE_DEVMEM;
        else if (strstr(recvbuf, " LKCD")) 
		return TYPE_LKCD;
        else if (strstr(recvbuf, " S390D")) 
		return TYPE_S390D;
       
        return (error(FATAL, "unknown remote file type: %s\n", file));
}

/*
 *  Try to set the receive buffer size to READBUFSIZE with setsockopt(), 
 *  storing the value returned by getsockopt() after the attempt is made.
 *  Then enforce a SO_RCVLOWAT (low water mark) of 1, to ensure that error
 *  recovery won't get hung in the recv() call in remote_clear_pipeline().
 */
void
remote_socket_options(int sockfd)
{
	int rcvbuf, optlen;

	pc->rcvbufsize = rcvbuf = READBUFSIZE;

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf,
	    sizeof(rcvbuf)) < 0) {
		error(INFO, "SO_RCVBUF setsockopt error\n");
		return;
	}

	optlen = sizeof(rcvbuf);
        if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf,
            (socklen_t *)&optlen) < 0) {
                error(INFO, "SO_RCVBUF getsockopt error\n");
                return;
        }

	if (CRASHDEBUG(1))
        	printf("socket SO_RCVBUF size: %d\n", rcvbuf); 

	rcvbuf = 1;

        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVLOWAT, (char *)&rcvbuf,
            sizeof(rcvbuf)) < 0) {
		/*
		 *  Earlier versions of Linux TCP won't accept this option,
                 *  which is hardcoded to the desired count of 1 anyway.
		 *  Set it to 0, and verify it as 1 in the getsockopt() call.
		 */
		if (CRASHDEBUG(1)) 
                	error(INFO, "SO_RCVLOWAT setsockopt error: %s\n",
				strerror(errno));
		rcvbuf = 0;
        }

        optlen = sizeof(rcvbuf);
        if (getsockopt(sockfd, SOL_SOCKET, SO_RCVLOWAT, (char *)&rcvbuf,
            (socklen_t *)&optlen) < 0) {
                error(INFO, "SO_RCVLOWAT getsockopt error\n");
                return;
        }

	if (CRASHDEBUG(1) || (rcvbuf != 1))
        	error(INFO, "socket SO_RCVLOWAT value: %d\n", rcvbuf); 

}

/*
 * Wrapper around recv to read full length packet.
 */
static int
remote_tcp_read(int sock, const char *pv_buffer, size_t cb_buffer)
{
	size_t cb_total = 0;

	do
	{
		ssize_t cb_read = recv(sock, (void*)pv_buffer, cb_buffer, MSG_NOSIGNAL);

		if (cb_read <= 0)
			return cb_read;
		cb_total += cb_read;
		cb_buffer -= cb_read;
		pv_buffer = (char *)pv_buffer + cb_read;
	} while (cb_buffer);

	return cb_total;
}

/*
 * Wrapper around recv to read full string packet.
 */
static int
remote_tcp_read_string(int sock, const char *pv_buffer, size_t cb_buffer, int nil_mode)
{
	size_t cb_total = 0;

	do
	{
		ssize_t cb_read = recv(sock, (void*)pv_buffer, cb_buffer, MSG_NOSIGNAL);

		if (cb_read <= 0)
			return cb_read;
		cb_total += cb_read;
		if (!nil_mode && cb_total >= 4)
			return cb_total;
		if (!pv_buffer[cb_read - 1])
			return cb_total;
		cb_buffer -= cb_read;
		pv_buffer = (char *)pv_buffer + cb_read;
	} while (cb_buffer);

	return cb_total;
}

/*
 * Wrapper around send to send full packet.
 */
static int
remote_tcp_write(int sock, const void *pv_buffer, size_t cb_buffer)
{
	do
	{
		size_t cb_now = cb_buffer;
		ssize_t cb_written = send(sock, (const char *)pv_buffer, cb_now, MSG_NOSIGNAL);

		if (cb_written < 0)
			return 1;
		cb_buffer -= cb_written;
		pv_buffer = (char *)pv_buffer + cb_written;
	} while (cb_buffer);

	return 0;
}

/*
 * Wrapper around tcp_write to send a string
 */
static int
remote_tcp_write_string(int sock, const char *pv_buffer)
{
	return remote_tcp_write(sock, pv_buffer, strlen(pv_buffer) + 1);
}


/*
 *  Request that the daemon open a file.
 */
static int
remote_file_open(struct remote_file *rfp)
{
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	char *p1;

	BZERO(sendbuf, BUFSIZE);
	BZERO(recvbuf, BUFSIZE);
       	sprintf(sendbuf, "OPEN %s", rfp->filename);
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());

        if (CRASHDEBUG(1))
                fprintf(fp, "remote_file_open: [%s]\n", recvbuf);

        if (strstr(recvbuf, "O_RDWR") || strstr(recvbuf, "O_RDONLY")) {
                p1 = strtok(recvbuf, " ");  /* OPEN */
                p1 = strtok(NULL, " ");     /* filename */
                p1 = strtok(NULL, " ");     /* fd */
                rfp->fd = atoi(p1);
                p1 = strtok(NULL, " ");     /* flags */
                if (STREQ(p1, "O_RDWR"))
			rfp->flags |= O_RDWR;
		else if (STREQ(p1, "O_RDONLY"))
			rfp->flags |= O_RDONLY;
                p1 = strtok(NULL, " ");     /* size */
		rfp->size = atoi(p1);
		return TRUE;
        } else 
		return FALSE;
}

/*
 *  Request that the daemon close a previously-opened file.
 */
static int
remote_file_close(struct remote_file *rfp)
{
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];

	BZERO(sendbuf, BUFSIZE);
	BZERO(recvbuf, BUFSIZE);
        sprintf(sendbuf, "CLOSE %d", rfp->fd);
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());

	return (strstr(recvbuf, "OK") ? TRUE : FALSE);
}

/*
 *  Get a copy of the daemon machine's /proc/version
 */
static int
remote_proc_version(char *buf)
{
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];

        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);
        sprintf(sendbuf, "PROC_VERSION");
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
        if (STREQ(recvbuf, "<FAIL>")) {
		buf[0] = 0;
                return FALSE;
	}
        strcpy(buf, recvbuf);
	return TRUE;
}

/*
 *  Check that virt_phys_base when accessed via
 *  phys_base - text_start is phys_base.
 */
static int
validate_phys_base(physaddr_t phys_base, physaddr_t text_start, physaddr_t virt_phys_base)
{
        ulong value;

        if (CRASHDEBUG(3))
                fprintf(fp, "validate_phys_base: virt_phys_base=0x%llx phys_base=0x%llx text_start=0x%llx calc=0x%llx\n",
                        (long long unsigned int)virt_phys_base,
			(long long unsigned int)phys_base,
			(long long unsigned int)text_start,
			(long long unsigned int)virt_phys_base + phys_base - text_start);

        if (READMEM(pc->rmfd, (void*)&value, sizeof(value),
		    virt_phys_base, virt_phys_base + phys_base - text_start)
	    == sizeof(value)) {
                if (value == phys_base)
                        return 1;
        }
        return 0;
}

/*
 *  Get remote phys_base based on virtual address of "phys_base".
 */
physaddr_t
get_remote_phys_base(physaddr_t text_start, physaddr_t virt_phys_base)
{
        int vcpu;
        ulong value;

	if (rc->vfd < 0) {
		struct remote_file remote_file, *rfp;

		rfp = &remote_file;
		BZERO(rfp, sizeof(struct remote_file));
		rfp->filename = "/dev/vmem";
		if (remote_file_open(rfp)) {
			rc->vfd = rfp->fd;
		} else
			return 0;
	}

        for (vcpu = 0; vcpu < rc->n_cpus; vcpu++)
                if (remote_memory_read(rc->vfd, (void*)&value, sizeof(value),
				       virt_phys_base, vcpu) == sizeof(value)) {
                        if (validate_phys_base(value, text_start, virt_phys_base))
                                return value;
                }

        return 0;
}

/*
 *  Do a remote VTOP if supported.
 */
physaddr_t
remote_vtop(int cpu, physaddr_t virt_addr)
{
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	char *p1;
	int errflag;
	ulong value;

	if (!rc->remote_type[0])
		return 0;       /* Not a special remote. */

	BZERO(sendbuf, BUFSIZE);
	BZERO(recvbuf, BUFSIZE);
	sprintf(sendbuf, "VTOP %d %llx", cpu, (long long unsigned int)virt_addr);
	remote_tcp_write_string(pc->sockfd, sendbuf);
	remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());

	if (CRASHDEBUG(2))
		fprintf(fp, "remote_vtop: [%s]\n", recvbuf);

	if (strstr(recvbuf, "<FAIL>"))
		error(FATAL, "remote_vtop for CPU %d\n", cpu);
	p1 = strtok(recvbuf, " ");  /* VTOP */
	p1 = strtok(NULL, " ");     /* cpu */
	p1 = strtok(NULL, " ");     /* vaddr */
	p1 = strtok(NULL, " ");     /* paddr */

	errflag = 0;
	value = htol(p1, RETURN_ON_ERROR|QUIET, &errflag);
	if (!errflag) {
		return value;
	}
	return 0;
}

/*
 *  Get a copy of the daemon machine cpu regs.
 */
int
get_remote_regs(struct bt_info *bt, ulong *eip, ulong *esp)
{
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	char *p1, *p2;
	int errflag;
	ulong value;

	if (!rc->remote_type[0])
		return 0;       /* Not a special remote. */

	*eip = 0;
	*esp = 0;

	BZERO(sendbuf, BUFSIZE);
	BZERO(recvbuf, BUFSIZE);
	sprintf(sendbuf, "FETCH_LIVE_IP_SP_BP %d", bt->tc->processor);
	if (remote_tcp_write_string(pc->sockfd, sendbuf))
		return 0;
	errflag = remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
	if (errflag <= 0)
		return 0;

	if (CRASHDEBUG(1))
		fprintf(fp, "get_remote_regs(cpu=%d): [%s]\n",
			bt->tc->processor, recvbuf);

	if (strstr(recvbuf, "<FAIL>")) {
		error(INFO, "get_remote_regs for CPU %d\n", bt->tc->processor);
		return 0;
	}
	p1 = strtok(recvbuf, " ");  /* FETCH_LIVE_IP_SP_BP */
	p1 = strtok(NULL, " ");     /* cpu */
	p1 = strtok(NULL, ":");     /* cs */
	p1 = strtok(NULL, " ");     /* ip */
	p2 = strtok(NULL, ":");     /* ss */
	p2 = strtok(NULL, " ");     /* sp */
	/* p2 = strtok(NULL, " ");     bp */

	errflag = 0;
	value = htol(p1, RETURN_ON_ERROR|QUIET, &errflag);
	if (!errflag) {
		*eip = value;
	}

	errflag = 0;
	value = htol(p2, RETURN_ON_ERROR|QUIET, &errflag);
	if (!errflag) {
		*esp = value;
	}
	return 1;
}

/*
 *  Get a remote cr3 if supported.
 */
physaddr_t
get_remote_cr3(int cpu)
{
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	char *p1;
	int errflag;
	ulong value;

	if (!rc->remote_type[0])
		return 0;       /* Not a special remote. */

	BZERO(sendbuf, BUFSIZE);
	BZERO(recvbuf, BUFSIZE);
	sprintf(sendbuf, "FETCH_LIVE_CR3 %d", cpu);
	if (remote_tcp_write_string(pc->sockfd, sendbuf))
		return 0;
	remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());

	if (CRASHDEBUG(1))
		fprintf(fp, "get_remote_cr3: [%s]\n", recvbuf);

	if (strstr(recvbuf, "<FAIL>"))
		error(FATAL, "get_remote_cr3 for CPU %d\n", cpu);
	p1 = strtok(recvbuf, " ");  /* FETCH_LIVE_CR3 */
	p1 = strtok(NULL, " ");     /* cpu */
	p1 = strtok(NULL, " ");     /* cr3 */

	errflag = 0;
	value = htol(p1, RETURN_ON_ERROR|QUIET, &errflag);
	if (!errflag)
		return value;
	return 0;
}


/*
 *
 *   Set up the file descriptors and file name strings if they haven't
 *   been set up before:
 *
 *   1. pc->namelist must be set to a local kernel namelist, which will be 
 *      copied from the remote machine if it was not specified.
 *
 *   2. pc->dumpfile will never be set for a remote operation, because there
 *      is no difference to readmem().
 *
 *   3. pc->server_namelist may be set if it has to be copied across.
 *
 *   4. pc->server_memsrc will be set to either /dev/mem or the dumpfile.
 */
void
remote_fd_init(void)
{
	char filename[BUFSIZE];
	struct remote_file remote_file, *rfp;

	rfp = &remote_file;

	if (pc->namelist && pc->server_namelist) {
		error(INFO, "too many namelists\n");
		program_usage(SHORT_FORM);
	}

	if ((pc->namelist || pc->server_namelist) &&
             pc->namelist_debug && pc->system_map) {
                        error(INFO,
              "too many namelist options:\n       %s\n       %s\n       %s\n",
                                pc->namelist ? 
				pc->namelist : pc->server_namelist, 
				pc->namelist_debug,
                                pc->system_map);
		program_usage(SHORT_FORM);
	}

	/*
	 *  Account for the remote possibility of a local dumpfile 
	 *  being entered on the command line.
	 */
        if (pc->flags & MEMORY_SOURCES) {
		if (pc->server_memsrc) {
                	error(INFO, "too many dumpfile/memory arguments\n");
			program_usage(SHORT_FORM);
		}
		pc->flags2 |= MEMSRC_LOCAL;
		if (pc->flags & (DEVMEM|MEMMOD)) {
			if (!get_proc_version())
                        	error(INFO, "/proc/version: %s\n", 
					strerror(errno));
        		pc->flags |= LIVE_SYSTEM;  
		}
	} else {
        	/*
         	 *  First open the remote memory source, defaulting to /dev/mem
         	 *  if no remote dumpfile name was entered.  If it is /dev/mem,
         	 *  then also go get the remote /proc/version.
         	 */
		pc->readmem = read_daemon;

		if (!pc->server_memsrc) 
			pc->server_memsrc = "/dev/mem";
	
		if (STREQ(pc->server_memsrc, "/dev/mem"))
			pc->flags |= REM_LIVE_SYSTEM;
	
		BZERO(rfp, sizeof(struct remote_file));
	       	rfp->filename = pc->server_memsrc;

	       	if (remote_file_open(rfp)) {
	               	pc->rmfd = rfp->fd;
	               	if (rfp->flags & O_RDWR)
	                       	pc->flags |= MFD_RDWR;

	               	if (BITS32() && REMOTE_ACTIVE()) {
	                       	BZERO(rfp, sizeof(struct remote_file));
	                       	rfp->filename = "/dev/kmem";
	                       	if (remote_file_open(rfp))
	                               	pc->rkfd = rfp->fd;
	               	}

                        if ((pc->flags & REM_NETDUMP) &&
                            !remote_netdump_init())
                                error(FATAL,
                                    "%s: remote initialization failed\n",
                                        pc->server_memsrc);

			if ((pc->flags & REM_LKCD) &&
			    !remote_lkcd_dump_init())
                               	error(FATAL, 
				    "%s: remote initialization failed\n",
                                       	pc->server_memsrc);

                        if ((pc->flags & REM_S390D) &&
                            !remote_s390_dump_init())
                                error(FATAL,
                                    "%s: remote initialization failed\n",
                                        pc->server_memsrc);

			if (REMOTE_DUMPFILE())
				pc->writemem = write_daemon;

	       	} else
	               	error(FATAL, "cannot open remote memory source: %s\n",
	                       	pc->server_memsrc);
	
	       	if (REMOTE_ACTIVE() && !remote_proc_version(kt->proc_version))
	       		error(WARNING, 
				"daemon cannot access /proc/version\n\n");
	}

	/*
	 *  If a local namelist was entered, check whether it's readable.  
         *  If a server namelist was entered, copy it across.
         *  If no server namelist was entered, query the daemon for it,
         *  and if found, copy it across,
         */
	if (pc->namelist) {
        	if ((pc->nfd = open(pc->namelist, O_RDONLY)) < 0)
                	error(FATAL, "%s: %s\n", pc->namelist, strerror(errno));
               	close(pc->nfd);
               	pc->nfd = -1;
		pc->flags |= NAMELIST_LOCAL;
	} else if (pc->server_namelist) {
        	BZERO(rfp, sizeof(struct remote_file));
        	rfp->filename = pc->server_namelist;
		if (!remote_file_open(rfp)) {
			error(FATAL, "daemon cannot open: %s\n",
				pc->server_namelist);
		}
		copy_to_local_namelist(rfp);
		remote_file_close(rfp);
	} else {
        	BZERO(rfp, sizeof(struct remote_file));
		BZERO(filename, BUFSIZE);
		rfp->filename = filename;
		if (!remote_find_booted_kernel(rfp)) 
			error(FATAL, 
			    "remote daemon cannot find booted kernel\n");
		if (!remote_file_open(rfp))
			error(FATAL, "remote daemon cannot open: %s\n",
				pc->server_namelist);
		copy_to_local_namelist(rfp);
		remote_file_close(rfp);
	}

	if (REMOTE_ACTIVE()) 
        	pc->flags |= LIVE_SYSTEM;  
}

/*
 *  Copy a remote kernel to a local file, which gets unlinked in the normal
 *  course of events.  However, the pc->nfd file descriptor will be kept 
 *  alive in case there's a command put in place to keep the file around.
 */
static void
copy_to_local_namelist(struct remote_file *rfp)
{
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	char readbuf[READBUFSIZE];
	int tty;

	if (pc->flags & KERNEL_DEBUG_QUERY) {
		/*
		 *  Don't bother copying the kernel if the daemon can
		 *  figure it out.
		 */
        	BZERO(sendbuf, BUFSIZE);
        	BZERO(recvbuf, BUFSIZE);
        	sprintf(sendbuf, "DEBUGGING_SYMBOLS %s", rfp->filename);
		remote_tcp_write_string(pc->sockfd, sendbuf);
		remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
		if (strstr(recvbuf, "NO_DEBUG")) {
			sprintf(readbuf, "%s@%s", rfp->filename, pc->server);
			pc->namelist = readbuf;
			no_debugging_data(FATAL);
		}
	}

	pc->namelist = create_local_namelist(rfp);

	if (pc->flags & NAMELIST_LOCAL)
		return;

	if ((pc->nfd = open(pc->namelist, 
	     O_RDWR|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
		pc->flags &= ~UNLINK_NAMELIST;
		error(FATAL, "cannot create local copy of kernel (%s)\n",
			pc->namelist);
	}

	tty = !(pc->flags & SILENT) && isatty(fileno(stdin));

	if (!(pc->flags & NAMELIST_NO_GZIP)) {
		copy_remote_gzip_file(rfp, pc->namelist, tty ?
		    "please wait... (copying remote kernel namelist: " : NULL);
        	if (tty) 
			fprintf(stderr, 
            "\r                                                           \r");
		return;
	}

        if (copy_remote_file(rfp, pc->nfd, pc->namelist,
	    tty ?  "please wait... (copying remote kernel namelist: " : NULL)) {
        	if (tty) 
			fprintf(stderr, 
            "\r                                                           \r");
        } else 
		error(FATAL, "write to local copy of kernel namelist failed\n");
}

/*
 *  Try to create a file of the format: vmlinux@@hostname
 *  If it already exists, append "_0", "_1", etc. until one's not found.
 *
 *  The file will be unlinked by display_sys_stats() the first time it's
 *  called.
 */

static char *
create_local_namelist(struct remote_file *rfp)
{
	char buf[BUFSIZE];
	char *p1;
	int i, use_local_copy;

	p1 = (char *)basename(rfp->filename);

	sprintf(buf, "%s@%s", p1, pc->server);
	for (i = 0, use_local_copy = FALSE; i >= 0; i++) {
		if (file_exists(buf, NULL)) {
			if (identical_namelist(buf, rfp)) {
				use_local_copy = TRUE;
				break;
			}
			sprintf(buf, "%s@%s_%d", p1,pc->server, i);
		} else
			break;
	}

	if ((p1 = (char *)malloc((size_t)(strlen(buf)+1))) == NULL) 
		error(FATAL, "cannot malloc temporary file name buffer\n");

	strcpy(p1, buf);

	if (use_local_copy) 
		pc->flags |= NAMELIST_LOCAL;
	else
		pc->flags |= UNLINK_NAMELIST;

	return p1;
}

/*
 *  Before copying a kernel across, check whether a kernel of the same
 *  name is identical to the remote version.
 */
static int
identical_namelist(char *file, struct remote_file *rfp)
{
	char *vers;
	FILE *pipe;
	struct stat sbuf;
	long csum;
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	char readbuf[BUFSIZE*2];

	if (stat(file, &sbuf) < 0)
		return FALSE;

	if (sbuf.st_size != rfp->size) 
		return FALSE;

	if (remote_file_checksum(rfp) && file_checksum(file, &csum) &&
	    (csum == rfp->csum))
		return TRUE;

        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);
        BZERO(readbuf, BUFSIZE);

        sprintf(sendbuf, "LINUX_VERSION %s", rfp->filename);
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
        if (strstr(recvbuf, "<FAIL>")) 
		return FALSE;

        vers = recvbuf;

        sprintf(readbuf, "/usr/bin/strings %s | grep 'Linux version'", 
		file);
        if ((pipe = popen(readbuf, "r"))) {
        	BZERO(readbuf, BUFSIZE);
                if (fread(readbuf, sizeof(char), BUFSIZE-1, pipe) <= 0) {
			pclose(pipe);
			return FALSE;
		}
                pclose(pipe);
	} else
		return FALSE;

	if (CRASHDEBUG(1)) {
		fprintf(fp, "remote version: [%s]\n", vers);
		fprintf(fp, "local version: [%s]\n", readbuf);
		fprintf(fp, "%s vs. %s => %s\n",
			file, rfp->filename,
			STREQ(vers, readbuf) ? "IDENTICAL" : "DIFFERENT");
	}

	return (STREQ(vers, readbuf));
}

/*
 *  If a remote file exists, get its checksum and return TRUE.
 */
static int
remote_file_checksum(struct remote_file *rfp)
{
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	char *p1;

        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);
        sprintf(sendbuf, "SUM %s", rfp->filename);
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
        if (strstr(recvbuf, "<FAIL>")) {
                error(INFO, "%s: does not exist on server %s\n",
                        rfp->filename, pc->server);
                return FALSE;
        }
        strtok(recvbuf, " ");         /* SUM */
        p1 = strtok(NULL, " ");       /* filename */
        p1 = strtok(NULL, " ");       /* checksum */

        rfp->csum = htol(p1, FAULT_ON_ERROR, NULL);
	return TRUE;
}

/*
 *  Copy a remote file locally, distinguishing it by appending an ampersand
 *  and the server name.
 *
 *  If the kernel is requested, save the unlinked copy of the remote kernel
 *  in a local file, using the same name created by create_local_namelist(). 
 *
 *  If a dumpfile, module, or any other file for that matter, append an
 *  ampersand plus the server name.
 *
 *  Other files may have their local filename altered if a file of the
 *  same name exists with a different checksum.
 */
int
get_remote_file(struct remote_file *rfp)
{
	int i;
	char local[BUFSIZE];
	char readbuf[READBUFSIZE];
	char *p1;
	struct load_module *lm;
	int cnt, sfd, err, retval;
	long csum;

	if (!REMOTE()) {
		error(INFO, "no remote files in use\n");
		return FALSE;
	}

	if (rfp->local)
		goto generic_file_save;

	sprintf(readbuf, "%s@%s", pc->server_memsrc, pc->server);
	if (STREQ(rfp->filename, "dumpfile") || 
	    STREQ(rfp->filename, pc->server_memsrc) ||
	    STREQ(rfp->filename, basename(pc->server_memsrc)) ||
	    STREQ(rfp->filename, readbuf)) 
		goto dumpfile_save;

	sprintf(readbuf, "%s", pc->namelist);
	if ((p1 = strstr(readbuf, "@")))
		*p1 = NULLCHAR;
	if (STREQ(rfp->filename, "kernel") ||
	    STREQ(rfp->filename, pc->namelist) ||
	    STREQ(rfp->filename, pc->server_namelist) ||
	    STREQ(rfp->filename, readbuf))
		goto kernel_save;


	if (STREQ(rfp->filename, "modules")) {
        	for (i = 0; i < kt->mods_installed; i++) {
                	lm = &st->load_modules[i];
                	if (lm->mod_flags & MOD_REMOTE) {
				fprintf(fp, "%s module saved as: %s\n",
					lm->mod_name, lm->mod_namelist);
				lm->mod_flags &= ~MOD_REMOTE;
			}
        	}
		return TRUE;
	}

	if (is_module_name(rfp->filename, NULL, &lm)) {
                if (lm->mod_flags & MOD_REMOTE) {
                        fprintf(fp, "%s module saved as: %s\n",
                               lm->mod_name, lm->mod_namelist);
			lm->mod_flags &= ~MOD_REMOTE;
                }
		return TRUE;
	}

	strcpy(local, rfp->filename);
	if ((p1 = strstr(local, ".o"))) {
		*p1 = NULLCHAR;
		if (is_module_name(basename(local), NULL, &lm)) {
                	if (lm->mod_flags & MOD_REMOTE) {
                        	fprintf(fp, "%s module saved as: %s\n",
                               		lm->mod_name, lm->mod_namelist);
				lm->mod_flags &= ~MOD_REMOTE;
				return TRUE;
			}
		}
	}

generic_file_save:

	cnt = 0;
	sprintf(local, "%s@%s", basename(rfp->filename), pc->server);
        while (file_exists(local, NULL)) {
		if (CRASHDEBUG(1))
                	fprintf(fp, "%s already exists in this directory\n",
                        	local);
		if (file_checksum(local, &csum) && (csum == rfp->csum)) {
			if (CRASHDEBUG(1))
				error(NOTE, 
			    	    "local %s checksum matches -- using it\n",
					local);
			strcpy(rfp->local, local);
			return TRUE;
		}
		sprintf(local, "%s@%s_%d", 
			basename(rfp->filename), pc->server, ++cnt);
	}

        if (!remote_file_open(rfp)) {
                error(INFO, "daemon cannot open: %s\n", rfp->filename);
		return FALSE;
	}

        if ((sfd = open(local, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
                error(INFO, "open: %s: %s\n", local, strerror(errno));
                remote_file_close(rfp);
                return FALSE;
        }

        if (copy_remote_file(rfp, sfd, local, rfp->flags & REMOTE_VERBOSE ?
	    "please wait... (copying remote file: " : NULL)) {
		if (rfp->flags & REMOTE_VERBOSE)
                	fprintf(stderr,
             "\rremote file saved as: \"%s\"                                \n",
                        local);
		retval = TRUE;
		rfp->flags |= REMOTE_COPY_DONE;
        } else {
                fprintf(stderr,
                "\r%s NOT saved                                             \n",
                        rfp->filename);
		retval = FALSE;
        }

        close(sfd);
        remote_file_close(rfp);

	if (cnt)
		strcpy(rfp->local, local);

	return retval;

kernel_save: 

	if (pc->flags & NAMELIST_SAVED) {
		error(INFO, "\"%s\" is already saved\n", pc->namelist);
		return FALSE;
	}

	if (pc->flags & NAMELIST_LOCAL) {
		error(INFO, "\"%s\" is a local file\n", pc->namelist);
		return FALSE;
	}

	if ((sfd = open(pc->namelist, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
		error(INFO, "open: %s: %s\n", pc->namelist, strerror(errno));
		return FALSE;
	}

	err = 0;
        lseek(sfd, 0, SEEK_SET);
        lseek(pc->nfd, 0, SEEK_SET);

	while ((cnt = read(pc->nfd, readbuf, READBUFSIZE)) > 0) {
		if (write(sfd, readbuf, cnt) != cnt) {
			error(INFO, "write:%s: %s\n", 
				pc->namelist, strerror(errno));
			err++;
			break;
		}
	}

	close(sfd);

	if (err) {
		fprintf(fp, "%s NOT saved\n", pc->namelist);
		unlink(pc->namelist);
		retval = FALSE;
	} else {
		fprintf(fp, "kernel saved as: \"%s\"\n", pc->namelist);
		close(pc->nfd);
		pc->nfd = -1;
		pc->flags |= NAMELIST_SAVED;
		retval = TRUE;
	}

	return (retval);

dumpfile_save:

        if (pc->flags & DUMPFILE_SAVED) {
                error(INFO, "\"%s@%s\" is already saved\n", 
			basename(pc->server_memsrc), pc->server);
		return FALSE;
	}

        if (pc->flags2 & MEMSRC_LOCAL) {
                error(INFO, "%s is a local file\n", pc->dumpfile);
		return FALSE;
	}

	if (!(REMOTE_DUMPFILE())) {
                error(INFO, "%s is not a dumpfile\n", pc->server_memsrc);
		return FALSE;
	}

	sprintf(local, "%s@%s", basename(pc->server_memsrc), pc->server);

	if (file_exists(local, NULL)) {
		error(INFO, "%s already exists in this directory\n",
			local);
		return FALSE;
	}

        rfp->filename = pc->server_memsrc;
        if (!remote_file_open(rfp)) {
                error(INFO, "daemon cannot open: %s\n", pc->server_memsrc);
		return FALSE;
	}

        if ((sfd = open(local, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
                error(INFO, "open: %s: %s\n", local, strerror(errno));
		remote_file_close(rfp);
                return FALSE;
        }

	if (copy_remote_file(rfp, sfd, local, 
	    "please wait... (copying remote dumpfile: ")) {
                fprintf(stderr, 
		"\rdumpfile saved as: \"%s\"                                \n",
			local);
                pc->flags |= DUMPFILE_SAVED;
		retval = TRUE;
	} else {
                fprintf(stderr, 
		"\r%s NOT saved                                             \n",
			pc->server_memsrc);
		retval = FALSE;
	}
	
	close(sfd);
        remote_file_close(rfp);

	return (retval);

}

/*
 *  Query the remote daemon for the kernel name that is running.
 */
static int 
remote_find_booted_kernel(struct remote_file *rfp)
{
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	char *p1;

        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);
        sprintf(sendbuf, "FIND_BOOTED_KERNEL");
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
        strtok(recvbuf, " ");           /* FIND_BOOTED_KERNEL */
        p1 = strtok(NULL, " ");         /* filename */
        if (STREQ(p1, "<FAIL>"))
		return FALSE;
	strcpy(rfp->filename, p1);

	return TRUE;
}

static int
remote_lkcd_dump_init(void)
{
        char sendbuf[BUFSIZE];
        char recvbuf[BUFSIZE];
        char *p1, *p2, *p3;

        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);
        sprintf(sendbuf, "LKCD_DUMP_INIT %d %s", pc->rmfd, pc->server_memsrc);
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
        if (strstr(recvbuf, "<FAIL>"))
                return FALSE;

	p1 = strstr(recvbuf, "panic_task: "); 
	p2 = strstr(recvbuf, "panicmsg: "); 

	if (p1) {
		p1 += strlen("panic_task: ");
		p3 = strstr(p1, "\n");
		*p3 = NULLCHAR;
		tt->panic_task = htol(p1, FAULT_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "panic_task: %lx\n", tt->panic_task);
	}
	if (p2) {
		p2 += strlen("panicmsg: ");
		if (CRASHDEBUG(1))
			fprintf(fp, "panicmsg: %s", p2);
	}

	set_remote_lkcd_panic_data(tt->panic_task, p2);

        return TRUE;
}


static int
remote_s390_dump_init(void)
{
        char sendbuf[BUFSIZE];
        char recvbuf[BUFSIZE];
        char *p1, *p2, *p3;

        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);
        sprintf(sendbuf, "S390_DUMP_INIT %d %s", pc->rmfd, pc->server_memsrc);
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
        if (strstr(recvbuf, "<FAIL>"))
                return FALSE;

	p1 = strstr(recvbuf, "panic_task: "); 
	p2 = strstr(recvbuf, "panicmsg: "); 

	if (p1) {
		p1 += strlen("panic_task: ");
		p3 = strstr(p1, "\n");
		*p3 = NULLCHAR;
		tt->panic_task = htol(p1, FAULT_ON_ERROR, NULL);
		if (CRASHDEBUG(1))
			fprintf(fp, "panic_task: %lx\n", tt->panic_task);
	}
	if (p2) {
		p2 += strlen("panicmsg: ");
		if (CRASHDEBUG(1))
			fprintf(fp, "panicmsg: %s", p2);
	}

        return TRUE;
}

static int
remote_netdump_init(void)
{
        char sendbuf[BUFSIZE];
        char recvbuf[BUFSIZE];
        char *p1, *p2;
	ulong panic_task;

        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);
        sprintf(sendbuf, "NETDUMP_INIT %d %s", pc->rmfd, pc->server_memsrc);
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
        if (strstr(recvbuf, "<FAIL>"))
                return FALSE;

        p1 = strstr(recvbuf, "panic_task: ");

        if (p1) {
                p1 += strlen("panic_task: ");
                p2 = strstr(p1, "\n");
                *p2 = NULLCHAR;
                panic_task = htol(p1, FAULT_ON_ERROR, NULL);
		tt->panic_task = panic_task;  /*  kludge */
                if (CRASHDEBUG(1))
                        fprintf(fp, "panic_task: %lx\n", tt->panic_task);
        }

        return TRUE;
}

uint
remote_page_size(void)
{
        char sendbuf[BUFSIZE];
        char recvbuf[BUFSIZE];
        char *p1, *p2, *p3;
	uint psz;

        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);

	if (REMOTE_ACTIVE())
        	sprintf(sendbuf, "PAGESIZE LIVE");
	else if (REMOTE_PAUSED())
		sprintf(sendbuf, "PAGESIZE NIL");
	else if (pc->flags & REM_NETDUMP)
        	sprintf(sendbuf, "PAGESIZE NETDUMP");
	else if (pc->flags & REM_MCLXCD)
        	sprintf(sendbuf, "PAGESIZE MCLXCD");
	else if (pc->flags & REM_LKCD)
        	sprintf(sendbuf, "PAGESIZE LKCD");
        else if (pc->flags & REM_S390D)
                sprintf(sendbuf, "PAGESIZE S390D");
	else 
                error(FATAL, 
		 "cannot determine remote page size (unknown memory source)\n");

        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
        if (strstr(recvbuf, "FAIL"))
                error(FATAL, "cannot determine remote page size\n");
        strtok(recvbuf, " ");           /* PAGESIZE */
        p1 = strtok(NULL, " ");         /* LIVE, MCLXCD or LKCD */
        p1 = strtok(NULL, " ");         /* page size */
        p2 = strtok(NULL, " ");         /* remote type */
        p3 = strtok(NULL, " ");         /* number of Cpus */
	psz = atoi(p1);

	if (psz > MAXRECVBUFSIZE)
		error(FATAL, 
		   "remote page size %d is larger than MAXRECVBUFSIZE!\n", psz);

        if (p2) {
                strncpy(rc->remote_type, p2, sizeof(rc->remote_type) - 1);
                rc->remote_type[sizeof(rc->remote_type) - 1] = 0;
        }
        if (p3)
                rc->n_cpus = atoi(p3);

	return psz;
}

/*
 *  Copy a remote file to a local file, closing the passed-in fd when done.
 *  A running tally of percentage-done numbers can  optionally be displayed.
 */
static int
copy_remote_file(struct remote_file *rfp, int fd, char *file, char *ttystr)
{
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE*2];
	char readbuf[READBUFSIZE];
	char *bufptr;
	long pct, last;
        ulong size, offset, filesize;
        ulong ret, req, tot;
	int sysret ATTRIBUTE_UNUSED;
	ssize_t bytes ATTRIBUTE_UNUSED;

	last = -1;
	lseek(fd, 0, SEEK_SET);
	filesize = rfp->size;

	for (offset = 0; offset < filesize; ) {

		size = MIN(filesize-offset, pc->rcvbufsize); 
		
		BZERO(sendbuf, BUFSIZE);
        	sprintf(sendbuf, "READ %d %lx %ld", rfp->fd, offset, size);
		bytes = write(pc->sockfd, sendbuf, strlen(sendbuf) + 1);

        	bzero(readbuf, READBUFSIZE);

        	req = size;
        	tot = 0;

        	sprintf(recvbuf, "%s:FAIL", sendbuf);
        	bufptr = readbuf;
        	while (req) {
                	ret = recv(pc->sockfd, bufptr, req, 0);
                	if (!tot && STRNEQ(bufptr, recvbuf)) {
                        	tot = -1;
                        	break;
                	}
                	req -= ret;
                	tot += ret;
                	bufptr += ret;
        	}

		if (tot == -1)
			break;

		if (write(fd, readbuf, size) != size) {
			error(INFO, 
			    "%swrite to local file \"%s\" failed", 
				ttystr ? "\n" : "", file);
			close(fd);
			return FALSE;
		}

		offset += tot;

		if (ttystr) {
			pct = (offset*100)/filesize;  

			if (pct > last) {         /* readline work-around... */
				if (last < 0) 
					sprintf(readbuf, "echo -n \'%s0%%)\'", 
						ttystr);
				else if (last >= 0 && last < 10) 
                                    	sprintf(readbuf,
                                	    "echo -e -n \"\\b\\b\\b%ld%%)\"", 
						pct);
				else if (last < 100) 
                                    	sprintf(readbuf,
                                	    "echo -e -n \"\\b\\b\\b\\b%ld%%)\"",
					        pct);
                               	sysret = system(readbuf);
				last = pct;
			}
		}
	}

	if (offset != filesize) {
		error(INFO, "%swrite to local file \"%s\" failed", 
			ttystr ? "\n" : "", file);
		close(fd);
		return FALSE;
	}

	fsync(fd);

	return TRUE;
}


/*
 *  Copy a remote file to a local file, closing the passed-in fd when done.
 *  A running tally of percentage-done numbers can  optionally be displayed.
 */

static void 
copy_remote_gzip_file(struct remote_file *rfp, char *file, char *ttystr)
{
        int done;
        char sendbuf[BUFSIZE];
        char readbuf[READBUFSIZE];
	char gziphdr[DATA_HDRSIZE];
        char *bufptr, *p1;
	FILE *pipe;
	size_t gtot;
	struct stat sbuf;
        ulong pct, ret, req, tot, total;

	sprintf(readbuf, "/usr/bin/gunzip > %s", pc->namelist);
        if ((pipe = popen(readbuf, "w")) == NULL)
		error(FATAL, "cannot open pipe to create %s\n", pc->namelist);

        BZERO(sendbuf, BUFSIZE);
        sprintf(sendbuf, "READ_GZIP %ld %s", pc->rcvbufsize, rfp->filename);
        remote_tcp_write_string(pc->sockfd, sendbuf);

       	bzero(readbuf, READBUFSIZE);

	done = total = 0;
	gtot = 0;

	while (!done) {

		req = pc->rcvbufsize; 
		bufptr = readbuf;
		tot = 0;

                while (req) {
                        ret = (ulong)recv(pc->sockfd, bufptr, req, 0); 
                        if (!tot) {
				if (STRNEQ(bufptr, FAILMSG)) {
					fprintf(fp, 
					    "copy_remote_gzip_file: %s\n",
						bufptr);
                                	tot = -1;
                                	break;
				}
				if (STRNEQ(bufptr, DONEMSG) ||
				    STRNEQ(bufptr, DATAMSG)) {
					BCOPY(bufptr, gziphdr, DATA_HDRSIZE);
					if (CRASHDEBUG(1))
						fprintf(fp, 
				                "copy_remote_gzip_file: [%s]\n",
							gziphdr);
                        		p1 = strtok(gziphdr, " "); /* DONE */
					if (STREQ(p1, "DONE"))
						done = TRUE;
                        		p1 = strtok(NULL, " ");     /* count */
					gtot = atol(p1);
					total += gtot;
				}
                        } 
                        req -= ret;
                        tot += ret;
                        bufptr += ret;
                }

                if (tot == -1)
                        break;

		if (fwrite(&readbuf[DATA_HDRSIZE], sizeof(char), gtot, pipe) 
		    != gtot) 
			error(FATAL, "fwrite to %s failed\n", pc->namelist);

		if (ttystr && (stat(pc->namelist, &sbuf) == 0)) {
			pct = (sbuf.st_size * 100)/rfp->size;
			fprintf(stderr, "\r%s%ld%%)%s", 
				ttystr, pct, CRASHDEBUG(1) ? "\n" : "");
		}
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "copy_remote_gzip_file: GZIP total: %ld\n", total);

	pclose(pipe);
}

/*
 *  Set up to have get_remote_file() copy the remote module locally.
 *  If it's already here, no copy is done.
 */
int
find_remote_module_objfile(struct load_module *lm, char *module, char *retbuf)
{
	int absolute;
	char sendbuf[BUFSIZE];
	char recvbuf[BUFSIZE];
	char local[BUFSIZE];
	char found[BUFSIZE];
	char *p1;
	long csum;
	struct remote_file remote_file, *rfp;

	rfp = &remote_file;
	BZERO(rfp, sizeof(struct remote_file));

	absolute = (*module == '/');

	if (absolute) {
		if ((p1 = strstr(module, "@"))) {
			*p1 = NULLCHAR;
		} else {
			error(FATAL, 
		      "module file name must have \"@server-name\" attached\n");
		}

		sprintf(local, "%s@%s", basename(module), pc->server);
		rfp->filename = module;
		rfp->local = local;

		if (!remote_file_checksum(rfp)) {
                	error(INFO, "%s: does not exist on server %s\n", 
				module, pc->server);
                	return FALSE;
        	}
	} else { 
		if ((p1 = strstr(module, "@")))
			*p1 = NULLCHAR;
	
		sprintf(local, "%s@%s", module, pc->server);
	
	        BZERO(sendbuf, BUFSIZE);
	        BZERO(recvbuf, BUFSIZE);
	        sprintf(sendbuf, "FIND_MODULE %s %s",
	                kt->utsname.release, module);
	        remote_tcp_write_string(pc->sockfd, sendbuf);
	        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
	        if (strstr(recvbuf, "<FAIL>")) {
			fprintf(fp, "find_remote_module_objfile: [%s]\n", 
				recvbuf);
	                return FALSE;
		}
	        strtok(recvbuf, " ");               /* FIND_MODULE */
	        p1 = strtok(NULL, " ");             /* release */
	        p1 = strtok(NULL, " ");             /* module */
	        strcpy(found, strtok(NULL, " "));   /* resultant path */
	        p1 = strtok(NULL, " ");             /* checksum */
		csum = htol(p1, FAULT_ON_ERROR, NULL);
	
		rfp->filename = found;
		rfp->local = local;
		rfp->csum = csum;
	}

	if (get_remote_file(rfp)) {
                if (!is_elf_file(rfp->local)) {
                	error(INFO, 
                        	"%s@%s: not an ELF format object file\n",
                                        rfp->filename, pc->server);
			return FALSE;
                }
                strcpy(retbuf, rfp->local);
		if (rfp->flags & REMOTE_COPY_DONE) {
			lm->mod_flags |= MOD_REMOTE;
			pc->flags |= UNLINK_MODULES;
		}
                return TRUE;
        }

	return FALSE;
}

/*
 *  Tell the daemon to free the current dumpfile memory.
 */
int 
remote_free_memory(void)
{
        char sendbuf[BUFSIZE];
        char recvbuf[BUFSIZE];
        char *type, *p1;

	if (pc->flags & REM_NETDUMP)
		type = "NETDUMP";
	else if (pc->flags & REM_MCLXCD)
		type = "MCLXCD";
	else if (pc->flags & REM_LKCD)
		type = "LKCD";
        else if (pc->flags & REM_S390D)
                type = "S390D";
	else
		return 0;

        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);
        sprintf(sendbuf, "MEMORY FREE %s", type);
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
        p1 = strtok(recvbuf, " ");      /* MEMORY */
        p1 = strtok(NULL, " ");         /* FREE */
        p1 = strtok(NULL, " ");         /* MCLXCD, LKCD etc. */
        p1 = strtok(NULL, " ");         /* pages */
        if (STREQ(p1, "<FAIL>"))
                return 0;

        return(atol(p1));
}

/*
 *  Return the number of dumpfile pages used by the daemon.
 */
int
remote_memory_used(void)
{
        char sendbuf[BUFSIZE];
        char recvbuf[BUFSIZE];
        char *type, *p1;

        if (pc->flags & REM_NETDUMP)
                type = "NETDUMP";
        else if (pc->flags & REM_MCLXCD)
                type = "MCLXCD";
        else if (pc->flags & REM_LKCD)
                type = "LKCD";
        else if (pc->flags & REM_S390D)
                type = "S390D";
        else
                return 0;

        BZERO(sendbuf, BUFSIZE);
        BZERO(recvbuf, BUFSIZE);
        sprintf(sendbuf, "MEMORY USED %s", type);
        remote_tcp_write_string(pc->sockfd, sendbuf);
        remote_tcp_read_string(pc->sockfd, recvbuf, BUFSIZE-1, NIL_MODE());
        p1 = strtok(recvbuf, " ");          /* MEMORY */
        p1 = strtok(NULL, " ");             /* FREE */
        p1 = strtok(NULL, " ");             /* MCLXCD, LKCD, etc. */
        p1 = strtok(NULL, " ");             /* pages */
        if (STREQ(p1, "<FAIL>"))
                return 0;

        return(atol(p1));
}

/*
 *  Have the daemon return the output of vas_memory_dump(), lkcd_memory_dump().
 *  or dump_lkcd_environment()
 */
int 
remote_memory_dump(int verbose)
{
        char sendbuf[BUFSIZE];
        char readbuf[READBUFSIZE];
	char datahdr[DATA_HDRSIZE];
        char *type, *bufptr, *p1;
	ulong done, total;
	ulong ret, req, tot;
	size_t dtot;

        if (pc->flags & REM_NETDUMP)
                type = "NETDUMP";
        else if (pc->flags & REM_MCLXCD)
                type = "MCLXCD";
        else if (pc->flags & REM_LKCD)
                type = "LKCD";
        else if (pc->flags & REM_S390D)
                type = "S390D";
        else
                return 0;

        BZERO(sendbuf, BUFSIZE);
        sprintf(sendbuf, "MEMORY_DUMP %ld %s%s", pc->rcvbufsize, type,
		verbose ? "_VERBOSE" : "");
        remote_tcp_write_string(pc->sockfd, sendbuf);

       	bzero(readbuf, READBUFSIZE);
	done = total = 0;
	dtot = 0;

	while (!done) {

		req = pc->rcvbufsize;
		bufptr = readbuf;
		tot = 0;

                while (req) {
                        ret = recv(pc->sockfd, bufptr, req, 0); 
                        if (!tot) {
				if (STRNEQ(bufptr, FAILMSG)) {
					fprintf(fp, 
					    "remote_memory_dump: %s\n",
						bufptr);
                                	tot = -1;
                                	break;
				}
				if (STRNEQ(bufptr, DONEMSG) ||
				    STRNEQ(bufptr, DATAMSG)) {
					BCOPY(bufptr, datahdr, DATA_HDRSIZE);
					if (CRASHDEBUG(1))
						fprintf(fp, 
					        "remote_memory_dump: [%s]\n",
							datahdr);
                        		p1 = strtok(datahdr, " "); /* DONE */
					if (STREQ(p1, "DONE"))
						done = TRUE;
                        		p1 = strtok(NULL, " ");     /* count */
					dtot = atol(p1);
					total += dtot;
				}
                        }
                        req -= ret;
                        tot += ret;
                        bufptr += ret;
                }

                if (tot == -1)
                        break;

		if (fwrite(&readbuf[DATA_HDRSIZE], sizeof(char), dtot, fp) 
		    != dtot) 
			error(FATAL, "fwrite to %s failed\n", pc->namelist);
	}

	return 1;
}

/*
 *  Read memory from the remote memory source.  The remote file descriptor
 *  is abstracted to allow for a common /dev/mem-/dev/kmem call.  Since
 *  this is only called from read_daemon(), the request can never exceed
 *  a page in length.
 */
int 
remote_memory_read(int rfd, char *buffer, int cnt, physaddr_t address, int vcpu)
{
        char sendbuf[BUFSIZE];
	char datahdr[DATA_HDRSIZE];
	char *p1;
	int ret, tot;
	ulong addr;

	addr = (ulong)address;  /* may be virtual */

        BZERO(sendbuf, BUFSIZE);
        if (pc->flags & REM_NETDUMP) {
                sprintf(sendbuf, "READ_NETDUMP %lx %d", addr, cnt);
        } else if (pc->flags & REM_MCLXCD)
                sprintf(sendbuf, "READ_MCLXCD %lx %d", addr, cnt);
        else if (pc->flags & REM_LKCD)
                sprintf(sendbuf, "READ_LKCD %d %lx %d", rfd, addr, cnt);
        else if (pc->flags & REM_S390D)
                sprintf(sendbuf, "READ_S390D %d %lx %d", rfd, addr, cnt);
        else if (vcpu >= 0)
                sprintf(sendbuf, "READ_LIVE %d %lx %d %d", rfd, addr, cnt, vcpu);
        else
                sprintf(sendbuf, "READ_LIVE %d %lx %d", rfd, addr, cnt);

	if (remote_tcp_write_string(pc->sockfd, sendbuf))
		return -1;

	/*
	 *  Read request will come back with a singular header 
	 *  followed by the data.
         */
        BZERO(datahdr, DATA_HDRSIZE);
	ret = remote_tcp_read_string(pc->sockfd, datahdr, DATA_HDRSIZE, 1);
	if (ret <= 0)
		return -1;
	if (CRASHDEBUG(3))
		fprintf(fp, "remote_memory_read: [%s]\n", datahdr);
	if (STRNEQ(datahdr, FAILMSG)) {
		p1 = strtok(datahdr, " ");  /* FAIL  */
		p1 = strtok(NULL, " ");     /* errno */
		errno = atoi(p1);
		return -1;
	}

	if (!STRNEQ(datahdr, DONEMSG) && !STRNEQ(datahdr, DATAMSG)) {
		error(INFO, "out of sync with remote memory source\n");
		return -1;
	}

	p1 = strtok(datahdr, " ");  /* DONE */
	p1 = strtok(NULL, " ");     /* count */
	tot = atol(p1);

	if (cnt != tot) {
		error(FATAL,
		      "requested %d bytes remote memory return %d bytes\n",
		      cnt, tot);
		return -1;
	}

	ret = remote_tcp_read(pc->sockfd, buffer, tot);
	if (ret != tot) {
		error(FATAL,
		      "requested %d bytes remote memory return %d bytes\n",
		      ret, tot);
		return -1;
	}
	return tot;
}

/*
 *  If a command was interrupted locally, there may be leftover data waiting
 *  to be read.
 */
void
remote_clear_pipeline(void)
{
	int ret;
	fd_set rfds;
	char recvbuf[READBUFSIZE];
	struct timeval tv;

        tv.tv_sec = 0;
        tv.tv_usec = 0;

        FD_ZERO(&rfds);
        FD_SET(pc->sockfd, &rfds);
        ret = select(pc->sockfd+1, &rfds, NULL, NULL, &tv);

	if (FD_ISSET(pc->sockfd, &rfds)) {
        	ret = recv(pc->sockfd, recvbuf, pc->rcvbufsize, 0); 
		if (CRASHDEBUG(1))
			error(INFO, 
	                    "remote_clear_pipeline(%d): %d bytes discarded\n", 
				pc->sockfd, ret);
	}
}

/*
 *  Attempt to run the user-entered command on the remote system.
 */
int
remote_execute(void)
{
	char command[BUFSIZE];
        char sendbuf[BUFSIZE*2];
        char readbuf[READBUFSIZE];
	char datahdr[DATA_HDRSIZE];
        char *bufptr, *p1;
	ulong done, total;
	ulong ret, req, tot;
	size_t dtot;

	if (!STRNEQ(args[0], "@") || strlen(args[0]) == 1)
		return FALSE;

	shift_string_left(concat_args(command, 0, FALSE), 1);

	if (QUOTED_STRING(command)) 
		strip_ending_char(strip_beginning_char(command, '"'), '"');

	if (CRASHDEBUG(1))
		error(INFO, "remote command: %s\n", command);

        BZERO(sendbuf, BUFSIZE);
        sprintf(sendbuf, "EXECUTE %ld %s", pc->rcvbufsize, command);
        remote_tcp_write_string(pc->sockfd, sendbuf);

       	bzero(readbuf, READBUFSIZE);
	done = total = 0;
	dtot = 0;

	while (!done) {

		req = pc->rcvbufsize;
		bufptr = readbuf;
		tot = 0;

                while (req) {
                        ret = recv(pc->sockfd, bufptr, req, 0); 
                        if (!tot) {
				if (STRNEQ(bufptr, FAILMSG)) {
					fprintf(fp, 
					    "remote_execute: %s\n",
						bufptr);
                                	tot = -1;
                                	break;
				}
				if (STRNEQ(bufptr, DONEMSG) ||
				    STRNEQ(bufptr, DATAMSG)) {
					BCOPY(bufptr, datahdr, DATA_HDRSIZE);
					if (CRASHDEBUG(1))
						fprintf(fp, 
					        "remote_execute: [%s]\n",
							datahdr);
                        		p1 = strtok(datahdr, " "); /* DONE */
					if (STREQ(p1, "DONE"))
						done = TRUE;
                        		p1 = strtok(NULL, " ");     /* count */
					dtot = atol(p1);
					total += dtot;
				}
                        }
                        req -= ret;
                        tot += ret;
                        bufptr += ret;
                }

                if (tot == -1)
                        break;

		if (fwrite(&readbuf[DATA_HDRSIZE], sizeof(char), dtot, fp) 
		    != dtot) 
			error(FATAL, "fwrite failed\n");
	}

	return TRUE;
}

/*
 *  Clean up on exit.
 */
void
remote_exit(void)
{
        char buf[BUFSIZE];

	if (pc->flags & UNLINK_NAMELIST)
        	unlink(pc->namelist);

        if (pc->flags & UNLINK_MODULES)
                unlink_module(NULL);

        BZERO(buf, BUFSIZE);
        sprintf(buf, "EXIT");
        remote_tcp_write_string(pc->sockfd, buf);
	/* 
	 *  Read but ignore the return status -- we don't really care... 
	 */
        remote_tcp_read_string(pc->sockfd, buf, BUFSIZE-1, NIL_MODE());

}
#endif /* !DAEMON */
