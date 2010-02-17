/*
**  Copyright (c) 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-genzone.c,v 1.3 2010/02/17 22:08:43 cm-msk Exp $
*/

#ifndef lint
static char opendkim_genzone_c_id[] = "$Id: opendkim-genzone.c,v 1.3 2010/02/17 22:08:43 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>

/* openssl includes */
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

/* opendkim includes */
#include "opendkim-db.h"

/* definitions */
#define	BUFRSZ		1024
#define	CMDLINEOPTS	"C:d:DE:o:N:r:R:St:T:v"
#define	DEFEXPIRE	604800
#define	DEFREFRESH	10800
#define	DEFRETRY	1800
#define	DEFTTL		86400
#define	DKIMZONE	"._domainkey"
#define	HOSTMASTER	"hostmaster"
#define	LARGEBUFRSZ	8192
#define	MARGIN		75
#define	MAXNS		16

#ifndef FALSE
# define FALSE		0
#endif /* ! FALSE */
#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN	256
#endif /* ! MAXHOSTNAMELEN */
#ifndef TRUE
# define TRUE		1
#endif /* ! TRUE */

/* globals */
char *progname;

/*
**  STRFLEN -- determine length of a formatted string
**
**  Parameters:
**  	str -- string of interest
**
**  Return value:
**  	Rendered width (i.e. expand tabs, etc.).
*/

int
strflen(char *str)
{
	int olen = 0;
	char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (*p == '\t')
			olen += 8 - (olen % 8);
		else
			olen++;
	}

	return olen;
}
	
/*
**  LOADKEY -- resolve a key
**
**  Parameters:
**  	buf -- key buffer
**  	buflen -- pointer to key buffer's length (updated)
**
**  Return value:
**  	TRUE on successful load, false otherwise
*/

int
loadkey(char *buf, size_t *buflen)
{
	assert(buf != NULL);
	assert(buflen != NULL);

	if (buf[0] == '/' || (buf[0] == '.' && buf[1] == '/') ||
	    (buf[0] == '.' && buf[1] == '.' && buf[2] == '/'))
	{
		int fd;
		int status;
		ssize_t rlen;
		struct stat s;

		fd = open(buf, O_RDONLY);
		if (fd < 0)
			return FALSE;

		status = fstat(fd, &s);
		if (status != 0)
		{
			close(fd);
			return FALSE;
		}

		*buflen = MIN(s.st_size, *buflen);
		rlen = read(fd, buf, *buflen);
		close(fd);

		if (rlen < *buflen)
			return FALSE;
	}

	return TRUE;
}

/*
**  USAGE -- print usage message and exit
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_USAGE
*/

int
usage(void)
{
	fprintf(stderr, "%s: usage: %s [opts] dataset\n"
	                "\t-C user@host\tcontact address to include in SOA\n"
	                "\t-d domain   \twrite keys for named domain only\n"
	                "\t-D          \tinclude `._domainkey' suffix\n"
	                "\t-E secs     \tuse specified expiration time in SOA\n"
	                "\t-o file     \toutput file\n"
	                "\t-N ns[,...] \tlist NS records\n"
	                "\t-r secs     \tuse specified refresh time in SOA\n"
	                "\t-R secs     \tuse specified retry time in SOA\n"
	                "\t-S          \twrite an SOA record\n"
	                "\t-t secs     \tuse specified per-record TTL\n"
	                "\t-T secs     \tuse specified default TTL in SOA\n"
	                "\t-v          \tverbose output\n",
		progname, progname);

	return EX_USAGE;
}

/*
**  MAIN -- program mainline
**
**  Parameters:
**  	argc, argv -- the usual
**
**  Return value:
**  	Exit status.
*/

int
main(int argc, char **argv)
{
	_Bool seenlf;
	_Bool suffix = FALSE;
	_Bool writesoa = FALSE;
	int c;
	int status;
	int verbose = 0;
	int olen;
	int ttl = -1;
	int defttl = DEFTTL;
	int expire = DEFEXPIRE;
	int refresh = DEFREFRESH;
	int retry = DEFRETRY;
	int nscount = 0;
	long len;
	time_t now;
	size_t keylen;
	char *p;
	char *dataset;
	char *outfile = NULL;
	char *onlydomain = NULL;
	char *contact = NULL;
	char *nameservers = NULL;
	char *nslist[MAXNS];
	FILE *out;
	BIO *private;
	BIO *outbio = NULL;
	EVP_PKEY *pkey;
	RSA *rsa;
	DKIMF_DB db;
	char keyname[BUFRSZ + 1];
	char domain[BUFRSZ + 1];
	char selector[BUFRSZ + 1];
	char tmpbuf[BUFRSZ + 1];
	char hostname[MAXHOSTNAMELEN + 1];
	char keydata[LARGEBUFRSZ];
	struct dkimf_db_data dbd[3];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'C':
			contact = strdup(optarg);
			break;

		  case 'd':
			onlydomain = optarg;
			break;

		  case 'D':
			suffix = TRUE;
			break;

		  case 'E':
			expire = strtol(optarg, &p, 10);
			if (*p != '\0' || expire < 0)
			{
				fprintf(stderr, "%s: invalid expire value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 'N':
			nameservers = strdup(optarg);
			break;

		  case 'o':
			outfile = optarg;
			break;

		  case 'r':
			refresh = strtol(optarg, &p, 10);
			if (*p != '\0' || refresh < 0)
			{
				fprintf(stderr, "%s: invalid refresh value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 'R':
			retry = strtol(optarg, &p, 10);
			if (*p != '\0' || retry < 0)
			{
				fprintf(stderr, "%s: invalid retry value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 't':
			ttl = strtol(optarg, &p, 10);
			if (*p != '\0' || ttl < 0)
			{
				fprintf(stderr, "%s: invalid TTL value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 'T':
			defttl = strtol(optarg, &p, 10);
			if (*p != '\0' || defttl < 0)
			{
				fprintf(stderr,
				        "%s: invalid default TTL value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 'S':
			writesoa = TRUE;
			break;

		  case 'v':
			verbose++;
			break;

		  default:
			return usage();
		}
	}

	if (optind == argc)
		return usage();

	dataset = argv[optind];

	outbio = BIO_new(BIO_s_mem());
	if (outbio == NULL)
	{
		fprintf(stderr, "%s: BIO_new() failed\n", progname);
		return 1;
	}

	status = dkimf_db_open(&db, dataset, DKIMF_DB_FLAG_READONLY, NULL);
	if (status != 0)
	{
		fprintf(stderr, "%s: dkimf_db_open() failed\n", progname);
		(void) BIO_free(outbio);
		return 1;
	}

	if (dkimf_db_type(db) == DKIMF_DB_TYPE_REFILE)
	{
		fprintf(stderr, "%s: invalid data set type\n", progname);
		(void) BIO_free(outbio);
		(void) dkimf_db_close(db);
		return 1;
	}

	if (verbose > 0)
		fprintf(stderr, "%s: database opened\n", progname);

	if (outfile != NULL)
	{
		out = fopen(outfile, "w");
		if (out == NULL)
		{
			fprintf(stderr, "%s: %s: fopen(): %s\n",
			        progname, outfile, strerror(errno));
			(void) dkimf_db_close(db);
			(void) BIO_free(outbio);
			return 1;
		}
	}
	else
	{
		out = stdout;
	}

	if (nameservers != NULL)
	{
		for (p = strtok(nameservers, ",");
		     p != NULL && nscount < MAXNS;
		     p = strtok(NULL, ","))
			nslist[nscount++] = p;
	}

	memset(hostname, '\0', sizeof hostname);
	gethostname(hostname, sizeof hostname);

	if (nscount == 0)
		nslist[nscount++] = hostname;

	(void) time(&now);

	fprintf(out, "; DKIM public key zone data\n");
	if (onlydomain != NULL)
		fprintf(out, "; for %s\n", onlydomain);
	fprintf(out, "; auto-generated by %s at %s\n", progname, ctime(&now));

	if (writesoa)
	{
		struct tm *tm;

		fprintf(out, "@\tIN\tSOA\t%s\t", nslist[0]);

		if (contact != NULL)
		{
			for (p = contact; *p != '\0'; p++)
			{
				if (*p == '@')
					*p = '.';
			}

			fprintf(out, "%s", contact);
		}
		else
		{
			struct passwd *pwd;
			char addr[BUFRSZ + 1];

			pwd = getpwuid(getuid());

			fprintf(out, "%s.%s",
			        pwd == NULL ? HOSTMASTER : pwd->pw_name,
			        hostname);
		}

		tm = localtime(&now);

		fprintf(out,
		        "\t (\n"
		        "\t%04d%02d%02d%02d   ; Serial (yyyymmddhh)\n"
		        "\t%-10d   ; Refresh\n"
		        "\t%-10d   ; Retry\n"
		        "\t%-10d   ; Expire\n"
		        "\t%-10d ) ; Default\n\n",
		        tm->tm_year + 1900,
		        tm->tm_mon + 1,
		        tm->tm_mday,
		        tm->tm_hour,
		        refresh, retry, expire, defttl);
	}

	if (nameservers != NULL)
	{
		for (c = 0; c < nscount; c++)
			fprintf(out, "\tIN\tNS\t%s\n", nslist[c]);

		fprintf(out, "\n");
	}

	dbd[0].dbdata_buffer = domain;
	dbd[1].dbdata_buffer = selector;
	dbd[2].dbdata_buffer = keydata;

	for (c = 0; ; c++)
	{
		memset(keyname, '\0', sizeof keyname);
		memset(domain, '\0', sizeof domain);
		memset(selector, '\0', sizeof selector);
		memset(keydata, '\0', sizeof keydata);

		dbd[0].dbdata_buflen = sizeof domain;
		dbd[1].dbdata_buflen = sizeof selector;
		dbd[2].dbdata_buflen = sizeof keydata;

		keylen = sizeof keyname;

		status = dkimf_db_walk(db, c == 0, keyname, &keylen, dbd, 3);
		if (status == -1)
		{
			fprintf(stderr, "%s: dkimf_db_walk(%d) failed\n",
			        progname, c);
			(void) dkimf_db_close(db);
			(void) BIO_free(outbio);
			return 1;
		}
		else if (status == 1)
		{
			(void) dkimf_db_close(db);
			(void) BIO_free(outbio);
			return 0;
		}

		if (onlydomain != NULL && strcasecmp(domain, onlydomain) != 0)
		{
			fprintf(stderr, "%s: record %d for `%s' skipped\n",
			        progname, c, keyname);

			continue;
		}

		if (verbose > 1)
		{
			fprintf(stderr, "%s: record %d for `%s' retrieved\n",
			        progname, c, keyname);
		}

		keylen = sizeof keydata;
		if (!loadkey(keydata, &keylen))
		{
			fprintf(stderr, "%s: key for `%s' load failed\n",
			        progname, keyname);
			(void) dkimf_db_close(db);
			(void) BIO_free(outbio);
			return 1;
		}

		if (verbose > 1)
		{
			fprintf(stderr, "%s: key for `%s' loaded\n",
			        progname, keyname);
		}

		/* create a BIO for the private key */
		private = BIO_new_mem_buf(keydata, keylen);
		if (private == NULL)
		{
			fprintf(stderr, "%s: BIO_new_mem_buf() failed\n",
			        progname);
			(void) dkimf_db_close(db);
			(void) BIO_free(outbio);
			return 1;
		}

		pkey = PEM_read_bio_PrivateKey(private, NULL, NULL, NULL);
		if (pkey == NULL)
		{
			fprintf(stderr,
			        "%s: PEM_read_bio_PrivateKey() failed\n",
			        progname);
			(void) dkimf_db_close(db);
			(void) BIO_free(private);
			(void) BIO_free(outbio);
			return 1;
		}

		rsa = EVP_PKEY_get1_RSA(pkey);
		if (rsa == NULL)
		{
			fprintf(stderr,
			        "%s: EVP_PKEY_get1_RSA() failed\n",
			        progname);
			(void) dkimf_db_close(db);
			(void) BIO_free(private);
			(void) EVP_PKEY_free(pkey);
			(void) BIO_free(outbio);
			return 1;
		}

		/* convert private to public */
		status = PEM_write_bio_RSA_PUBKEY(outbio, rsa);
		if (status == 0)
		{
			fprintf(stderr,
			        "%s: PEM_write_bio_RSA_PUBKEY() failed\n",
			        progname);
			(void) dkimf_db_close(db);
			(void) BIO_free(private);
			(void) EVP_PKEY_free(pkey);
			(void) BIO_free(outbio);
			return 1;
		}

		/* write the record */
		if (ttl == -1)
		{
			snprintf(tmpbuf, sizeof tmpbuf,
			         "%s%s\tIN\tTXT\t( \"k=rsa; p=", selector,
			         suffix ? DKIMZONE : "");
		}
		else
		{
			snprintf(tmpbuf, sizeof tmpbuf,
			         "%s%s\t%d\tIN\tTXT\t( \"k=rsa; p=", selector,
			         suffix ? DKIMZONE : "", ttl);
		}

		fprintf(out, "%s", tmpbuf);

		olen = strflen(tmpbuf);

		seenlf = FALSE;
		for (len = BIO_get_mem_data(outbio, &p); len > 0; len--, p++)
		{
			if (*p == '\n')
			{
				seenlf = TRUE;
			}
			else if (seenlf && *p == '-')
			{
				break;
			}
			else if (!seenlf)
			{
				continue;
			}
			else if (isascii(*p) && !isspace(*p))
			{
				(void) fputc(*p, out);
				olen++;
			}

			if (olen >= MARGIN)
			{
				fprintf(out, "\"\n\t\"");
				olen = 9;
			}
		}

		fprintf(out, "\" )\n");

		/* prepare for the next one */
		(void) BIO_reset(outbio);
	}

	if (out != stdout)
		fclose(out);

	(void) BIO_free(outbio);
	(void) dkimf_db_close(db);

	if (verbose > 0)
	{
		fprintf(stdout, "%s: %d record%s written\n",
		        progname, c, c == 1 ? "" : "s");
	}

	return 0;
}
