/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2015, 2018, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _DKIM_TYPES_H_
#define _DKIM_TYPES_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#ifdef USE_TRE
# ifdef TRE_PRE_080
#  include <tre/regex.h>
# else /* TRE_PRE_080 */
#  include <tre/tre.h>
# endif /* TRE_PRE_080 */
#else /* USE_TRE */
# include <regex.h>
#endif /* USE_TRE */

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
# include <gnutls/abstract.h>
#else /* USE_GNUTLS */
/* OpenSSL includes */
# include <openssl/pem.h>
# include <openssl/rsa.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/sha.h>
#endif /* USE_GNUTLS */

#ifdef QUERY_CACHE
/* libdb includes */
# include <db.h>
#endif /* QUERY_CACHE */

/* libopendkim includes */
#include "dkim.h"
#include "dkim-internal.h"

/* struct dkim_qmethod -- signature query method */
struct dkim_qmethod
{
	char *			qm_type;
	char *			qm_options;
	struct dkim_qmethod *	qm_next;
};

/* struct dkim_xtag -- signature extension tag */
struct dkim_xtag
{
	char *			xt_tag;
	char *			xt_value;
	struct dkim_xtag *	xt_next;
};

/* struct dkim_queryinfo -- DNS query information */
struct dkim_queryinfo
{
	int			dq_type;
	const char		dq_name[DKIM_MAXHOSTNAMELEN + 1];
};

/* struct dkim_dstring -- a dynamically-sized string */
struct dkim_dstring
{
	int			ds_alloc;
	int			ds_max;
	int			ds_len;
	DKIM *			ds_dkim;
	unsigned char *		ds_buf;
};

/* struct dkim_header -- an RFC2822 header of some kind */
struct dkim_header
{
	int			hdr_flags;
	size_t			hdr_textlen;
	size_t			hdr_namelen;
	u_char *		hdr_text;
	u_char *		hdr_colon;
	struct dkim_header *	hdr_next;
};

/* hdr_flags bits */
#define	DKIM_HDR_SIGNED		0x01

/* struct dkim_plist -- a parameter/value pair */
struct dkim_plist
{
	u_char *		plist_param;
	u_char *		plist_value;
	struct dkim_plist *	plist_next;
};

/* struct dkim_set -- a set of parameter/value pairs */
struct dkim_set
{
	_Bool			set_bad;
#ifdef _FFR_CONDITIONAL
	u_int			set_minv;
#endif /* _FFR_CONDITIONAL */
	dkim_set_t		set_type;
	u_char *		set_data;
	const char *		set_name;
	void *			set_udata;
	struct dkim_plist *	set_plist[NPRINTABLE];
	struct dkim_set *	set_next;
};

/* public key algorithm identification and common parameters */
struct dkim_pki
{
	dkim_keytype_t		pki_id;
	unsigned int		pki_keysize;
	size_t			pki_sigsize;
};

/* public key algorithm key material */
struct dkim_pkm
{
#if defined(USE_GNUTLS)
	union {
	  struct {
		gnutls_x509_privkey_t	xpriv;
		gnutls_privkey_t	priv;
	  } s;
	  struct {
		gnutls_pubkey_t		pub;
	  } v;
	} u;
#else /* USE_GNUTLS */
	BIO *				pkm_bio;
	EVP_PKEY *			pkm_pkey;
	RSA *				pkm_rsa;
#endif /* !USE_GNUTLS */
};

#define pkm_xpriv	u.s.xpriv
#define pkm_priv	u.s.priv
#define pkm_pub		u.v.pub

/* combination of a pointer to and the size of a contiguous memory region */
struct alen
{
	u_char *	addr;
	size_t		len;
};
        
/* struct dkim_siginfo -- signature information for use by the caller */
struct dkim_siginfo
{
	struct dkim_pki		sig_pki;
	u_int			sig_flags;
	u_int			sig_bh;
	dkim_canon_t		sig_hdrcanonalg;
	dkim_canon_t		sig_bodycanonalg;
	dkim_hashalg_t		sig_hashalg;
	dkim_signalg_t		sig_signalg;
	uint64_t		sig_timestamp;
#if defined(DEEP_ARGUMENT_COPIES)
	u_char *		sig_domain;
	u_char *		sig_selector;
#else /* DEEP_ARGUMENT_COPIES */
	const u_char *		sig_domain;
	const u_char *		sig_selector;
#endif /* !DEEP_ARGUMENT_COPIES */
	union {
	  struct {
	    struct dkim_pkm	pkm;
	  } s;
	  struct {
	    struct alen		sig;
	    struct alen		key;
	    struct dkim_set *	taglist;
	    struct dkim_set *	keytaglist;
	    dkim_query_t	query;
	    int			dnssec;
	    u_int		error;
	  } v;
	} u;
	void *			sig_context;
	struct dkim_canon *	sig_hdrcanon;
	struct dkim_canon *	sig_bodycanon;
	struct dkim_dstring *	sig_sslerrbuf;
};

#define sig_pkalg	sig_pki.pki_id
#define sig_keybits	sig_pki.pki_keysize

#define sig_pkm		u.s.pkm

#define sig_sig		u.v.sig.addr
#define sig_siglen	u.v.sig.len
#define sig_key		u.v.key.addr
#define sig_keylen	u.v.key.len
#define sig_taglist	u.v.taglist
#define sig_keytaglist	u.v.keytaglist
#define sig_query	u.v.query
#define sig_dnssec_key	u.v.dnssec
#define sig_error	u.v.error

#ifdef USE_GNUTLS
/* struct dkim_sha -- stuff needed to do a sha hash */
struct dkim_sha
{
#if defined(DEBUG_FEATURES)
	int			sha_tmpfd;
#endif /* DEBUG_FEATURES */
	u_int			sha_outlen;
	gnutls_hash_hd_t	sha_hd;
	u_char *		sha_out;
};
#else /* USE_GNUTLS */
/* struct dkim_sha1 -- stuff needed to do a sha1 hash */
struct dkim_sha1
{
#if defined(DEBUG_FEATURES)
	int			sha1_tmpfd;
	BIO *			sha1_tmpbio;
#endif /* DEBUG_FEATURES */
	SHA_CTX			sha1_ctx;
	u_char			sha1_out[SHA_DIGEST_LENGTH];
};

# ifdef HAVE_SHA256
/* struct dkim_sha256 -- stuff needed to do a sha256 hash */
struct dkim_sha256
{
#if defined(DEBUG_FEATURES)
	int			sha256_tmpfd;
	BIO *			sha256_tmpbio;
#endif /* DEBUG_FEATURES */
	SHA256_CTX		sha256_ctx;
	u_char			sha256_out[SHA256_DIGEST_LENGTH];
};
# endif /* HAVE_SHA256 */
#endif /* USE_GNUTLS */

/* struct dkim_canon -- a canonicalization status handle */
struct dkim_canon
{
	_Bool			canon_done;
	_Bool			canon_hdr;
	_Bool			canon_blankline;
	int			canon_lastchar;
	int			canon_bodystate;
	dkim_hashalg_t		canon_hashtype;
	u_int			canon_blanks;
	size_t			canon_hashbuflen;
	size_t			canon_hashbufsize;
	ssize_t			canon_remain;
	ssize_t			canon_wrote;
	ssize_t			canon_length;
	dkim_canon_t		canon_canon;
	u_char *		canon_hashbuf;
	u_char *		canon_hdrlist;
	void *			canon_hash;
	struct dkim_dstring *	canon_buf;
	struct dkim_header *	canon_sigheader;
	struct dkim_canon *	canon_next;
};

#if defined(TAS_SUPPORT)

/* struct dkim_test_dns_data -- simulated DNS replies */
struct dkim_test_dns_data
{
	int			dns_class;
	int			dns_type;
	int			dns_prec;
	u_char *		dns_query;
	u_char *		dns_reply;
	struct dkim_test_dns_data * dns_next;
};

#endif /* TAS_SUPPORT */

/* struct dkim_unbound_cb_data -- libunbound callback data */
struct dkim_unbound_cb_data
{
	int			ubd_done;
	int			ubd_rcode;
	int			ubd_id;
	int			ubd_type;
	u_int			ubd_result;
	DKIM_STAT		ubd_stat;
	size_t			ubd_buflen;
	u_char *		ubd_buf;
	const char *		ubd_jobid;
};

/* struct dkim -- a complete DKIM transaction context */
struct dkim
{
	_Bool			dkim_partial;
	_Bool			dkim_bodydone;
	_Bool			dkim_subdomain;
	_Bool			dkim_skipbody;
#ifdef _FFR_RESIGN
	_Bool			dkim_hdrbind;
#endif /* _FFR_RESIGN */
	_Bool			dkim_eoh_reentry;
	int			dkim_mode;
	int			dkim_state;
	int			dkim_chunkstate;
	int			dkim_chunksm;
	int			dkim_chunkcrlf;
	int			dkim_timeout;
	int			dkim_presult;
	int			dkim_hdrcnt;
	int			dkim_minsiglen;
#ifdef _FFR_CONDITIONAL
	int			dkim_cddepth;
#endif /* _FFR_CONDITIONAL */
#ifdef _FFR_RESIGN
	u_int			dkim_refcnt;
#endif /* _FFR_RESIGN */
#ifdef QUERY_CACHE
	u_int			dkim_cache_queries;
	u_int			dkim_cache_hits;
#endif /* QUERY_CACHE */
	u_int			dkim_version;
	u_int			dkim_sigcount;
	size_t			dkim_margin;
	size_t			dkim_b64siglen;
	size_t			dkim_keylen;
	size_t			dkim_errlen;
  	struct dkim_qmethod *	dkim_querymethods;
	dkim_canon_t		dkim_hdrcanonalg;
	dkim_canon_t		dkim_bodycanonalg;
	dkim_hashalg_arg_t	dkim_hashalg;
#ifdef _FFR_ATPS
	_Bool			dkim_atps;
#endif /* _FFR_ATPS */
	ssize_t			dkim_bodylen;
	ssize_t			dkim_signlen;
	const u_char *		dkim_id;
#if defined(DEEP_ARGUMENT_COPIES)
	u_char *		dkim_domain;
	u_char *		dkim_selector;
	u_char *		dkim_signer;
#else /* DEEP_ARGUMENT_COPIES */
	const u_char *		dkim_domain;
	const u_char *		dkim_selector;
	const u_char *		dkim_signer;
#endif /* !DEEP_ARGUMENT_COPIES */
#if defined(MANAGE_AUTHOR_IDENTIFIERS)
	u_char *		dkim_sender;
	u_char *		dkim_user;
#endif /* MANAGE_AUTHOR_IDENTIFIERS */
	u_char *		dkim_b64key;
	u_char *		dkim_b64sig;
#if defined(DEEP_ARGUMENT_COPIES)
	u_char *		dkim_key;
#else /* DEEP_ARGUMENT_COPIES */
	const u_char *		dkim_key;
#endif /* !DEEP_ARGUMENT_COPIES */
	u_char *		dkim_reportaddr;
#ifdef _FFR_CONDITIONAL
	u_char *		dkim_conditional;
#endif /* _FFR_CONDITIONAL */
	u_char *		dkim_error;
	u_char *		dkim_hdrlist;
#if defined(DEBUG_FEATURES)
	u_char *		dkim_zdecode;
	u_char *		dkim_tmpdir;
#endif /* DEBUG_FEATURES */
	DKIM_SIGINFO *		dkim_signature;
	void *			dkim_closure;
	const void *		dkim_user_context;
#ifdef _FFR_RESIGN
	DKIM *			dkim_resign;
#endif /* _FFR_RESIGN */
	struct dkim_xtag *	dkim_xtags;
	struct dkim_siginfo **	dkim_siglist;
	struct dkim_set *	dkim_sethead;
	struct dkim_set *	dkim_settail;
	struct dkim_set *	dkim_sigset;
	struct dkim_header *	dkim_hhead;
	struct dkim_header *	dkim_htail;
#if defined(MANAGE_AUTHOR_IDENTIFIERS)
	struct dkim_header *	dkim_senderhdr;
#endif /* MANAGE_AUTHOR_IDENTIFIERS */
	struct dkim_canon *	dkim_canonhead;
	struct dkim_canon *	dkim_canontail;
	struct dkim_dstring *	dkim_hdrbuf;
	struct dkim_dstring *	dkim_canonbuf;
	struct dkim_dstring *	dkim_sslerrbuf;
#if defined(TAS_SUPPORT)
	struct dkim_test_dns_data * dkim_dnstesth;
	struct dkim_test_dns_data * dkim_dnstestt;
#endif /* TAS_SUPPORT */
	regex_t *		dkim_hdrre;
	DKIM_LIB *		dkim_libhandle;
};

/* struct dkim_lib -- a DKIM library context */
struct dkim_lib
{
	_Bool			dkiml_signre;
	_Bool			dkiml_skipre;
	_Bool			dkiml_dnsinit_done;
	u_int			dkiml_timeout;
	u_int			dkiml_version;
	u_int			dkiml_callback_int;
	u_int			dkiml_minkeybits;
	uint32_t		dkiml_flags;
	uint64_t		dkiml_fixedtime;
	uint64_t		dkiml_sigttl;
	uint64_t		dkiml_clockdrift;
	dkim_query_t		dkiml_querymethod;
#if defined(SHARED)
	u_int			dkiml_flsize;
	u_int *			dkiml_flist;
#endif /* SHARED */
	void *			(*dkiml_malloc) (void *closure, size_t nbytes);
	void			(*dkiml_free) (void *closure, void *p);
	const u_char * const *	dkiml_requiredhdrs;
	const u_char * const *	dkiml_oversignhdrs;
	const u_char * const *	dkiml_mbs;
#ifdef QUERY_CACHE
	DB *			dkiml_cache;
#endif /* QUERY_CACHE */
	regex_t			dkiml_hdrre;
	regex_t			dkiml_skiphdrre;
	DKIM_CBSTAT		(*dkiml_key_lookup) (DKIM *dkim,
				                     DKIM_SIGINFO *sig,
				                     u_char *buf,
				                     size_t buflen);
	void *			(*dkiml_sig_handle) (void *closure);
	void			(*dkiml_sig_handle_free) (void *closure,
				                          void *user);
	void			(*dkiml_sig_tagvalues) (void *user,
				                        dkim_param_t pcode,
				                        const u_char *param,
				                        const u_char *value);
	DKIM_CBSTAT		(*dkiml_prescreen) (DKIM *dkim,
				                    DKIM_SIGINFO **sigs,
				                    int nsigs);
	DKIM_CBSTAT		(*dkiml_final) (DKIM *dkim,
				                DKIM_SIGINFO **sigs,
				                int nsigs);
	void			(*dkiml_dns_callback) (const void *context);
	void			*dkiml_dns_service;
	int			(*dkiml_dns_init) (void **srv);
	void			(*dkiml_dns_close) (void *srv);
	int			(*dkiml_dns_start) (void *srv, int type,
				                    unsigned char *query,
				                    unsigned char *buf,
				                    size_t buflen,
				                    void **qh);
	int			(*dkiml_dns_cancel) (void *srv, void *qh);
	int			(*dkiml_dns_setns) (void *srv, const char *ns);
	int			(*dkiml_dns_config) (void *srv,
				                     const char *conf);
	int			(*dkiml_dns_trustanchor) (void *srv,
				                          const char *ta);
	int			(*dkiml_dns_waitreply) (void *srv,
				                        void *qh,
				                        struct timeval *to,
				                        size_t *bytes,
				                        int *error,
				                        int *dnssec);
#if defined(DEBUG_FEATURES)
	u_char			dkiml_tmpdir[MAXPATHLEN + 1];
#endif /* DEBUG_FEATURES */
	u_char			dkiml_queryinfo[MAXPATHLEN + 1];
};

#endif /* _DKIM_TYPES_H_ */
