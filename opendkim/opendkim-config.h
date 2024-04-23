/*
**  Copyright (c) 2006-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2015, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _DKIM_CONFIG_H_
#define _DKIM_CONFIG_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>

/* macros */
#ifndef FALSE
# define FALSE	0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE	1
#endif /* ! TRUE */

/* config definition */
struct configdef dkimf_config[] =
{
	{ "AllowSHA1Only",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "AlwaysAddARHeader",		CONFIG_TYPE_BOOLEAN,	FALSE },
#ifdef _FFR_ATPS
	{ "ATPSDomains",		CONFIG_TYPE_STRING,	FALSE },
	{ "ATPSHashAlgorithm",		CONFIG_TYPE_STRING,	FALSE },
#endif /* _FFR_ATPS */
	{ "AuthservID",			CONFIG_TYPE_STRING,	FALSE },
	{ "AuthservIDWithJobID",	CONFIG_TYPE_BOOLEAN,	FALSE },
#if defined(STANDALONE)
	{ "AutoRestart",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "AutoRestartCount",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "AutoRestartRate",		CONFIG_TYPE_STRING,	FALSE },
	{ "Background",			CONFIG_TYPE_BOOLEAN,	FALSE },
#endif /* STANDALONE */
	{ "BaseDirectory",		CONFIG_TYPE_STRING,	FALSE },
	{ "BodyLengthDB",		CONFIG_TYPE_STRING,	FALSE },
#ifdef USE_UNBOUND
	{ "BogusKey",			CONFIG_TYPE_STRING,	FALSE },
#endif /* USE_UNBOUND*/
	{ "Canonicalization",		CONFIG_TYPE_STRING,	FALSE },
	{ "CaptureUnknownErrors",	CONFIG_TYPE_BOOLEAN,	FALSE },
#if defined(STANDALONE)
	{ "ChangeRootDirectory",	CONFIG_TYPE_STRING,	FALSE },
#endif /* STANDALONE */
	{ "ClockDrift",			CONFIG_TYPE_INTEGER,	FALSE },
#ifdef _FFR_CONDITIONAL
	{ "ConditionalSignatures",	CONFIG_TYPE_STRING,	FALSE },
#endif /* _FFR_CONDITIONAL */
#ifdef _FFR_DEFAULT_SENDER
	{ "DefaultSender",		CONFIG_TYPE_STRING,	FALSE },
#endif /* _FFR_DEFAULT_SENDER */
	{ "Diagnostics",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "DiagnosticDirectory",	CONFIG_TYPE_STRING,	FALSE },
	{ "DisableCryptoInit",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "DNSConnect",			CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "DNSTimeout",			CONFIG_TYPE_INTEGER,	FALSE },
#if defined(SINGLE_SIGNING)
	{ "Domain",			CONFIG_TYPE_STRING,	FALSE },
#endif /* SINGLE_SIGNING */
	{ "DomainKeysCompat",		CONFIG_TYPE_BOOLEAN,	FALSE },
#if defined(BYPASS_CRITERIA)
	{ "DontSignMailTo",		CONFIG_TYPE_STRING,	FALSE },
#endif /* BYPASS_CRITERIA */
#if defined(STANDALONE)
	{ "EnableCoredumps",		CONFIG_TYPE_BOOLEAN,	FALSE },
#endif /* STANDALONE */
#if defined(BYPASS_CRITERIA)
	{ "ExemptDomains",		CONFIG_TYPE_STRING,	FALSE },
#endif /* BYPASS_CRITERIA */
#if defined(EXTERNAL_IGNORE_LIST)
	{ "ExternalIgnoreList",		CONFIG_TYPE_STRING,	FALSE },
#endif /* EXTERNAL_IGNORE_LIST */
#ifdef USE_LUA
	{ "FinalPolicyScript",		CONFIG_TYPE_STRING,	FALSE },
#endif /* USE_LUA */
	{ "FixCRLF",			CONFIG_TYPE_BOOLEAN,	FALSE },
#ifdef _FFR_RATE_LIMIT
	{ "FlowData",			CONFIG_TYPE_STRING,	FALSE },
	{ "FlowDataFactor",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "FlowDataTTL",		CONFIG_TYPE_INTEGER,	FALSE },
#endif /* _FFR_RATE_LIMIT */
#ifdef _FFR_IDENTITY_HEADER
	{ "IdentityHeader",		CONFIG_TYPE_STRING,     FALSE },
	{ "IdentityHeaderRemove",	CONFIG_TYPE_BOOLEAN,    FALSE },
#endif /* _FFR_IDENTITY_HEADER */
	{ "IgnoreMalformedMail",	CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "Include",			CONFIG_TYPE_INCLUDE,	FALSE },
#if defined(LOCAL_SIGNING_CRITERIA)
	{ "InternalHosts",		CONFIG_TYPE_STRING,	FALSE },
#endif /* LOCAL_SIGNING_CRITERIA */
	{ "KeepAuthResults",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "KeepTemporaryFiles",		CONFIG_TYPE_BOOLEAN,	FALSE },
#if defined(SINGLE_SIGNING)
	{ "KeyFile",			CONFIG_TYPE_STRING,	FALSE },
	{ "KeyTable",			CONFIG_TYPE_STRING,	FALSE },
#else /* SINGLE_SIGNING */
	{ "KeyTable",			CONFIG_TYPE_STRING,	TRUE  },
#endif /* !SINGLE_SIGNING */
#ifdef USE_LDAP
	{ "LDAPAuthMechanism",		CONFIG_TYPE_STRING,	FALSE },
# ifdef USE_SASL
	{ "LDAPAuthName",		CONFIG_TYPE_STRING,	FALSE },
	{ "LDAPAuthRealm",		CONFIG_TYPE_STRING,	FALSE },
	{ "LDAPAuthUser",		CONFIG_TYPE_STRING,	FALSE },
# endif /* USE_SASL */
	{ "LDAPBindPassword",		CONFIG_TYPE_STRING,	FALSE },
	{ "LDAPBindUser",		CONFIG_TYPE_STRING,	FALSE },
	{ "LDAPDisableCache",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "LDAPKeepaliveIdle",		CONFIG_TYPE_STRING,	FALSE },
	{ "LDAPKeepaliveInterval",	CONFIG_TYPE_STRING,	FALSE },
	{ "LDAPKeepaliveProbes",	CONFIG_TYPE_STRING,	FALSE },
	{ "LDAPTimeout",		CONFIG_TYPE_STRING,	FALSE },
	{ "LDAPUseTLS",			CONFIG_TYPE_BOOLEAN,	FALSE },
#endif /* USE_LDAP */
	{ "LogResults",			CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "LogWhy",			CONFIG_TYPE_BOOLEAN,	FALSE },
#ifdef _FFR_LUA_ONLY_SIGNING
	{ "LuaOnlySigning",		CONFIG_TYPE_BOOLEAN,	FALSE },
#endif /* _FFR_LUA_ONLY_SIGNING */
#if defined(STRICT_MODE)
	{ "MalformedAddressReplyText",	CONFIG_TYPE_STRING,	FALSE },
	{ "MalformedMessageReplyText",	CONFIG_TYPE_STRING,	FALSE },
#endif /* STRICT_MODE */
	{ "MaximumHeaders",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "MaximumSignedBytes",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "MaximumSignaturesToVerify",	CONFIG_TYPE_INTEGER,	FALSE },
#if defined(LOCAL_SIGNING_CRITERIA)
	{ "MacroList",			CONFIG_TYPE_STRING,	FALSE },
#endif /* LOCAL_SIGNING_CRITERIA */
#if defined(PRODUCTION_TESTS)
	{ "MilterDebug",		CONFIG_TYPE_INTEGER,	FALSE },
#endif /* PRODUCTION_TESTS */
	{ "Minimum",			CONFIG_TYPE_STRING,	FALSE },
	{ "MinimumKeyBits",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "MultipleSignatures",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "Mode",			CONFIG_TYPE_STRING,	FALSE },
#if defined(LOCAL_SIGNING_CRITERIA)
	{ "MTA",			CONFIG_TYPE_STRING,	FALSE },
#endif /* LOCAL_SIGNING_CRITERIA */
	{ "MTACommand",			CONFIG_TYPE_STRING,	FALSE },
	{ "MustBeSigned",		CONFIG_TYPE_STRING,	FALSE },
	{ "Nameservers",		CONFIG_TYPE_STRING,	FALSE },
	{ "NoHeaderB",			CONFIG_TYPE_BOOLEAN,	FALSE },
#if defined(STRICT_MODE)
	{ "NoSenderReplyText",		CONFIG_TYPE_STRING,	FALSE },
#endif /* STRICT_MODE */
	{ "OmitHeaders",		CONFIG_TYPE_STRING,	FALSE },
	{ "On-BadSignature",		CONFIG_TYPE_STRING,	FALSE },
	{ "On-Default",			CONFIG_TYPE_STRING,	FALSE },
	{ "On-DNSError",		CONFIG_TYPE_STRING,	FALSE },
	{ "On-InternalError",		CONFIG_TYPE_STRING,	FALSE },
	{ "On-KeyNotFound",		CONFIG_TYPE_STRING,	FALSE },
#if defined(STRICT_MODE)
	{ "On-MalformedAddress",	CONFIG_TYPE_STRING,	FALSE },
	{ "On-MalformedMessage",	CONFIG_TYPE_STRING,	FALSE },
	{ "On-NoSender",		CONFIG_TYPE_STRING,	FALSE },
#endif /* STRICT_MODE */
	{ "On-NoSignature",		CONFIG_TYPE_STRING,	FALSE },
#ifdef _FFR_REPUTATION
	{ "On-ReputationError",		CONFIG_TYPE_STRING,	FALSE },
#endif /* _FFR_REPUTATION */
	{ "On-Security",		CONFIG_TYPE_STRING,	FALSE },
#if defined(STRICT_MODE)
	{ "On-ServiceException",	CONFIG_TYPE_STRING,	FALSE },
#endif /* STRICT_MODE */
	{ "On-SignatureError",		CONFIG_TYPE_STRING,	FALSE },
	{ "OverSignHeaders",		CONFIG_TYPE_STRING,	FALSE },
#if defined(BYPASS_CRITERIA)
	{ "PeerList",			CONFIG_TYPE_STRING,	FALSE },
#endif /* BYPASS_CRITERIA */
#if defined(STANDALONE)
	{ "PidFile",			CONFIG_TYPE_STRING,	FALSE },
#endif /* STANDALONE */
#ifdef POPAUTH
	{ "POPDBFile",			CONFIG_TYPE_STRING,	FALSE },
#endif /* POPAUTH */
	{ "Quarantine",			CONFIG_TYPE_BOOLEAN,	FALSE },
#ifdef QUERY_CACHE
	{ "QueryCache",			CONFIG_TYPE_BOOLEAN,	FALSE },
#endif /* QUERY_CACHE */
#ifdef _FFR_RATE_LIMIT
	{ "RateLimits",			CONFIG_TYPE_STRING,	FALSE },
#endif /* _FFR_RATE_LIMIT */
	{ "RedirectFailuresTo",		CONFIG_TYPE_STRING,	FALSE },
	{ "RemoveARAll",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "RemoveARFrom",		CONFIG_TYPE_STRING,	FALSE },
	{ "RemoveOldSignatures",	CONFIG_TYPE_BOOLEAN,	FALSE },
#ifdef _FFR_REPLACE_RULES
	{ "ReplaceHeaders",		CONFIG_TYPE_STRING,	FALSE },
	{ "ReplaceRules",		CONFIG_TYPE_STRING,	FALSE },
#endif /* _FFR_REPLACE_RULES */
	{ "ReportAddress",		CONFIG_TYPE_STRING,	FALSE },
	{ "ReportBccAddress",		CONFIG_TYPE_STRING,	FALSE },
#ifdef _FFR_REPUTATION
	{ "ReputationCache",		CONFIG_TYPE_STRING,	FALSE },
	{ "ReputationCacheTTL",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "ReputationDuplicates",	CONFIG_TYPE_STRING,	FALSE },
	{ "ReputationLimits",		CONFIG_TYPE_STRING,	FALSE },
	{ "ReputationLowTime",		CONFIG_TYPE_STRING,	FALSE },
	{ "ReputationMinimum",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "ReputationLimitModifiers",	CONFIG_TYPE_STRING,	FALSE },
	{ "ReputationRatios",		CONFIG_TYPE_STRING,	FALSE },
#endif /* _FFR_REPUTATION */
#ifdef _FFR_REPRRD
	{ "ReputationRRDHashDepth",	CONFIG_TYPE_INTEGER,	FALSE },
	{ "ReputationRRDRoot",		CONFIG_TYPE_STRING,	FALSE },
	{ "ReputationTest", /* DUP */	CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "ReputationVerbose", /* DUP */ CONFIG_TYPE_BOOLEAN,	FALSE },
#endif /* _FFR_REPRRD */
#ifdef _FFR_REPUTATION
	{ "ReputationSpamCheck",	CONFIG_TYPE_STRING,	FALSE },
	{ "ReputationTest", /* DUP */	CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "ReputationTimeFactor",	CONFIG_TYPE_INTEGER,	FALSE },
	{ "ReputationTimeout",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "ReputationVerbose", /* DUP */ CONFIG_TYPE_BOOLEAN,	FALSE },
#endif /* _FFR_REPUTATION */
	{ "RequestReports",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "RequiredHeaders",		CONFIG_TYPE_BOOLEAN,	FALSE },
#if defined(REQUIRE_SAFE_KEYS)
	{ "RequireSafeKeys",		CONFIG_TYPE_BOOLEAN,	FALSE },
#endif /* REQUIRE_SAFE_KEYS */
#ifdef _FFR_RESIGN
	{ "ResignAll",			CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "ResignMailTo",		CONFIG_TYPE_STRING,	FALSE },
#endif /* _FFR_RESIGN */
	{ "ResolverConfiguration",	CONFIG_TYPE_STRING,	FALSE },
	{ "ResolverTracing",		CONFIG_TYPE_BOOLEAN,	FALSE },
#ifdef USE_LUA
	{ "ScreenPolicyScript",		CONFIG_TYPE_STRING,	FALSE },
#endif /* USE_LUA */
#if defined(SINGLE_SIGNING)
	{ "Selector",			CONFIG_TYPE_STRING,	FALSE },
#endif /* SINGLE_SIGNING */
	{ "SelectCanonicalizationHeader", CONFIG_TYPE_STRING,	FALSE },
	{ "SenderHeaders",		CONFIG_TYPE_STRING,	FALSE },
#ifdef _FFR_SENDER_MACRO
	{ "SenderMacro",		CONFIG_TYPE_STRING,	FALSE },
#endif /* _FFR_SENDER_MACRO */
	{ "SendReports",		CONFIG_TYPE_BOOLEAN,	FALSE },
#if defined(STRICT_MODE)
	{ "ServiceExceptionReplyText",	CONFIG_TYPE_STRING,	FALSE },
#endif /* STRICT_MODE */
#ifdef USE_LUA
	{ "SetupPolicyScript",		CONFIG_TYPE_STRING,	FALSE },
#endif /* USE_LUA */
	{ "SignatureAlgorithm",		CONFIG_TYPE_STRING,	FALSE },
	{ "SignatureTTL",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "SignHeaders",		CONFIG_TYPE_STRING,	FALSE },
#if defined(SINGLE_SIGNING) || defined(USE_LUA)
	{ "SigningTable",		CONFIG_TYPE_STRING,	FALSE },
#else /* SINGLE_SIGNING || USE_LUA */
	{ "SigningTable",		CONFIG_TYPE_STRING,	TRUE  },
#endif /* !SINGLE_SIGNING && !USE_LUA */
#ifdef HAVE_CURL_EASY_STRERROR
	{ "SMTPURI",			CONFIG_TYPE_STRING,	FALSE },
#endif /* HAVE_CURL_EASY_STRERROR */
	{ "Socket",			CONFIG_TYPE_STRING,	FALSE },
	{ "SoftwareHeader",		CONFIG_TYPE_BOOLEAN,	FALSE },
#if defined(USE_ODBX) || defined(USE_LDAP)
	{ "SoftStart",			CONFIG_TYPE_BOOLEAN,	FALSE },
#endif /* defined(USE_ODBX) || defined(USE_LDAP) */
#ifdef _FFR_STATS
	{ "Statistics",			CONFIG_TYPE_STRING,	FALSE },
	{ "StatisticsName",		CONFIG_TYPE_STRING,	FALSE },
# ifdef USE_LUA
#  ifdef _FFR_STATSEXT
	{ "StatisticsPolicyScript",	CONFIG_TYPE_STRING,	FALSE },
#  endif /* _FFR_STATSEXT */
# endif /* USE_LUA */
	{ "StatisticsPrefix",		CONFIG_TYPE_STRING,	FALSE },
#endif /* _FFR_STATS */
	{ "StrictHeaders",		CONFIG_TYPE_BOOLEAN,	FALSE },
#if defined(PRODUCTION_TESTS)
	{ "StrictTestMode",		CONFIG_TYPE_BOOLEAN,	FALSE },
#endif /* PRODUCTION_TESTS */
#if defined(SINGLE_SIGNING)
	{ "SubDomains",			CONFIG_TYPE_BOOLEAN,	FALSE },
#endif /* SINGLE_SIGNING */
	{ "Syslog",			CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "SyslogFacility",		CONFIG_TYPE_STRING,	FALSE },
	{ "SyslogName",			CONFIG_TYPE_STRING,	FALSE },
	{ "SyslogSuccess",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "TemporaryDirectory",		CONFIG_TYPE_STRING,	FALSE },
#if defined(PRODUCTION_TESTS)
	{ "TestDNSData",		CONFIG_TYPE_STRING,	FALSE },
	{ "TestPublicKeys",		CONFIG_TYPE_STRING,	FALSE },
#endif /* PRODUCTION_TESTS */
	{ "TrustAnchorFile",		CONFIG_TYPE_STRING,	FALSE },
	{ "TrustSignaturesFrom",	CONFIG_TYPE_STRING,	FALSE },
	{ "UMask",			CONFIG_TYPE_INTEGER,	FALSE },
#ifdef USE_UNBOUND
	{ "UnprotectedKey",		CONFIG_TYPE_STRING,	FALSE },
#endif /* USE_UNBOUND */
#if defined(STANDALONE)
	{ "UserID",			CONFIG_TYPE_STRING,	FALSE },
#endif /* STANDALONE */
#ifdef _FFR_VBR
	{ "VBR-Certifiers",		CONFIG_TYPE_STRING,	FALSE },
	{ "VBR-PurgeFields",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "VBR-TrustedCertifiers",	CONFIG_TYPE_STRING,	FALSE },
	{ "VBR-TrustedCertifiersOnly",	CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "VBR-Type",			CONFIG_TYPE_STRING,	FALSE },
#endif /* _FFR_VBR */
	{ "WeakSyntaxChecks",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "X-Header",			CONFIG_TYPE_BOOLEAN,	FALSE },
	{ NULL,				(u_int) -1,		FALSE }
};

#endif /* _DKIM_CONFIG_H_ */
