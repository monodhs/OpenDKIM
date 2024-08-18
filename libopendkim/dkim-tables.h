/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, 2014, 2015, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _DKIM_TABLES_H_
#define _DKIM_TABLES_H_

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* tables */
extern struct nametable *keyflags;
extern struct nametable *keyparams;
extern struct nametable *querytypes;
extern struct nametable *results;
extern struct nametable *settypes;
extern struct nametable *sigerrors;
extern struct nametable *sigparams;
#ifdef _FFR_CONDITIONAL
extern struct nametable *mandatory;
#endif /* _FFR_CONDITIONAL */

#endif /* _DKIM_TABLES_H_ */
