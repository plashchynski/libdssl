#ifndef icmp_h	/* John Chambers' version of icmp.h */
#define icmp_h
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*       Interface Control Message Protocol (ICMP) Definitions.                 *
*                                                                              *
* ICMP is the IP "administrative message" protocol. These messages are used as *
* internal  control  messages  for  the TCP/UDP/IP package.  The most valuable *
* message is the ICMP_ECHO request, aka "ping", but there are lots  of  others *
* that are useful, too.                                                        *
*                                                                              *
* This header file is a merger of the ip_icmp.h files on several Unix systems, *
* included here because some vendors don't see fit  to  include  it  in  their *
* /usr/include/* library. All of the information here is supposed to be public *
* knowledge, and there shouldn't be any problems  with  copying  this  to  any *
* system at all.  Note that we've tried to collect here all the other #include *
* lines that are needed to make ICMP  messages  work.   But  this  isn't  very *
* portable, so you will probably have to make some tweaks of your own...       *
*                                                                              *
* Due to the stupid problems with incompatible definitions of such  things  as *
* the u_short/ushort type, I've taken the liberty of converting things here to *
* use definitions from my debug package.  I hope it's all self-explanatory. If *
* not, look in V.h for further details.                                      *
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#ifdef SYSLOG
#include <syslog.h>
#endif
//#include <sys/param.h>
/* #include <sys/socket.h> */
//#include <sys/file.h>
//#include <sys/ioctl.h>

//#include "sys_netdb.h" 

#if defined(BSD) || defined(ULTRIX) || defined(SUN) || defined(SunOS) || defined(Darwin)
#include <netinet/in_systm.h>

#ifndef IPPROTO_IP
#include <netinet/in.h>
#endif
#include "ip.h"
#include <sys/wait.h>
#elif defined(SYS5) || defined(ESIX) || defined(Linux)
#include "ip.h"
#include "iphdr.h"
#else
#endif
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
* Here is the structure of an ICMP packet header, including  a  short  defined *
* name  for the structure.  Alternative names are included, to try to cover as *
* many of the different naming conventions as are known. The layout of an ICMP *
* header (shamelessly copied from Doug Comer's book) is as follows.  Note that *
* the bit and byte numbering is littlendian and zero-based, unlike the network *
* byte order, which is bigendian.  The Internet gang loves such inconsistency. *
*                                                                              *
* byte:  0               1               2               3                     *
*  bit:  0   2   4   6   8  10  12  14  16  18  20  22  24  26  28  30  32     *
*       +---------------+---------------+---------------+---------------+      *
*       |      type     |     code      |           checksum            |      *
*       +---------------+---------------+---------------+---------------+      *
*       |          identifier           |        sequence number        |      *
*       +---------------+---------------+---------------+---------------+      *
*       |                         optional data                         |      *
*       +---------------+---------------+---------------+---------------+      *
*       |                             . . .                             |      *
*       +---------------+---------------+---------------+---------------+      *
*                                                                              *
* It is often easier to declare 8-bit, 16-bit and 32-bit  pointers  and  index *
* into  the  packet  than it is to use a C struct, but most programmers prefer *
* the confusion of using the struct, and much code has been written  doing  it *
* that way, so here is our attempt to merge various structs:                   *
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#define ICMP struct icmp
ICMP {
	U8  icmp_type;		/* Message type */
	U8  icmp_code;		/* Type extension */
	U16 icmp_cksum;		/* Ones complement cksum of ICMP packet */
	union {
		U8     ih_pptr;		/* ICMP_PARAMPROB */
		struct in_addr ih_gwaddr;	/* ICMP_REDIRECT */
		struct ih_idseq {	/* Most other messages */
			U16	icd_id;
			U16	icd_seq;
		} ih_idseq;
		I32 ih_void;
	} icmp_hun;
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
	union {
		struct id_ts {
			U32 its_otime;
			U32 its_rtime;
			U32 its_ttime;
		} id_ts;
		struct id_ip  {
			struct ip idi_ip;	/* Options and 64 bits of data */
		} id_ip;
		U32 id_mask;
		char id_data[1];
	} icmp_dun;
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define icmp_mask	icmp_dun.id_mask
#define icmp_data	icmp_dun.id_data
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
* Lower bounds on packet lengths for various  types.   For  the  error  advice *
* packets  must  first  insure that the packet is large enought to contain the *
* returned ip header.  Only then can we do the check to  see  if  64  bits  of *
* packet  data  have  been  returned,  since  we need to check the returned ip *
* header length.                                                               *
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#ifndef	ICMP_MINLEN
#define	ICMP_MINLEN      8				/* abs minimum */
#define	ICMP_TSLEN      (8 +(3 * sizeof (U32)))	/* timestamp */
#define ICMP_MASKLEN    12				/* address mask */
#define	ICMP_ADVLENMIN  (8 + sizeof(struct ip) + 8)	/* min */
#define	ICMP_ADVLEN(p)  (8 + ((p)->icmp_ip.ip_hl << 2) + 8)
#endif				 /* N.B.: must separately check that ip_hl >= 5 */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
* Definitions of type and code field values.
*/
#ifndef	ICMP_ECHOREPLY
#define	ICMP_ECHOREPLY              0	/* echo reply */
#define	ICMP_UNREACH                3	/* dest unreachable, codes: */
#define		ICMP_UNREACH_NET        0	/* bad net */
#define		ICMP_UNREACH_HOST       1	/* bad host */
#define		ICMP_UNREACH_PROTOCOL   2	/* bad protocol */
#define		ICMP_UNREACH_PORT       3	/* bad port */
#define		ICMP_UNREACH_NEEDFRAG   4	/* IP_DF caused drop */
#define		ICMP_UNREACH_SRCFAIL    5	/* src route failed */
#define	ICMP_SOURCEQUENCH           4	/* packet lost, slow down */
#define	ICMP_REDIRECT               5	/* shorter route, codes: */
#define		ICMP_REDIRECT_NET       0	/* for network */
#define		ICMP_REDIRECT_HOST      1	/* for host */
#define		ICMP_REDIRECT_TOSNET    2	/* for tos and net */
#define		ICMP_REDIRECT_TOSHOST   3	/* for tos and host */
#define	ICMP_ECHO                   8	/* echo service */
#define	ICMP_TIMXCEED              11	/* time exceeded, code: */
#define		ICMP_TIMXCEED_INTRANS   0	/* ttl==0 in transit */
#define		ICMP_TIMXCEED_REASS     1	/* ttl==0 in reass */
#define	ICMP_PARAMPROB             12	/* ip header bad */
#define	ICMP_TSTAMP                13	/* timestamp request */
#define	ICMP_TSTAMPREPLY           14	/* timestamp reply */
#define	ICMP_IREQ                  15	/* information request */
#define	ICMP_IREQREPLY             16	/* information reply */
#define	ICMP_MASKREQ               17	/* address mask request */
#define	ICMP_MASKREPLY             18	/* address mask reply */
#endif

#ifndef ICMP_MAXTYPE
#define ICMP_MAXTYPE		18
#endif

#ifndef ICMP_INFOTYPE
#define ICMP_INFOTYPE(type) \
	(((type) == ICMP_ECHOREPLY) || ((type) == ICMP_ECHO) || \
	 ((type) == ICMP_TSTAMP   ) || ((type) == ICMP_TSTAMPREPLY) || \
	 ((type) == ICMP_IREQ     ) || ((type) == ICMP_IREQREPLY) || \
	 ((type) == ICMP_MASKREQ  ) || ((type) == ICMP_MASKREPLY))
#endif

extern char *ICMPtype();
extern char *IPproto();
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
* Here are some globals that our ping() subroutine offers to the caller.  You
* should compile and link the icmp.o module if you use these.
*/
extern int ipackets, opackets;	/* Packet counts for ping() in icmp.c */
extern int pinginterval;	/* How often to ping */
extern int pingtimeout;	/* When to give up */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
* Here is a kludge to get around the flakiness of the timeout structure  in  a
* lot of <sys/time.h> files.  Note our subtle respelling of the name, to avoid
* conflicts with existing libraries (and save a keystroke here and there ;-).
*/
#define TIMO struct timout
TIMO {
	long tv_sec;	/* seconds */
	long tv_usec;	/* microseconds */
};
#if SNMPD > 0
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
* The following stuff is for the SNMP agent.  Since there is just a little bit
* of confusion about the naming convention here, we define both of the names.
*/
#include "snmptype.h"

#define Snmp_icmp_stat struct snmp_icmp_stat 
#define Snmp_icmp_data struct snmp_icmp_stat
Snmp_icmp_stat {
	Counter  icmpInMsgs;
	Counter  icmpInErrors;
	Counter  icmpInDestUnreachs;
	Counter  icmpInTimeExcds;
	Counter  icmpInParmProbs;
	Counter  icmpInSrcQuenchs;
	Counter  icmpInRedirects;
	Counter  icmpInEchos;
	Counter  icmpInEchoReps;
	Counter  icmpInTimestamps;
	Counter  icmpInTimestampReps;
	Counter  icmpInAddrMasks;
	Counter  icmpInAddrMaskReps;
	Counter  icmpOutMsgs;
	Counter  icmpOutErrors;
	Counter  icmpOutDestUnreachs;
	Counter  icmpOutTimeExcds;
	Counter  icmpOutParmProbs;
	Counter  icmpOutSrcQuenchs;
	Counter  icmpOutRedirects;
	Counter  icmpOutEchos;
	Counter  icmpOutEchoReps;
	Counter  icmpOutTimestamps;
	Counter  icmpOutTimestampReps;
	Counter  icmpOutAddrMasks;
	Counter  icmpOutAddrMaskReps;
};
extern  Snmp_icmp_stat icmp_stat;	/* In lu_icmp */
#define ICMPD struct snmp_icmp_stat		/* For lazy typists */
#endif

#endif

