//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-27
//
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include <rte_byteorder.h>
#include <rte_memcpy.h>
#include "pg_dns.h"

#define DNS_HDR_SIZE 12

// limit
#define MAX_LABEL_LEN   (63)
#define MAX_DOMAIN_LEN  (255)
#define MAX_UDP_SIZE    (512)

//0 is q,1 is r
#define QR_Q (0)
#define QR_R (1)
#define GET_QR(flag) ((flag & 0x8000) / 0x8000)
#define SET_QR_R(flag) (flag |= 0x8000)
#define SET_QR_Q(flag) (flag &= 0x7fff)
#define GET_OPCODE(flag) ((flag & 0x7800) >> 11)
#define GET_AA(flag) ((flag & 0x0400) / 0x0400)
#define SET_AA(flag) (flag |= 0x0400)
#define GET_TC(flag) ((flag & 0x0200) / 0x0200)
#define SET_TC(flag) (flag |= 0x0200)
#define GET_RD(flag) ((flag & 0x0100) / 0x0100)
#define SET_RD(flag) (flag |= 0x0100)
#define SET_RA(flag) (flag |= 0x0080)
#define GET_ERROR(flag) (flag & 0x7)
#define SET_ERROR(flag,errcode) ((flag) = (((flag) & 0xfff0) + errcode))
#define IS_PTR(os) (os >= 0xc000 && os <= 0xcfff)       //in reply msg
#define GET_OFFSET(offset) (offset & 0x3fff)    //the 2 higher bits set to 0
#define SET_OFFSET(offset) (offset |= 0xc000)
#define IS_EDNS0(flag) (flag > 0x4000 && flag < 0x4fff)

enum {
    DNS_CLASS_IN = 1
};

typedef enum dns_rr_type {
    DNS_TYPE_ANY = 255,   /**< any                                */
    DNS_TYPE_A	= 1,    /**< Host address (A) record.		    */
    DNS_TYPE_NS	= 2,    /**< Authoritative name server (NS)	    */
    DNS_TYPE_CNAME	= 5,	/**< Canonical name (CNAME) record.	    */
    DNS_TYPE_SOA	= 6,    /**< Marks start of zone authority.	    */
    DNS_TYPE_PTR	= 12,	/**< Domain name pointer.		    */
    DNS_TYPE_MX	= 15,	/**< Mail exchange record.		    */
    DNS_TYPE_TXT	= 16,	/**< Text string.			    */
    DNS_TYPE_KEY	= 25,	/**< Key.				    */
    DNS_TYPE_AAAA	= 28,	/**< IPv6 address.			    */
    DNS_TYPE_SRV	= 33,	/**< Server selection (SRV) record.	    */

    DNS_TYPE_OPT	= 41,	/**< DNS options - contains EDNS metadata.  */
    DNS_TYPE_DS	= 43,	/**< DNS Delegation Signer (DS)		    */
    DNS_TYPE_SSHFP	= 44,	/**< DNS SSH Key Fingerprint		    */
    DNS_TYPE_IPSECKEY= 45,	/**< DNS IPSEC Key.			    */
    DNS_TYPE_RRSIG	= 46,	/**< DNS Resource Record signature.	    */
    DNS_TYPE_NSEC	= 47,	/**< DNS Next Secure Name.		    */
    DNS_TYPE_DNSKEY	= 48	/**< DNSSEC Key.			    */
} dns_rr_type;

// dump integer to big endian encode string
static inline void dump16be(uint16_t v, char *buf) {
    uint16_t *tmp16 = (uint16_t *)buf;
    *tmp16 = rte_cpu_to_be_16(v);
}

static int strToDNSType(const char *ss) {
    if (strcasecmp(ss, "A") == 0) return DNS_TYPE_A;
    else if (strcasecmp(ss, "AAAA") == 0) return DNS_TYPE_AAAA;
    else if (strcasecmp(ss, "NS") == 0) return DNS_TYPE_NS;
    else if (strcasecmp(ss, "CNAME") == 0) return DNS_TYPE_CNAME;
    else if (strcasecmp(ss, "MX") == 0) return DNS_TYPE_MX;
    else if (strcasecmp(ss, "SOA") == 0) return DNS_TYPE_SOA;
    else if (strcasecmp(ss, "TXT") == 0) return DNS_TYPE_TXT;
    else if (strcasecmp(ss, "SRV") == 0) return DNS_TYPE_SRV;
    else if (strcasecmp(ss, "PTR") == 0) return DNS_TYPE_PTR;
    return -1;
}

static int dumpDNSHdr(char *buf, size_t size, uint16_t xid, uint16_t flag,
               uint16_t nQd, uint16_t nAn, uint16_t nNs, uint16_t nAr)
{
    if (size < DNS_HDR_SIZE) {
        return -1;
    }
    // ignore the byte order of xid.
    memcpy(buf, &xid, 2);
    buf += 2;
    dump16be(flag, buf);
    buf += 2;
    dump16be(nQd, buf);
    buf += 2;
    dump16be(nAn, buf);
    buf += 2;
    dump16be(nNs, buf);
    buf += 2;
    dump16be(nAr, buf);
    return DNS_HDR_SIZE;
}

static inline int dnsHdr_dump(dnsHdr_t *hdr, char *buf, size_t size) {
    return dumpDNSHdr(buf, size, hdr->xid, hdr->flag, hdr->nQd,
                      hdr->nAnRR, hdr->nNsRR, hdr->nArRR);
}

static int dumpDnsQuestion(char *buf, size_t size, char *name,
                           uint16_t qType, uint16_t qClass)
{
    char *p = buf;
    size_t nameLen = strlen(name) + 1;
    if (size < nameLen+4) {
        return -1;
    }
    memcpy(p, name, nameLen);
    p += nameLen;
    dump16be(qType, p);
    p += 2;
    dump16be(qClass, p);
    return (int) (nameLen + 4);
}

static int dot2lenlabel(char *human, char *label) {
    char *dest = label;
    if (dest == NULL) dest = human;
    size_t totallen = strlen(human);
    *(dest + totallen) = 0;
    char *prev = human + totallen - 1;
    char *src = human + totallen - 2;
    dest = dest + totallen - 1;

    for (; src >= human; src--, dest--) {
        if (*src == '.') {
            *dest = (uint8_t) (prev - src - 1);
            prev = src;
        } else {
            *dest = *src;
        }
    }
    *dest = (uint8_t) (prev - src - 1);
    return 0;
}

static bool endswith(const char *str, const char *suffix) {
    const char *p = str + (strlen(str) - strlen(suffix));
    if (p < str) return false;
    return strcmp(p, suffix) == 0;
}

l4Data_t *dnsQueryNew(char *name, char *type_ss) {
    assert(name != NULL);
    if (type_ss == NULL) type_ss = (char *)"A";

    int errcode;
    uint16_t type;
    l4Data_t *d;
    char buf[4096];
    char name_buf[MAX_DOMAIN_LEN+2];
    char *start = buf;
    dnsHdr_t hdr = {0, 0, 1, 0, 0, 0};
    errcode = strToDNSType(type_ss);
    if (errcode < 0) {
        return NULL;
    }
    type = (uint16_t)errcode;
    d = malloc(sizeof(*d));
    if (d == NULL) return NULL;
    SET_RD(hdr.flag);

    strncpy(name_buf, name, MAX_DOMAIN_LEN);
    if (endswith(name_buf, ".") == false) {
        strncat(name_buf, ".", 2);
    }
    dot2lenlabel(name_buf, NULL);

    dnsHdr_dump(&hdr, start, DNS_HDR_SIZE);
    start += DNS_HDR_SIZE;
    int n = dumpDnsQuestion(start, 4096-DNS_HDR_SIZE, name_buf, type, DNS_CLASS_IN);

    d->len = n + DNS_HDR_SIZE;
    d->data  = malloc(d->len);
    if (d->data == NULL) {
        free(d);
        return NULL;
    }
    rte_memcpy(d->data, buf, d->len);
    d->f = &dnsIncXid;
    return d;
}

void dnsIncXid(l4Data_t *d) {
    uint16_t *p = (uint16_t *)(d->data);
    ++(*p);
}
