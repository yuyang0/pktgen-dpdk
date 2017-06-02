//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-27
//

#ifndef _PG_DNS_H_
#define _PG_DNS_H_ 1

#include <stdint.h>
#include "l4data.h"

typedef struct dnsHdr_s {
    uint16_t xid;
    uint16_t flag;
    uint16_t nQd;
    uint16_t nAnRR;
    uint16_t nNsRR;   // only contains NS records
    uint16_t nArRR;
}__attribute__((__packed__)) dnsHdr_t;

l4Data_t *dnsQueryNew(char *name, char *type);
void dnsIncXid(l4Data_t *d);

#endif /* _PG_DNS_H_ */
