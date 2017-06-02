//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-31
//

#ifndef _L4DATA_H_
#define _L4DATA_H_ 1

#include <stdlib.h>

struct l4Data_s;
typedef void l4DataUpdateFunc(struct l4Data_s *);

typedef struct l4Data_s {
    void *data;
    size_t len;
    l4DataUpdateFunc *f;
} l4Data_t;

static inline void l4DataDestroy(l4Data_t *d) {
    if (!d) return;
    if (d->data) free(d->data);
    free(d);
}

#define L4DATA_UPDATE(d) if ((d)->f) ((d)->f)(d)

#endif /* _L4DATA_H_ */
