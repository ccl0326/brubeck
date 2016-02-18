#ifndef __BRUBECK_GRAPHITE_H__
#define __BRUBECK_GRAPHITE_H__

#include "bloom.h"

struct brubeck_graphite_msg {
        char *key;
        uint16_t key_len;
        value_t value;
        uint32_t timestamp;
};

struct brubeck_graphite {
        struct brubeck_sampler sampler;
        pthread_t *workers;
        unsigned int worker_count;
        unsigned int mmsg_count;
};

int brubeck_graphite_msg_parse(struct brubeck_graphite_msg *msg, char *buffer, size_t length);

struct brubeck_sampler *brubeck_graphite_new(struct brubeck_server *server, json_t *settings);

#endif
