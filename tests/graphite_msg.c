#include <string.h>

#include "sput.h"
#include "brubeck.h"

static void try_parse(struct brubeck_graphite_msg *msg, const char *msg_text, double expected) {
	char buffer[64];
	size_t len = strlen(msg_text);
	memcpy(buffer, msg_text, len);

	sput_fail_unless(brubeck_graphite_msg_parse(msg, buffer, len) == 0, msg_text);
	sput_fail_unless(expected == msg->value, "msg.value == expected");
}

void test_graphite_msg__parse_strings(void)
{
        struct brubeck_graphite_msg msg;

        try_parse(&msg, "github.auth.fingerprint.sha1 12\n", 12);
	try_parse(&msg, "github.auth.fingerprint.sha1 2 1455782855\n", 2);
}
