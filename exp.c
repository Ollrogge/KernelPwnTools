#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#include "util/util.h"

// commands
#define DEV_PATH "" // the path the device is placed

// root account without password
static char g_root[] = "root::0:0:root:/root:/bin/sh\n\n\n";
static_assert(sizeof(g_root) == 0x20);

// globals
// (END globals)

int main(void) {}
