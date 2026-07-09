#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#include "util/util.h"

// commands
#define DEV_PATH "" // the path the device is placed

// constants
#define PAGE 0x1000
#define FAULT_ADDR 0xdead0000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4 * PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET
// (END constants)

// root account without password
static char g_root[] = "root::0:0:root:/root:/bin/sh\n\n\n";
static_assert(sizeof(g_root) == 0x20);

// globals
// (END globals)

int main(void) {}
