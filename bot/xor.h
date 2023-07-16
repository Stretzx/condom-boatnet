#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
#ifdef DEBUG
    BOOL locked;
#endif
};

#define XOR_DOMAIN 1
#define XOR_EXEC 2

#define XOR_PROC 3
#define XOR_EXE 4
#define XOR_FD 5
#define XOR_CMDLINE 6

#define XOR_WATCHDOG1 7
#define XOR_WATCHDOG2 8
#define XOR_WATCHDOG3 9
#define XOR_WATCHDOG4 10
#define XOR_WATCHDOG5 11
#define XOR_WATCHDOG6 12
#define XOR_WATCHDOG7 13
#define XOR_WATCHDOG8 14
#define XOR_PORT 15

#define TABLE_MAX_KEYS 16

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t);
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
