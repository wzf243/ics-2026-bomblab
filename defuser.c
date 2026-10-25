#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

/* All recovered arithmetic is uint32_t arithmetic, including wraparound. */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    if (!out || cap == 0 || count == 0) return 1;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32,
                            i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return 0;
}

int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t lo = (uint32_t)challenge;
    uint32_t hi = (uint32_t)(challenge >> 32);
    uint32_t middle = (uint32_t)(challenge >> 16);
    uint32_t a = (lo + 2u * hi) ^ 0xa1c6u;
    uint32_t b = (middle ^ 0x9507u) + 2u * hi;
    uint32_t value = ((lo + 0x5fc2u) ^ b) ^ a;
    return write_answer(out, cap, &value, 1);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[6];
    values[0] = 3u * (uint32_t)((challenge >> 6) & 63u);
    for (unsigned i = 1; i < 6; ++i) {
        uint32_t part = (uint32_t)((challenge >> (11u + 4u * i)) & 63u);
        values[i] = 3u * (values[i - 1] ^ (part + i));
    }
    return write_answer(out, cap, values, 6);
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t index = (uint32_t)challenge & 7u;
    uint32_t x = (uint32_t)(challenge >> 3) ^ (uint32_t)(challenge >> 32);
    uint32_t value;
    switch (index) {
        case 0: value = 5u * x + 0xfe38u; break;
        case 1: value = (x ^ 0x157u) + (x >> 2); break;
        case 2: value = (2u * x) ^ 0xf38cu; break;
        case 3: value = 3u * x + 0xf393u; break;
        case 4: value = (2u * x) ^ 0xb003u; break;
        case 5: value = 5u * x + 0x2ebd5u; break;
        case 6: value = 5u * x + 0x26142u; break;
        default: value = (x ^ 0xe5b7u) + (x >> 2); break;
    }
    uint32_t values[2] = {index, value};
    return write_answer(out, cap, values, 2);
}

static uint32_t walk(uint32_t target, uint32_t low, uint32_t high, uint32_t salt) {
    uint32_t middle = low + ((high - low) >> 1);
    if (target == middle) return (middle + 0x36u) ^ salt;
    if (target < middle)
        return (5u * walk(target, low, middle - 1u, salt)) ^ (middle + salt) ^ 0x11u;
    return (5u * walk(target, middle + 1u, high, salt)) ^ (middle + salt) ^ 0xeu;
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t target = (uint32_t)challenge & 127u;
    uint32_t salt = (uint32_t)(challenge >> 7) ^ (uint32_t)(challenge >> 32);
    uint32_t value = walk(target, 0, 127, salt);
    return write_answer(out, cap, &value, 1);
}

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    static const struct { unsigned next; uint32_t tag, value; } nodes[12] = {
        {11, 0x73b, 0x44ed}, {12, 0xb6a, 0xad08}, {8, 0xa88, 0xcfa1},
        {0, 0x63b, 0x72ca}, {2, 0x447, 0xcd67}, {10, 0x85d, 0x7dc4},
        {7, 0x27e, 0x22d9}, {3, 0x165, 0x5473}, {6, 0x978, 0xdc19},
        {4, 0x510, 0xacd6}, {9, 0x003, 0x0115}, {1, 0x365, 0xfa8f}
    };
    static const unsigned heads[8] = {5, 10, 9, 4, 2, 8, 6, 7};
    unsigned node = heads[challenge & 7u];
    unsigned count = (unsigned)((challenge >> 3) & 3u) + 1u;
    uint32_t acc = (uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32) ^ 0xc95u;
    uint32_t last_tag = 0;
    for (unsigned i = 0; i < count; ++i) {
        acc = (3u * acc + nodes[node].value) ^ nodes[node].tag;
        last_tag = nodes[node].tag;
        node = nodes[node].next;
    }
    uint32_t values[2] = {acc, last_tag};
    return write_answer(out, cap, values, 2);
}

static uint32_t op0(uint32_t x) { return (8u * x + 0xd772u) ^ (3u * x); }
static uint32_t op1(uint32_t x) { return (x ^ (x >> 1)) + 0x7638u; }
static uint32_t op2(uint32_t x) { return (x ^ 0x5bceu) + 4u * x; }
static uint32_t op3(uint32_t x) { return ((x << 2) | (x >> 30)) ^ 0xd7e4u; }
static uint32_t op4(uint32_t x) { return (x + 0x3d76u) ^ (x >> 2); }
static uint32_t op5(uint32_t x) { return (x >> 2) | (x << 30); }

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    static uint32_t (*const ops[8])(uint32_t) = {op4, op5, op1, op0, op3, op2, op2, op1};
    unsigned first = (unsigned)(challenge & 7u);
    unsigned second = (unsigned)((challenge >> 3) & 7u);
    uint32_t x = (uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32);
    uint32_t value = ops[second](ops[first](x) ^ 0xa3b9u) + 0x78dfu;
    return write_answer(out, cap, &value, 1);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    uint32_t selector = (uint32_t)context & 3u;
    uint32_t c = (uint32_t)challenge ^ (uint32_t)(challenge >> 32);
    uint32_t t = (uint32_t)context ^ (uint32_t)(context >> 32);
    uint32_t mixed = (3u * (c ^ t) + 0xe7cbu) ^ 0x92e1u;
    uint32_t answer = mixed ^ (selector * 0xe7cbu) ^ (uint32_t)(context >> 16);
    uint32_t check = answer ^ ((c >> 7) + t + selector + 0x92e1u);
    if (!out || cap == 0) return 1;
    int size = snprintf(out, cap, "%sOPEN%" PRIu32 " %" PRIu32 " %" PRIu32,
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", selector, answer, check);
    return size < 0 || (size_t)size >= cap;
}
