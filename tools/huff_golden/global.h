#ifndef GLOBAL_H
#define GLOBAL_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FATAL_ERROR(...)                                                                           \
    do {                                                                                           \
        fprintf(stderr, __VA_ARGS__);                                                              \
        exit(1);                                                                                   \
    } while (0)
#endif
