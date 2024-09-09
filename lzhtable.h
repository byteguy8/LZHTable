// Humble implementation of a hash table

#ifndef _LZHTABLE_H_
#define _LZHTABLE_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct _lzhtable_allocator_
{
    void *(*alloc)(size_t byes);
    void *(*realloc)(void *ptr, size_t bytes);
    void (*dealloc)(void *ptr);
} LZHTableAllocator;

typedef struct _lzhtable_node_
{
    uint8_t *key;
    size_t key_size;
    void *value;

    struct _lzhtable_node_ *previous_table_node;
    struct _lzhtable_node_ *next_table_node;

    struct _lzhtable_node_ *previous_bucket_node;
    struct _lzhtable_node_ *next_bucket_node;
} LZHTableNode;

typedef struct _lzhtable_bucket_
{
    size_t size;
    struct _lzhtable_node_ *head;
    struct _lzhtable_node_ *tail;
} LZHTableBucket;

typedef struct _lzhtable_
{
    size_t m; // count of buckets available
    size_t n; // count of distinct elements in the table
    struct _lzhtable_bucket_ *buckets;
    struct _lzhtable_node_ *nodes;
    struct _lzhtable_allocator_ *allocator;
} LZHTable;

// interface
struct _lzhtable_ *lzhtable_create(size_t length, struct _lzhtable_allocator_ *allocator);
void lzhtable_node_destroy(struct _lzhtable_node_ *node, struct _lzhtable_ *table);
void lzhtable_destroy(struct _lzhtable_ *table);

uint32_t jenkins_hash(const uint8_t *key, size_t length);
int lzhtable_compare(uint8_t *key, size_t key_size, struct _lzhtable_bucket_ *bucket, struct _lzhtable_node_ **out_node);
int lzhtable_bucket_insert(uint8_t *key, size_t key_size, void *value, struct _lzhtable_bucket_ *bucket, struct _lzhtable_allocator_ *allocator, struct _lzhtable_node_ **out_node);

struct _lzhtable_bucket_ *lzhtable_contains(uint8_t *key, size_t key_size, struct _lzhtable_ *table, struct _lzhtable_node_ **node_out);
void *lzhtable_get(uint8_t *key, size_t key_size, struct _lzhtable_ *table);
int lzhtable_put(uint8_t *key, size_t key_size, void *value, struct _lzhtable_ *table, uint32_t **hash_out);
int lzhtable_remove(uint8_t *key, size_t key_size, struct _lzhtable_ *table, void **value);

void lzhtable_clear(void (*clear_fn)(void *value), struct _lzhtable_ *table);

#endif