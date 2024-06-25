#include "lzhtable.h"

// implementation
struct _lzhtable_ *lzhtable_create(size_t length, struct _lzhtable_allocator_ *allocator)
{
    size_t buckets_length = sizeof(struct _lzhtable_bucket_) * length;

    struct _lzhtable_bucket_ *buckets = NULL;
    struct _lzhtable_ *table = NULL;

    if (allocator)
    {
        buckets = allocator->lzhtable_alloc(buckets_length, 0);
        table = allocator->lzhtable_alloc(buckets_length, 0);
    }
    else
    {
        buckets = (struct _lzhtable_bucket_ *)malloc(buckets_length);
        table = (struct _lzhtable_ *)malloc(sizeof(struct _lzhtable_));
    }

    if (!buckets || !table)
    {
        if (allocator)
        {
            allocator->lzhtable_dealloc(buckets, 0);
            allocator->lzhtable_dealloc(table, 0);
        }
        else
        {
            free(buckets);
            free(table);
        }

        return NULL;
    }

    memset(buckets, 0, buckets_length);

    table->m = length;
    table->n = 0;
    table->buckets = buckets;
    table->nodes = NULL;
    table->allocator = allocator;

    return table;
}

void lzhtable_node_destroy(struct _lzhtable_node_ *node, struct _lzhtable_ *table)
{
    if (table->allocator)
        table->allocator->lzhtable_dealloc(node->key, 0);
    else
        free(node->key);

    node->key = NULL;
    node->key_size = 0;
    node->value = NULL;

    node->next_table_node = NULL;
    node->previous_table_node = NULL;

    node->next_bucket_node = NULL;
    node->previous_bucket_node = NULL;

    if (table->allocator)
        table->allocator->lzhtable_dealloc(node, 0);
    else
        free(node);
}

void lzhtable_destroy(struct _lzhtable_ *table)
{
    if (!table)
        return;

    struct _lzhtable_allocator_ *allocator = table->allocator;
    struct _lzhtable_node_ *node = table->nodes;

    while (node)
    {
        struct _lzhtable_node_ *previous = node->previous_table_node;

        lzhtable_node_destroy(node, table);

        node = previous;
    }

    if (allocator)
        allocator->lzhtable_dealloc(table->buckets, 0);
    else
        free(table->buckets);

    table->m = 0;
    table->n = 0;
    table->buckets = NULL;
    table->nodes = NULL;

    if (allocator)
        allocator->lzhtable_dealloc(table, 0);
    else
        free(table);
}

uint32_t jenkins_hash(const uint8_t *key, size_t length)
{
    size_t i = 0;
    uint32_t hash = 0;

    while (i != length)
    {
        hash += key[i++];
        hash += hash << 10;
        hash ^= hash >> 6;
    }

    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;

    return hash;
}

int lzhtable_compare(uint8_t *key, size_t key_size, struct _lzhtable_bucket_ *bucket, struct _lzhtable_node_ **out_node)
{
    struct _lzhtable_node_ *node = bucket->head;

    while (node)
    {
        struct _lzhtable_node_ *next = node->next_bucket_node;

        if (node->key_size == key_size)
        {
            if (memcmp(key, node->key, key_size) == 0)
            {
                if (out_node)
                    *out_node = node;

                return 1;
            }
        }

        node = next;
    }

    return 0;
}

int lzhtable_bucket_insert(uint8_t *key, size_t key_size, void *value, struct _lzhtable_bucket_ *bucket, struct _lzhtable_allocator_ *allocator, struct _lzhtable_node_ **out_node)
{
    uint8_t *key_cpy = NULL;
    struct _lzhtable_node_ *node = NULL;

    if (allocator)
    {
        key_cpy = allocator->lzhtable_alloc(key_size, 0);
        node = allocator->lzhtable_alloc(sizeof(struct _lzhtable_node_), 0);
    }
    else
    {
        key_cpy = malloc(key_size);
        node = (struct _lzhtable_node_ *)malloc(sizeof(struct _lzhtable_node_));
    }

    if (!key_cpy || !node)
    {
        if (allocator)
        {
            allocator->lzhtable_dealloc(key_cpy, 0);
            allocator->lzhtable_dealloc(node, 0);
        }
        else
        {
            free(key_cpy);
            free(node);
        }

        return 1;
    }

    memcpy(key_cpy, key, key_size);

    node->key = key_cpy;
    node->key_size = key_size;
    node->value = value;

    node->previous_table_node = NULL;
    node->next_table_node = NULL;

    node->previous_bucket_node = NULL;
    node->next_bucket_node = NULL;

    if (bucket->head)
    {
        node->previous_bucket_node = bucket->tail;
        bucket->tail->next_bucket_node = node;
    }
    else
        bucket->head = node;

    bucket->size++;
    bucket->tail = node;

    if (out_node)
        *out_node = node;

    return 0;
}

struct _lzhtable_bucket_ *lzhtable_contains(uint8_t *key, size_t key_size, struct _lzhtable_ *table, struct _lzhtable_node_ **node_out)
{
    uint32_t k = jenkins_hash(key, key_size);
    size_t index = k % table->m;

    struct _lzhtable_bucket_ *bucket = &table->buckets[index];

    if (lzhtable_compare(key, key_size, bucket, node_out))
        return bucket;

    return NULL;
}

void *lzhtable_get(uint8_t *key, size_t key_size, struct _lzhtable_ *table)
{
    uint32_t k = jenkins_hash(key, key_size);
    size_t index = k % table->m;

    struct _lzhtable_bucket_ *bucket = &table->buckets[index];
    struct _lzhtable_node_ *node = NULL;

    if (lzhtable_compare(key, key_size, bucket, &node))
        return node->value;

    return NULL;
}

int lzhtable_put(uint8_t *key, size_t key_size, void *value, struct _lzhtable_ *table, uint32_t **hash_out)
{
    uint32_t k = jenkins_hash(key, key_size);
    size_t index = k % table->m;

    struct _lzhtable_bucket_ *bucket = &table->buckets[index];
    struct _lzhtable_node_ *node = NULL;

    if (bucket->size > 0 && lzhtable_compare(key, key_size, bucket, &node))
    {
        node->value = value;
        return 0;
    }

    if (lzhtable_bucket_insert(key, key_size, value, bucket, table->allocator, &node))
        return 1;

    if (hash_out)
        **hash_out = k;

    if (table->nodes)
    {
        table->nodes->next_table_node = node;
        node->previous_table_node = table->nodes;
    }

    table->nodes = node;

    return 0;
}

int lzhtable_remove(uint8_t *key, size_t key_size, struct _lzhtable_ *table, void **value)
{
    uint32_t k = jenkins_hash(key, key_size);
    size_t index = k % table->m;

    struct _lzhtable_bucket_ *bucket = &table->buckets[index];

    if (bucket->size == 0)
        return 0;

    struct _lzhtable_node_ *node = NULL;

    if (lzhtable_compare(key, key_size, bucket, &node))
    {
        if (value)
            *value = node->value;

        if (node == table->nodes)
            table->nodes = node->previous_table_node;

        if (node->previous_table_node)
            node->previous_table_node->next_table_node = node->next_table_node;

        if (node->next_table_node)
            node->next_table_node->previous_table_node = node->previous_table_node;

        if (node->previous_bucket_node)
            node->previous_bucket_node->next_bucket_node = node->next_bucket_node;

        if (node->next_bucket_node)
            node->next_bucket_node->previous_bucket_node = node->previous_bucket_node;

        lzhtable_node_destroy(node, table);

        return 1;
    }

    return 0;
}