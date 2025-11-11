#pragma once

#include <stddef.h>
#include <stdint.h>

// #define LFS_FUSE_ENC_LINUX
#define LFS_FUSE_ENC_MBEDTLS

struct lfs_fuse_crypt_ctx;

struct lfs_fuse_crypt_ctx *lfs_fuse_crypt_open(const void *key, size_t key_len);

int lfs_fuse_crypt_encrypt(struct lfs_fuse_crypt_ctx *ctx, const void *in, size_t len, uint32_t block, uint32_t off, void *out);

int lfs_fuse_crypt_decrypt(struct lfs_fuse_crypt_ctx *ctx, const void *in, size_t len, uint32_t block, uint32_t off, void *out);

void lfs_fuse_crypt_close(struct lfs_fuse_crypt_ctx *ctx);

union lfs_fuse_crypt_data_unit {
    struct {
        uint64_t block;
        uint64_t off;
    } bo;
    uint8_t bytes[16];
};
