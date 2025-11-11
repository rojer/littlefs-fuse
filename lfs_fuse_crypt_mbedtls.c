#include "lfs_fuse_crypt.h"

#ifdef LFS_FUSE_ENC_MBEDTLS

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/aes.h"

struct lfs_fuse_crypt_ctx {
  mbedtls_aes_xts_context ec;
  mbedtls_aes_xts_context dc;
};

struct lfs_fuse_crypt_ctx *lfs_fuse_crypt_open(const void *key, size_t key_len) {

    if (key_len != 32 && key_len != 64) {
        return NULL;
    }

    struct lfs_fuse_crypt_ctx *ctx = calloc(1, sizeof(*ctx));

    if (ctx == NULL) return NULL;

    mbedtls_aes_xts_init(&ctx->ec);
    mbedtls_aes_xts_init(&ctx->dc);

    if (mbedtls_aes_xts_setkey_enc(&ctx->ec, key, key_len * 8) != 0) {
        goto out_err;
    }

    if (mbedtls_aes_xts_setkey_dec(&ctx->dc, key, key_len * 8) != 0) {
        goto out_err;
    }

    return ctx;

out_err:
    mbedtls_aes_xts_free(&ctx->ec);
    mbedtls_aes_xts_free(&ctx->dc);
    free(ctx);
    return NULL;
}

int lfs_fuse_crypt_encrypt(struct lfs_fuse_crypt_ctx *ctx, const void *in, size_t len, uint32_t block, uint32_t off, void *out) {
    const union lfs_fuse_crypt_data_unit du = {
        .bo = {
            .block = block,
            .off = off,
        },
    };
    if (mbedtls_aes_crypt_xts(&ctx->ec, MBEDTLS_AES_ENCRYPT, len, du.bytes, in, out) != 0) {
        return -EIO;
    }
    return 0;
}

int lfs_fuse_crypt_decrypt(struct lfs_fuse_crypt_ctx *ctx, const void *in, size_t len, uint32_t block, uint32_t off, void *out) {
    const union lfs_fuse_crypt_data_unit du = {
        .bo = {
            .block = block,
            .off = off,
        },
    };
    if (mbedtls_aes_crypt_xts(&ctx->dc, MBEDTLS_AES_DECRYPT, len, du.bytes, in, out) != 0) {
        return -EIO;
    }
    return 0;
}

void lfs_fuse_crypt_close(struct lfs_fuse_crypt_ctx *ctx) {
    mbedtls_aes_xts_free(&ctx->ec);
    mbedtls_aes_xts_free(&ctx->dc);
    free(ctx);
}
#endif
