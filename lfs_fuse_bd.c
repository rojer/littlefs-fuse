/*
 * Linux user-space block device wrapper
 *
 * Copyright (c) 2022, the littlefs authors.
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "lfs_fuse_bd.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <assert.h>
#if !defined(__FreeBSD__)
#include <sys/ioctl.h>
#include <linux/fs.h>
#elif defined(__FreeBSD__)
#define BLKSSZGET DIOCGSECTORSIZE
#define BLKGETSIZE DIOCGMEDIASIZE
#include <sys/disk.h>
#endif

#include "lfs_fuse_crypt.h"
#include <mtd/mtd-user.h>

struct lfs_fuse_bd_ctx {
    int fd;
    mtd_info_t mtd_info;
    struct lfs_fuse_crypt_ctx *crypt_ctx;
    void *enc_buf;
};


// Block device wrapper for user-space block devices
int lfs_fuse_bd_create(struct lfs_config *cfg, const char *path, const void *key, lfs_size_t key_len) {
    int err = 0;

    struct lfs_fuse_bd_ctx *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) return -ENOMEM;

    ctx->fd = open(path, O_RDWR);
    if (ctx->fd < 0) {
        err = -errno;
        goto out_err;
    }

    if (ioctl(ctx->fd, MEMGETINFO, &ctx->mtd_info) == 0) {
        if (!cfg->block_size) {
            cfg->block_size = ctx->mtd_info.erasesize;
        }
        if (!cfg->block_count) {
            cfg->block_count = ctx->mtd_info.size / cfg->block_size;
        }
    } else {
        // get sector size
        if (!cfg->block_size) {
            long ssize;
            err = ioctl(ctx->fd, BLKSSZGET, &ssize);
            if (err) {
                err = -errno;
                goto out_err;
            }
            cfg->block_size = ssize;
        }

        // get size in sectors
        if (!cfg->block_count) {
            uint64_t size;
            err = ioctl(ctx->fd, BLKGETSIZE64, &size);
            if (err) {
                err = -errno;
                goto out_err;
            }
            cfg->block_count = size / cfg->block_size;
        }
    }

    // setup function pointers
    cfg->read  = lfs_fuse_bd_read;
    cfg->prog  = lfs_fuse_bd_prog;
    cfg->erase = lfs_fuse_bd_erase;
    cfg->sync  = lfs_fuse_bd_sync;

    // setup encryption, if enabled
    if (key_len > 0) {
        ctx->crypt_ctx = lfs_fuse_crypt_open(key, key_len);
        if (ctx->crypt_ctx == NULL) {
            err = -EIO;
            goto out_err;
        }
    }

    cfg->context = ctx;

    return 0;

out_err:
    if (ctx != NULL) {
        if (ctx->fd >= 0) close(ctx->fd);
        free(ctx);
    }
    return err;
}

void lfs_fuse_bd_destroy(const struct lfs_config *cfg) {
    struct lfs_fuse_bd_ctx *ctx = cfg->context;
    if (ctx == NULL) return;
    close(ctx->fd);
    if (ctx->crypt_ctx != 0) {
        lfs_fuse_crypt_close(ctx->crypt_ctx);
        free(ctx->enc_buf);
    }
    free(ctx);
}

int lfs_fuse_bd_read(const struct lfs_config *cfg, lfs_block_t block,
        lfs_off_t off, void *buffer, lfs_size_t size) {
    struct lfs_fuse_bd_ctx *ctx = cfg->context;
    int fd = ctx->fd;
    uint8_t *buffer_ = buffer;

    // check if read is valid
    assert(block < cfg->block_count);

    // go to block
    off_t err = lseek(fd, (off_t)block*cfg->block_size + (off_t)off, SEEK_SET);
    if (err < 0) {
        return -errno;
    }

    lfs_size_t size2 = size;

    // read block
    while (size > 0) {
        ssize_t res = read(fd, buffer_, (size_t)size);
        if (res < 0) {
            if (errno == EINTR) continue;
            return -errno;
        } else if (res == 0) {
            return -EIO;
        }

        buffer_ += res;
        size -= res;
    }

    // decrypt
    if (ctx->crypt_ctx != NULL) {
        lfs_size_t ps = cfg->prog_size;
        uint8_t *p = buffer;
        while (size2 > 0) {
            if (lfs_fuse_crypt_decrypt(ctx->crypt_ctx, p, ps, block, off, p) < 0) {
                return -EIO;
            }
            size2 -= ps;
            off += ps;
            p += ps;
        }
    }

    return 0;
}

int lfs_fuse_bd_prog(const struct lfs_config *cfg, lfs_block_t block,
        lfs_off_t off, const void *buffer, lfs_size_t size) {
    struct lfs_fuse_bd_ctx *ctx = cfg->context;
    int fd = ctx->fd;
    const uint8_t *buffer_ = buffer;

    // check if write is valid
    assert(block < cfg->block_count);

    // go to block
    off_t err = lseek(fd, (off_t)block*cfg->block_size + (off_t)off, SEEK_SET);
    if (err < 0) {
        return -errno;
    }

    uint8_t *enc_buf = NULL;

    // encrypt
    if (ctx->crypt_ctx != NULL) {
        enc_buf = malloc(size);
        lfs_size_t size2 = size;
        lfs_size_t ps = cfg->prog_size;
        uint8_t *p = enc_buf;
        while (size2 > 0) {
            if (lfs_fuse_crypt_encrypt(ctx->crypt_ctx, buffer_, ps, block, off, p) < 0) {
                return -EIO;
            }
            buffer_ += ps;
            size2 -= ps;
            off += ps;
            p += ps;
        }
        buffer_ = enc_buf;
    }

    // write block
    while (size > 0) {
        ssize_t res = write(fd, buffer_, (size_t)size);
        if (res < 0) {
            if (errno == EINTR) continue;
            free(enc_buf);
            return -errno;
        }

        buffer_ += res;
        size -= res;
    }

    free(enc_buf);

    return 0;
}

int lfs_fuse_bd_erase(const struct lfs_config *cfg, lfs_block_t block) {
    struct lfs_fuse_bd_ctx *ctx = cfg->context;
    if (ctx->mtd_info.size == 0) {
        // do nothing
        return 0;
    }
    struct erase_info_user64 ei = {
        .start = block * cfg->block_size,
        .length = cfg->block_size,
    };
    while (true) {
        if (ioctl(ctx->fd, MEMERASE64, &ei) < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        break;
    }
    return 0;
}

int lfs_fuse_bd_sync(const struct lfs_config *cfg) {
    struct lfs_fuse_bd_ctx *ctx = cfg->context;
    if (ctx->mtd_info.size > 0) {
        // do nothing
        return 0;
    }

    int err = fsync(ctx->fd);
    if (err) {
        return -errno;
    }

    return 0;
}
