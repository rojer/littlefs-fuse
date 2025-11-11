#include "lfs_fuse_crypt.h"

#ifdef LFS_FUSE_ENC_LINUX

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <errno.h>

struct lfs_fuse_crypt_ctx {
  int alg_fd;
  int op_fd;
};

static int lfs_fuse_crypt_crypt(int op_fd, int op, const void *in, size_t len, uint32_t block, uint32_t off, void *out) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    struct af_alg_iv *alg_iv;
    struct iovec iov[1];
    int ret;

    char cbuf[128];

    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &op, sizeof(int));

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    const union lfs_fuse_crypt_data_unit du = {
        .bo = {
            .block = block,
            .off = off,
        },
    };
    alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    alg_iv->ivlen = sizeof(du);
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + sizeof(du));
    memcpy(alg_iv->iv, &du, sizeof(du));

    msg.msg_control = cbuf;
    msg.msg_controllen = (char*)CMSG_NXTHDR(&msg, cmsg) - cbuf;

    iov[0].iov_base = (void *)in;
    iov[0].iov_len = len;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    do {
        ret = sendmsg(op_fd, &msg, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
    } while (0);

    do {
        ret = read(op_fd, out, len);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("read (ciphertext)");
            return -errno;
        }
    } while (0);

    return 0;
}

struct lfs_fuse_crypt_ctx *lfs_fuse_crypt_open(const void *key, size_t key_len) {

    if (key_len != 32 && key_len != 64) {
        return NULL;
    }

    int alg_fd, op_fd;

    alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_fd < 0) {
        return NULL;
    }

    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "skcipher",
        .salg_name = "xts(aes)",
    };

    if (bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(alg_fd);
        return NULL;
    }

    if (setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY, key, key_len) < 0) {
        perror("setsockopt (key)");
        close(alg_fd);
        return NULL;
    }

    op_fd = accept(alg_fd, NULL, 0);
    if (op_fd < 0) {
        close(alg_fd);
        return NULL;
    }

    struct lfs_fuse_crypt_ctx *ctx = calloc(1, sizeof(*ctx));

    ctx->alg_fd = alg_fd;
    ctx->op_fd = op_fd;

    return ctx;
}

int lfs_fuse_crypt_encrypt(struct lfs_fuse_crypt_ctx *ctx, const void *in, size_t len, uint32_t block, uint32_t off, void *out) {
    return lfs_fuse_crypt_crypt(ctx->op_fd, ALG_OP_ENCRYPT, in, len, block, off, out);
}

int lfs_fuse_crypt_decrypt(struct lfs_fuse_crypt_ctx *ctx, const void *in, size_t len, uint32_t block, uint32_t off, void *out) {
    return lfs_fuse_crypt_crypt(ctx->op_fd, ALG_OP_DECRYPT, in, len, block, off, out);
}

void lfs_fuse_crypt_close(struct lfs_fuse_crypt_ctx *ctx) {
    close(ctx->op_fd);
    close(ctx->alg_fd);
    free(ctx);
}
#endif
