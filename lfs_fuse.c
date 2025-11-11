/*
 * FUSE wrapper for the littlefs
 *
 * Copyright (c) 2022, the littlefs authors.
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#define _GNU_SOURCE
#define FUSE_USE_VERSION 26

#ifdef linux
// needed for a few things fuse depends on
#define _XOPEN_SOURCE 700
#endif

#include <fuse/fuse.h>
#include "lfs.h"
#include "lfs_util.h"
#include "lfs_fuse_bd.h"

#include <stdio.h>
#include <inttypes.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <unistd.h>

// littefs-fuse version
//
// Note this is different from the littlefs core version, and littlefs
// on-disk version
//
// Major (top-nibble), incremented on backwards incompatible changes
// Minor (bottom-nibble), incremented on feature additions
#define LFS_FUSE_VERSION 0x00020007
#define LFS_FUSE_VERSION_MAJOR (0xffff & (LFS_FUSE_VERSION >> 16))
#define LFS_FUSE_VERSION_MINOR (0xffff & (LFS_FUSE_VERSION >>  0))


// config and other state
static struct lfs_config config = {0};
static const char *device = NULL;
static bool stat_ = false;
static bool format = false;
static bool migrate = false;
static lfs_t lfs;

static uint8_t s_key[64] = {0};
size_t s_key_len = 0;

static unsigned long s_mount_flags = 0;
static char *s_mountpoint = NULL;

#define RELATIME_THRESHOLD (24 * 60 * 60)
// #define RELATIME_THRESHOLD 10 // For testing

#define LFS_ATTR_UTIMENS 0x54 // 'T'

struct lfs_timens {
    uint32_t sec;
    uint32_t nsec;
} __attribute__((packed));

struct lfs_attr_utimens {
    struct lfs_timens ctime;
    struct lfs_timens mtime;
    struct lfs_timens atime;
} __attribute__((packed));

static void lfs_ts_to_tns(const struct timespec *ts, struct lfs_timens *tns) {
  tns->sec = ts->tv_sec;
  tns->nsec = ts->tv_nsec;
}

static void lfs_tv_to_tns(const struct timeval *tv, struct lfs_timens *tns) {
  tns->sec = tv->tv_sec;
  tns->nsec = tv->tv_usec * 1000;
}

static bool lfs_get_utimens(lfs_t *lfs, const char *path, struct lfs_attr_utimens *ut) {
  return (lfs_getattr(lfs, path, LFS_ATTR_UTIMENS, ut, sizeof(*ut)) >= sizeof(*ut));
}

static bool lfs_set_utimens(lfs_t *lfs, const char *path, const struct lfs_attr_utimens *ut) {
  return (lfs_setattr(lfs, path, LFS_ATTR_UTIMENS, ut, sizeof(*ut)) == LFS_ERR_OK);
}

static bool check_relatime(const struct timeval *now, struct lfs_attr_utimens *uts) {
  bool a = true;
  if (s_mount_flags & ST_RELATIME) {
      const uint32_t m_sec = uts->mtime.sec;
      const uint32_t a_sec = uts->atime.sec;
      if (a_sec >= m_sec && now->tv_sec - a_sec < RELATIME_THRESHOLD) {
          a = false;
      }
  }
  if (a) {
      lfs_tv_to_tns(now, &uts->atime);
  }
  return a;
}

static void lfs_update_utimens(lfs_t *lfs, const char *path, bool c, bool m, bool a) {
  if (a && !c && !m && (s_mount_flags & ST_NOATIME)) {
    return;
  }
  struct timeval now;
  gettimeofday(&now, NULL);
  struct lfs_attr_utimens uts = {0};
  if (!lfs_get_utimens(lfs, path, &uts)) {
    c = m = a = true;
  }
  if (c) lfs_tv_to_tns(&now, &uts.ctime);
  if (m) lfs_tv_to_tns(&now, &uts.mtime);
  if (a) {
    a = (m || check_relatime(&now, &uts));
    if (!a && !c && !m) return;
  }
  lfs_set_utimens(lfs, path, &uts);
}

static bool lfs_file_get_utimens(lfs_t *lfs, lfs_file_t *file, struct lfs_attr_utimens *ut) {
  return (lfs_file_getattr(lfs, file, LFS_ATTR_UTIMENS, ut, sizeof(*ut)) >= sizeof(*ut));
}

static bool lfs_file_set_utimens(lfs_t *lfs, lfs_file_t *file, const struct lfs_attr_utimens *ut) {
  return (lfs_file_setattr(lfs, file, LFS_ATTR_UTIMENS, ut, sizeof(*ut)) == LFS_ERR_OK);
}

static void lfs_file_update_utimens(lfs_t *lfs, lfs_file_t *file, bool c, bool m, bool a) {
  if (a && !c && !m && (s_mount_flags & ST_NOATIME)) {
    return;
  }
  struct timeval now;
  gettimeofday(&now, NULL);
  struct lfs_attr_utimens uts = {0};
  if (!lfs_file_get_utimens(lfs, file, &uts)) {
    c = m = a = true;
  }
  if (c) lfs_tv_to_tns(&now, &uts.ctime);
  if (m) lfs_tv_to_tns(&now, &uts.mtime);
  if (a) {
    a = (m || check_relatime(&now, &uts));
    if (!a && !c && !m) return;
  }
  lfs_file_set_utimens(lfs, file, &uts);
}

#define LFS_ATTR_UNIX 0x55 // 'U'

struct lfs_attr_unix {
    uint32_t uid;
    uint32_t gid;
    uint32_t mode;
} __attribute__((packed));

static bool lfs_get_unix(lfs_t *lfs, const char *path, struct lfs_attr_unix *ua) {
  return (lfs_getattr(lfs, path, LFS_ATTR_UNIX, ua, sizeof(*ua)) >= sizeof(*ua));
}

static bool lfs_set_unix(lfs_t *lfs, const char *path, const struct lfs_attr_unix *ua) {
  return (lfs_setattr(lfs, path, LFS_ATTR_UNIX, ua, sizeof(*ua)) == LFS_ERR_OK);
}

static bool lfs_file_set_unix(lfs_t *lfs, lfs_file_t *file, const struct lfs_attr_unix *ua) {
  return (lfs_file_setattr(lfs, file, LFS_ATTR_UNIX, ua, sizeof(*ua)) == LFS_ERR_OK);
}

// actual fuse functions
void lfs_fuse_defaults(struct lfs_config *config) {
    // default to 512 erase cycles, arbitrary value
    if (!config->block_cycles) {
        config->block_cycles = 512;
    }

    // defaults, ram is less of a concern here than what
    // littlefs is used to, so these may end up a bit funny
    if (!config->prog_size) {
        config->prog_size = config->block_size;
    }

    if (!config->read_size) {
        config->read_size = config->block_size;
    }

    if (!config->cache_size) {
        config->cache_size = config->block_size;
    }

    // arbitrary, though we have a lot of RAM here
    if (!config->lookahead_size) {
        config->lookahead_size = 8192;
    }
}

static void *get_mount_opts(void *arg) {
    struct statvfs res = {0};
    if (statvfs(s_mountpoint, &res) == 0) {
        s_mount_flags = res.f_flag;
    }
    return NULL;
}

void *lfs_fuse_init(struct fuse_conn_info *conn) {

    // it's kind of silly but this appears to be the only way
    // to access our own mount options
    static pthread_t stat_thr;
    pthread_create(&stat_thr, NULL, get_mount_opts, NULL);

    // set that we want to take care of O_TRUNC
    conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;

    // we also support writes of any size
    conn->want |= FUSE_CAP_BIG_WRITES;

    return 0;
}

int lfs_fuse_stat(void) {
    int err = lfs_fuse_bd_create(&config, device, s_key, s_key_len);
    if (err) {
        return err;
    }

    lfs_fuse_defaults(&config);

    err = lfs_mount(&lfs, &config);
    if (err) {
        goto failed;
    }

    // get on-disk info
    struct lfs_fsinfo fsinfo;
    err = lfs_fs_stat(&lfs, &fsinfo);
    if (err) {
        goto failed;
    }

    // get block usage
    lfs_ssize_t in_use = lfs_fs_size(&lfs);
    if (in_use < 0) {
        err = in_use;
        goto failed;
    }

    // print to stdout
    printf("disk_version: lfs%d.%d\n",
            0xffff & (fsinfo.disk_version >> 16),
            0xffff & (fsinfo.disk_version >>  0));
    printf("block_size: %d\n", config.block_size);
    printf("block_count: %d\n", config.block_count);
    printf("  used: %d/%d (%.1f%%)\n",
            in_use,
            config.block_count,
            100.0f * (float)in_use / (float)config.block_count);
    printf("  free: %d/%d (%.1f%%)\n",
            config.block_count-in_use,
            config.block_count,
            100.0f * (float)(config.block_count-in_use)
                / (float)config.block_count);
    printf("name_max: %d\n", fsinfo.name_max);
    printf("file_max: %d\n", fsinfo.file_max);
    printf("attr_max: %d\n", fsinfo.attr_max);

    err = lfs_unmount(&lfs);

failed:
    lfs_fuse_bd_destroy(&config);
    return err;
}

int lfs_fuse_format(void) {
    int err = lfs_fuse_bd_create(&config, device, s_key, s_key_len);
    if (err) {
        return err;
    }

    lfs_fuse_defaults(&config);

    err = lfs_format(&lfs, &config);

    if (lfs_mount(&lfs, &config) == 0)  {
      lfs_update_utimens(&lfs, "/", true, true, true);
      const struct lfs_attr_unix ua = {
        .uid = geteuid(),
        .gid = getegid(),
        .mode = S_IFDIR | S_IRWXU | (S_IRGRP | S_IXGRP) | (S_IROTH | S_IXOTH),
      };
      lfs_set_unix(&lfs, "/", &ua);
      lfs_unmount(&lfs);
    }

    lfs_fuse_bd_destroy(&config);
    return err;
}

int lfs_fuse_migrate(void) {
    int err = lfs_fuse_bd_create(&config, device, s_key, s_key_len);
    if (err) {
        return err;
    }

    lfs_fuse_defaults(&config);

    err = lfs_migrate(&lfs, &config);

    lfs_fuse_bd_destroy(&config);
    return err;
}

int lfs_fuse_mount(void) {
    int err = lfs_fuse_bd_create(&config, device, s_key, s_key_len);
    if (err) {
        return err;
    }

    lfs_fuse_defaults(&config);

    return lfs_mount(&lfs, &config);
}

void lfs_fuse_destroy(void *eh) {
    lfs_unmount(&lfs);
    lfs_fuse_bd_destroy(&config);
}

int lfs_fuse_statfs(const char *path, struct statvfs *s) {
    memset(s, 0, sizeof(struct statvfs));

    // get the on-disk name_max from littlefs
    struct lfs_fsinfo fsinfo;
    int err = lfs_fs_stat(&lfs, &fsinfo);
    if (err) {
        return err;
    }

    // get the filesystem block usage from littlefs
    lfs_ssize_t in_use = lfs_fs_size(&lfs);
    if (in_use < 0) {
        return in_use;
    }

    s->f_bsize = config.block_size;
    s->f_frsize = config.block_size;
    s->f_blocks = config.block_count;
    s->f_bfree = config.block_count - in_use;
    s->f_bavail = config.block_count - in_use;
    s->f_namemax = fsinfo.name_max;

    return 0;
}

static void lfs_fuse_tostat(struct stat *s, struct lfs_info *info) {
    memset(s, 0, sizeof(struct stat));

    s->st_size = info->size;
    s->st_mode = S_IRWXU | S_IRWXG | S_IRWXO;

    switch (info->type) {
        case LFS_TYPE_DIR: s->st_mode |= S_IFDIR; break;
        case LFS_TYPE_REG: s->st_mode |= S_IFREG; break;
    }
}

int lfs_fuse_getattr(const char *path, struct stat *s) {
    struct lfs_info info;
    int err = lfs_stat(&lfs, path, &info);
    if (err) {
        return err;
    }

    lfs_fuse_tostat(s, &info);

    struct lfs_attr_utimens uts;
    if (lfs_get_utimens(&lfs, path, &uts)) {
      s->st_ctime = uts.ctime.sec;
      s->st_mtime = uts.mtime.sec;
      s->st_atime = uts.atime.sec;
    }

    struct lfs_attr_unix ua;
    if (lfs_get_unix(&lfs, path, &ua)) {
      s->st_uid = ua.uid;
      s->st_gid = ua.gid;
      s->st_mode = ua.mode;
    }

    return 0;
}

int lfs_fuse_access(const char *path, int mask) {
    struct lfs_info info;
    return lfs_stat(&lfs, path, &info);
}

int lfs_fuse_mkdir(const char *path, mode_t mode) {
    int res = lfs_mkdir(&lfs, path);
    if (res == 0) {
      lfs_update_utimens(&lfs, path, true, true, true);
      struct fuse_context *ctx = fuse_get_context();
      const struct lfs_attr_unix ua = {
        .uid = ctx->uid,
        .gid = ctx->gid,
        .mode = (S_IFDIR | mode),
      };
      lfs_set_unix(&lfs, path, &ua);
    }
    return res;
}

int lfs_fuse_opendir(const char *path, struct fuse_file_info *fi) {
    lfs_dir_t *dir = malloc(sizeof(lfs_dir_t));
    memset(dir, 0, sizeof(lfs_dir_t));

    int err = lfs_dir_open(&lfs, dir, path);
    if (err) {
        free(dir);
        return err;
    }

    fi->fh = (uint64_t)dir;
    return 0;
}

int lfs_fuse_releasedir(const char *path, struct fuse_file_info *fi) {
    lfs_dir_t *dir = (lfs_dir_t*)fi->fh;

    int err = lfs_dir_close(&lfs, dir);
    free(dir);
    return err;
}

int lfs_fuse_readdir(const char *path, void *buf,
        fuse_fill_dir_t filler, off_t offset,
        struct fuse_file_info *fi) {

    lfs_dir_t *dir = (lfs_dir_t*)fi->fh;
    struct stat s;
    struct lfs_info info;

    while (true) {
        int err = lfs_dir_read(&lfs, dir, &info);
        if (err != 1) {
            return err;
        }

        lfs_fuse_tostat(&s, &info);
        filler(buf, info.name, &s, 0);
    }
}

int lfs_fuse_rename(const char *from, const char *to) {
    return lfs_rename(&lfs, from, to);
}

int lfs_fuse_unlink(const char *path) {
    return lfs_remove(&lfs, path);
}

int lfs_fuse_open(const char *path, struct fuse_file_info *fi) {
    lfs_file_t *file = malloc(sizeof(lfs_file_t));
    memset(file, 0, sizeof(lfs_file_t));

    int flags = 0;
    if ((fi->flags & 3) == O_RDONLY) flags |= LFS_O_RDONLY;
    if ((fi->flags & 3) == O_WRONLY) flags |= LFS_O_WRONLY;
    if ((fi->flags & 3) == O_RDWR)   flags |= LFS_O_RDWR;
    if (fi->flags & O_CREAT)         flags |= LFS_O_CREAT;
    if (fi->flags & O_EXCL)          flags |= LFS_O_EXCL;
    if (fi->flags & O_TRUNC)         flags |= LFS_O_TRUNC;
    if (fi->flags & O_APPEND)        flags |= LFS_O_APPEND;

    int err = lfs_file_open(&lfs, file, path, flags);
    if (err) {
        free(file);
        return err;
    }

    fi->fh = (uint64_t)file;
    return 0;
}

int lfs_fuse_release(const char *path, struct fuse_file_info *fi) {
    lfs_file_t *file = (lfs_file_t*)fi->fh;

    int err = lfs_file_close(&lfs, file);
    free(file);
    return err;
}

int lfs_fuse_fgetattr(const char *path, struct stat *s,
        struct fuse_file_info *fi) {
    lfs_file_t *file = (lfs_file_t*)fi->fh;

    lfs_fuse_tostat(s, &(struct lfs_info){
        .size = lfs_file_size(&lfs, file),
        .type = LFS_TYPE_REG,
    });

    return 0;
}

int lfs_fuse_read(const char *path, char *buf, size_t size,
        off_t off, struct fuse_file_info *fi) {
    lfs_file_t *file = (lfs_file_t*)fi->fh;

    if (lfs_file_tell(&lfs, file) != off) {
        lfs_soff_t soff = lfs_file_seek(&lfs, file, off, LFS_SEEK_SET);
        if (soff < 0) {
            return soff;
        }
    }

    int ret = lfs_file_read(&lfs, file, buf, size);
    if (ret > 0) {
      lfs_file_update_utimens(&lfs, file, false, false, true);
    }
    return ret;
}

int lfs_fuse_write(const char *path, const char *buf, size_t size,
        off_t off, struct fuse_file_info *fi) {
    lfs_file_t *file = (lfs_file_t*)fi->fh;

    if (lfs_file_tell(&lfs, file) != off) {
        lfs_soff_t soff = lfs_file_seek(&lfs, file, off, LFS_SEEK_SET);
        if (soff < 0) {
            return soff;
        }
    }

    int ret = lfs_file_write(&lfs, file, buf, size);
    if (ret > 0) {
      lfs_file_update_utimens(&lfs, file, true, true, false);
    }
    return ret;
}

int lfs_fuse_fsync(const char *path, int isdatasync,
        struct fuse_file_info *fi) {
    lfs_file_t *file = (lfs_file_t*)fi->fh;
    return lfs_file_sync(&lfs, file);
}

int lfs_fuse_flush(const char *path, struct fuse_file_info *fi) {
    lfs_file_t *file = (lfs_file_t*)fi->fh;
    return lfs_file_sync(&lfs, file);
}

int lfs_fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    int err = lfs_fuse_open(path, fi);
    if (err) {
        return err;
    }

    struct fuse_context *ctx = fuse_get_context();
    lfs_file_t *file = (lfs_file_t*)fi->fh;
    const struct lfs_attr_unix ua = {
        .uid = ctx->uid,
        .gid = ctx->gid,
        .mode = mode,
    };
    lfs_file_set_unix(&lfs, file, &ua);
    lfs_file_update_utimens(&lfs, file, true, true, true);

    return lfs_fuse_fsync(path, 0, fi);
}

int lfs_fuse_ftruncate(const char *path, off_t size,
        struct fuse_file_info *fi) {
    lfs_file_t *file = (lfs_file_t*)fi->fh;
    return lfs_file_truncate(&lfs, file, size);
}

int lfs_fuse_truncate(const char *path, off_t size) {
    lfs_file_t file;
    int err = lfs_file_open(&lfs, &file, path, LFS_O_WRONLY);
    if (err) {
        return err;
    }

    err = lfs_file_truncate(&lfs, &file, size);
    if (err) {
        return err;
    }

    return lfs_file_close(&lfs, &file);
}

// unsupported functions
int lfs_fuse_link(const char *from, const char *to) {
    // not supported, fail
    return -EPERM;
}

int lfs_fuse_mknod(const char *path, mode_t mode, dev_t dev) {
    // not supported, fail
    return -EPERM;
}

int lfs_fuse_chmod(const char *path, mode_t mode) {
    struct lfs_attr_unix ua;
    if (!lfs_get_unix(&lfs, path, &ua)) return -EIO;
    ua.mode = mode;
    if (!lfs_set_unix(&lfs, path, &ua)) return EIO;
    lfs_update_utimens(&lfs, path, true, false, false);
    return 0;
}

int lfs_fuse_chown(const char *path, uid_t uid, gid_t gid) {
    struct lfs_attr_unix ua;
    if (!lfs_get_unix(&lfs, path, &ua)) return -EIO;
    ua.uid = uid;
    ua.gid = gid;
    if (!lfs_set_unix(&lfs, path, &ua)) return EIO;
    lfs_update_utimens(&lfs, path, true, false, false);
    return 0;
}

int lfs_fuse_utimens(const char *path, const struct timespec ts[2]) {
    struct lfs_attr_utimens uts = {0};
    lfs_get_utimens(&lfs, path, &uts);
    lfs_ts_to_tns(&ts[1], &uts.mtime);
    lfs_ts_to_tns(&ts[0], &uts.atime);
    return (lfs_set_utimens(&lfs, path, &uts) ? 0 : -EIO);
}

static struct fuse_operations lfs_fuse_ops = {
    .init       = lfs_fuse_init,
    .destroy    = lfs_fuse_destroy,
    .statfs     = lfs_fuse_statfs,

    .getattr    = lfs_fuse_getattr,
    .access     = lfs_fuse_access,

    .mkdir      = lfs_fuse_mkdir,
    .rmdir      = lfs_fuse_unlink,
    .opendir    = lfs_fuse_opendir,
    .releasedir = lfs_fuse_releasedir,
    .readdir    = lfs_fuse_readdir,

    .rename     = lfs_fuse_rename,
    .unlink     = lfs_fuse_unlink,

    .open       = lfs_fuse_open,
    .create     = lfs_fuse_create,
    .truncate   = lfs_fuse_truncate,
    .release    = lfs_fuse_release,
    .fgetattr   = lfs_fuse_fgetattr,
    .read       = lfs_fuse_read,
    .write      = lfs_fuse_write,
    .fsync      = lfs_fuse_fsync,
    .flush      = lfs_fuse_flush,

    .link       = lfs_fuse_link,
    .symlink    = lfs_fuse_link,
    .mknod      = lfs_fuse_mknod,
    .chmod      = lfs_fuse_chmod,
    .chown      = lfs_fuse_chown,
    .utimens    = lfs_fuse_utimens,

    .flag_nopath = true,
};


// binding into fuse and general ui
enum lfs_fuse_keys {
    KEY_HELP,
    KEY_VERSION,
    KEY_STAT,
    KEY_FORMAT,
    KEY_MIGRATE,
    KEY_DISK_VERSION,
    KEY_KEY_FILE,
};

#define OPT(t, p) { t, offsetof(struct lfs_config, p), 0}
static struct fuse_opt lfs_fuse_opts[] = {
    FUSE_OPT_KEY("--stat",      KEY_STAT),
    FUSE_OPT_KEY("--format",    KEY_FORMAT),
    FUSE_OPT_KEY("--migrate",   KEY_MIGRATE),
    {"-d=",                     -1U, KEY_DISK_VERSION},
    {"--disk_version=",         -1U, KEY_DISK_VERSION},
    OPT("-b=%"                  SCNu32, block_size),
    OPT("--block_size=%"        SCNu32, block_size),
    OPT("--block_count=%"       SCNu32, block_count),
    OPT("--block_cycles=%"      SCNu32, block_cycles),
    OPT("--read_size=%"         SCNu32, read_size),
    OPT("--prog_size=%"         SCNu32, prog_size),
    OPT("--cache_size=%"        SCNu32, cache_size),
    OPT("--lookahead_size=%"    SCNu32, lookahead_size),
    OPT("--name_max=%"          SCNu32, name_max),
    OPT("--file_max=%"          SCNu32, file_max),
    OPT("--attr_max=%"          SCNu32, attr_max),
    {"-k=",                     -1U, KEY_KEY_FILE},
    {"--key=",                  -1U, KEY_KEY_FILE},
    FUSE_OPT_KEY("-V",          KEY_VERSION),
    FUSE_OPT_KEY("--version",   KEY_VERSION),
    FUSE_OPT_KEY("-h",          KEY_HELP),
    FUSE_OPT_KEY("--help",      KEY_HELP),
    FUSE_OPT_END
};

static const char help_text[] =
"usage: %s [options] device mountpoint\n"
"\n"
"general options:\n"
"    -o opt,[opt...]        FUSE options\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"\n"
"littlefs options:\n"
"    --stat                 print filesystem info instead of mounting\n"
"    --format               format instead of mounting\n"
"    --migrate              migrate previous version  instead of mounting\n"
"    -d   --disk_version    attempt to use this on-disk version of littlefs\n"
"    -b   --block_size      logical block size, overrides the block device\n"
"    --block_count          block count, overrides the block device\n"
"    --block_cycles         number of erase cycles before eviction (512)\n"
"    --read_size            readable unit (block_size)\n"
"    --prog_size            programmable unit (block_size)\n"
"    --cache_size           size of caches (block_size)\n"
"    --lookahead_size       size of lookahead buffer (8192)\n"
"    --name_max             max size of file names (255)\n"
"    --file_max             max size of file contents (2147483647)\n"
"    --attr_max             max size of custom attributes (1022)\n"
"    -k   --key             encrytion key file, 32 or 64 bytes\n"
"\n";

int lfs_fuse_opt_proc(void *data, const char *arg,
        int key, struct fuse_args *args) {

    // option parsing
    switch (key) {
        case FUSE_OPT_KEY_NONOPT:
            if (!device) {
                device = strdup(arg);
                return 0;
            } else {
                s_mountpoint = strdup(arg);
                return 1;
            }
            break;

        case KEY_STAT:
            stat_ = true;
            return 0;

        case KEY_FORMAT:
            format = true;
            return 0;

        case KEY_MIGRATE:
            migrate = true;
            return 0;

        case KEY_HELP:
            fprintf(stderr, help_text, args->argv[0]);
            fuse_opt_add_arg(args, "-ho");
            fuse_main(args->argc, args->argv, &lfs_fuse_ops, NULL);
            exit(1);

        case KEY_VERSION:
            fprintf(stderr, "littlefs-fuse version: v%d.%d\n",
                LFS_FUSE_VERSION_MAJOR, LFS_FUSE_VERSION_MINOR);
            fprintf(stderr, "littlefs version: v%d.%d\n",
                LFS_VERSION_MAJOR, LFS_VERSION_MINOR);
            fprintf(stderr, "littlefs disk version: lfs%d.%d\n",
                LFS_DISK_VERSION_MAJOR, LFS_DISK_VERSION_MINOR);
            fuse_opt_add_arg(args, "--version");
            fuse_main(args->argc, args->argv, &lfs_fuse_ops, NULL);
            exit(0);

        case KEY_DISK_VERSION: {
            // skip opt prefix
            const char *arg_ = strchr(arg, '=');
            if (arg_) {
                arg = arg_ + 1;
            }

            // parse out the requested disk version
            // supported formats:
            // - no-prefix       - 2.1
            // - v-prefix        - v2.1
            // - lfs-prefix      - lfs2.1
            // - littlefs-prefix - littlefs2.1
            const char *orig_arg = arg;
            if (strlen(arg) >= strlen("v")
                    && memcmp(arg, "v", strlen("v")) == 0) {
                arg += strlen("v");
            } else if (strlen(arg) >= strlen("lfs")
                    && memcmp(arg, "lfs", strlen("lfs")) == 0) {
                arg += strlen("lfs");
            } else if (strlen(arg) >= strlen("littlefs")
                    && memcmp(arg, "littlefs", strlen("littlefs")) == 0) {
                arg += strlen("littlefs");
            }

            char *parsed;
            uintmax_t major = strtoumax(arg, &parsed, 0);
            if (parsed == arg) {
                goto invalid_version;
            }
            arg = parsed;

            if (arg[0] != '.') {
                goto invalid_version;
            }
            arg += 1;

            uintmax_t minor = strtoumax(arg, &parsed, 0);
            if (parsed == arg) {
                goto invalid_version;
            }
            arg = parsed;

            if (arg[0] != '\0') {
                goto invalid_version;
            }

            if (major > 0xffff || minor > 0xffff) {
                goto invalid_version;
            }

            config.disk_version
                    = ((major & 0xffff) << 16)
                    | ((minor & 0xffff) <<  0);
            return 0;

        invalid_version:
            fprintf(stderr, "invalid disk version: \"%s\"\n", orig_arg);
            exit(1);
        }

        case KEY_KEY_FILE: {
            const char *arg_ = strchr(arg, '=');
            if (arg_) {
                arg = arg_ + 1;
            }
            int kfd = open(arg, O_RDONLY);
            if (kfd < 0) {
                fprintf(stderr, "failed to open %s", arg);
                exit(1);
            }
            int n = read(kfd, s_key, sizeof(s_key));
            close(kfd);
            if (n < 0) {
                fprintf(stderr, "failed to read %s", arg);
                exit(1);
            }
            if (n != 32 && n != 64) {
                fprintf(stderr, "invalid key size %d", n);
                exit(1);
            }
            s_key_len = n;
            return 0;
        }
    }

    return 1;
}

int main(int argc, char *argv[]) {
    // parse custom options
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    fuse_opt_parse(&args, &config, lfs_fuse_opts, lfs_fuse_opt_proc);
    if (!device) {
        fprintf(stderr, "missing device parameter\n");
        exit(1);
    }

    if (stat_) {
        // stat time, no mount
        int err = lfs_fuse_stat();
        if (err) {
            LFS_ERROR("%s", strerror(-err));
            exit(-err);
        }
        exit(0);
    }

    if (format) {
        // format time, no mount
        int err = lfs_fuse_format();
        if (err) {
            LFS_ERROR("%s", strerror(-err));
            exit(-err);
        }
        exit(0);
    }

    if (migrate) {
        // migrate time, no mount
        int err = lfs_fuse_migrate();
        if (err) {
            LFS_ERROR("%s", strerror(-err));
            exit(-err);
        }
        exit(0);
    }

    // go ahead and mount so errors are reported before backgrounding
    int err = lfs_fuse_mount();
    if (err) {
        LFS_ERROR("%s", strerror(-err));
        exit(-err);
    }

    fuse_opt_add_arg(&args, "-f");

    // fuse_opt_add_arg(&args, "-o");
    // fuse_opt_add_arg(&args, "noatime");
    // fuse_opt_add_arg(&args, "-o");
    // fuse_opt_add_arg(&args, "allow_root");

    // always single-threaded
    fuse_opt_add_arg(&args, "-s");

    // enter fuse
    err = fuse_main(args.argc, args.argv, &lfs_fuse_ops, NULL);
    if (err) {
        lfs_fuse_destroy(NULL);
    }

    return err;
}
