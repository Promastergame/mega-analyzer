/*
 * shmshim.c — LD_PRELOAD shim emulating System V shared memory
 * (shmget/shmat/shmdt/shmctl) on kernels that lack SysV IPC (e.g. Android),
 * backed by MAP_SHARED file mmaps under $SHMSHIM_DIR.
 *
 * Purpose: let PostgreSQL start on such kernels for the local labs/servers
 * lab. Not a general/complete SysV implementation — just enough for PG's
 * small interlock segment and forked-backend sharing.
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#define MAX_SEG 256

struct seg {
    int used;
    int id;
    key_t key;
    size_t size;
    void *addr;      /* current mapping in this process, if attached */
    char path[512];
};

static struct seg segs[MAX_SEG];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int next_id = 1000;

static const char *shim_dir(void) {
    const char *d = getenv("SHMSHIM_DIR");
    return d ? d : "/tmp/shmshim";
}

static struct seg *find_by_id(int id) {
    for (int i = 0; i < MAX_SEG; i++)
        if (segs[i].used && segs[i].id == id) return &segs[i];
    return NULL;
}

static struct seg *find_by_key(key_t key) {
    for (int i = 0; i < MAX_SEG; i++)
        if (segs[i].used && segs[i].key == key) return &segs[i];
    return NULL;
}

static struct seg *alloc_slot(void) {
    for (int i = 0; i < MAX_SEG; i++)
        if (!segs[i].used) return &segs[i];
    return NULL;
}

int shmget(key_t key, size_t size, int shmflg) {
    pthread_mutex_lock(&lock);

    mkdir(shim_dir(), 0700);

    struct seg *s = NULL;
    if (key != IPC_PRIVATE)
        s = find_by_key(key);

    char path[512];
    snprintf(path, sizeof(path), "%s/seg_%ld", shim_dir(), (long)key);

    int exists_on_disk = (access(path, F_OK) == 0);

    if (key != IPC_PRIVATE && (s || exists_on_disk)) {
        if ((shmflg & IPC_CREAT) && (shmflg & IPC_EXCL)) {
            pthread_mutex_unlock(&lock);
            errno = EEXIST;
            return -1;
        }
        if (s) {
            int id = s->id;
            pthread_mutex_unlock(&lock);
            return id;
        }
        /* Exists on disk from another process — adopt it. */
        struct seg *ns = alloc_slot();
        if (!ns) { pthread_mutex_unlock(&lock); errno = ENOMEM; return -1; }
        struct stat st;
        stat(path, &st);
        ns->used = 1; ns->id = next_id++; ns->key = key;
        ns->size = size ? size : (size_t)st.st_size; ns->addr = NULL;
        snprintf(ns->path, sizeof(ns->path), "%s", path);
        int id = ns->id;
        pthread_mutex_unlock(&lock);
        return id;
    }

    if (!(shmflg & IPC_CREAT)) {
        pthread_mutex_unlock(&lock);
        errno = ENOENT;
        return -1;
    }

    struct seg *ns = alloc_slot();
    if (!ns) { pthread_mutex_unlock(&lock); errno = ENOMEM; return -1; }

    if (key == IPC_PRIVATE)
        snprintf(path, sizeof(path), "%s/seg_priv_%d", shim_dir(), next_id);

    int fd = open(path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) { pthread_mutex_unlock(&lock); return -1; }
    if (ftruncate(fd, size) != 0) { close(fd); pthread_mutex_unlock(&lock); return -1; }
    close(fd);

    ns->used = 1; ns->id = next_id++; ns->key = key;
    ns->size = size; ns->addr = NULL;
    snprintf(ns->path, sizeof(ns->path), "%s", path);
    int id = ns->id;
    pthread_mutex_unlock(&lock);
    return id;
}

void *shmat(int shmid, const void *shmaddr, int shmflg) {
    pthread_mutex_lock(&lock);
    struct seg *s = find_by_id(shmid);
    if (!s) { pthread_mutex_unlock(&lock); errno = EINVAL; return (void *)-1; }

    int prot = (shmflg & SHM_RDONLY) ? PROT_READ : (PROT_READ | PROT_WRITE);
    int fd = open(s->path, O_RDWR);
    if (fd < 0) { pthread_mutex_unlock(&lock); return (void *)-1; }
    void *p = mmap((void *)shmaddr, s->size, prot, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { pthread_mutex_unlock(&lock); return (void *)-1; }
    s->addr = p;
    pthread_mutex_unlock(&lock);
    return p;
}

int shmdt(const void *shmaddr) {
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_SEG; i++) {
        if (segs[i].used && segs[i].addr == shmaddr) {
            munmap((void *)shmaddr, segs[i].size);
            segs[i].addr = NULL;
            pthread_mutex_unlock(&lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&lock);
    /* Unknown address — best effort. */
    return 0;
}

int shmctl(int shmid, int cmd, struct shmid_ds *buf) {
    pthread_mutex_lock(&lock);
    struct seg *s = find_by_id(shmid);
    if (!s) { pthread_mutex_unlock(&lock); errno = EINVAL; return -1; }

    if (cmd == IPC_RMID) {
        unlink(s->path);
        s->used = 0;
        pthread_mutex_unlock(&lock);
        return 0;
    }
    if (cmd == IPC_STAT) {
        if (buf) {
            memset(buf, 0, sizeof(*buf));
            buf->shm_segsz = s->size;
            /* Report 1 attach so PG's postmaster-liveness interlock behaves;
             * a fresh cluster start unlinks stale segments anyway. */
            buf->shm_nattch = 1;
            buf->shm_perm.mode = 0600;
        }
        pthread_mutex_unlock(&lock);
        return 0;
    }
    pthread_mutex_unlock(&lock);
    return 0;
}
