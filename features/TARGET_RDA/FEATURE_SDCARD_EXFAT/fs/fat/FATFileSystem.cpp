/* mbed Microcontroller Library
 * Copyright (c) 2006-2012 ARM Limited
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "mbed.h"

#include "ffconf.h"
#include "mbed_debug.h"

#include "FATFileSystem.h"
#include "FATFileHandle.h"
#include "FATDirHandle.h"
#include "critical.h"

#define _MAX_FN_LEN FF_MAX_LFN

DWORD get_fattime(void) {
    time_t rawtime;
    time(&rawtime);
    struct tm *ptm = localtime(&rawtime);
    return (DWORD)(ptm->tm_year - 80) << 25
         | (DWORD)(ptm->tm_mon + 1  ) << 21
         | (DWORD)(ptm->tm_mday     ) << 16
         | (DWORD)(ptm->tm_hour     ) << 11
         | (DWORD)(ptm->tm_min      ) << 5
         | (DWORD)(ptm->tm_sec/2    );
}

FATFileSystem *FATFileSystem::_ffs[FF_VOLUMES] = {0};
static PlatformMutex * mutex = NULL;

PlatformMutex * get_fat_mutex() {
    PlatformMutex * new_mutex = new PlatformMutex;

    core_util_critical_section_enter();
    if (NULL == mutex) {
        mutex = new_mutex;
    }
    core_util_critical_section_exit();

    if (mutex != new_mutex) {
        delete new_mutex;
    }
    return mutex;
}

FATFileSystem::FATFileSystem(const char* n) : FileSystemLike(n), _mutex(get_fat_mutex()) {
    lock();
    debug_if(FFS_DBG, "FATFileSystem(%s)\n", n);
    for(int i=0; i<FF_VOLUMES; i++) {
        if(_ffs[i] == 0) {
            char n[64];
            _ffs[i] = this;
            _fsid[0] = '0' + i;
            _fsid[1] = '\0';
            debug_if(FFS_DBG, "Mounting [%s] on ffs drive [%s]\n", getName(), _fsid);
            sprintf(n, "%s:/", _fsid);
            f_mount(&_fs, n, 0);
            unlock();
            return;
        }
    }
    error("Couldn't create %s in FATFileSystem::FATFileSystem\n", n);
    unlock();
}

FATFileSystem::~FATFileSystem() {
    lock();
    for (int i=0; i<FF_VOLUMES; i++) {
        if (_ffs[i] == this) {
            _ffs[i] = 0;
            f_mount(NULL, (const TCHAR *)_fsid, 0);
        }
    }
    unlock();
}

FileHandle *FATFileSystem::open(const char* name, int flags) {
    lock();
    debug_if(FFS_DBG, "open(%s) on filesystem [%s], drv [%s] enter \n", name, getName(), _fsid);
    char n[_MAX_FN_LEN];

    int sn = snprintf(n, _MAX_FN_LEN, "%s:/%s", _fsid, name);
    if (sn < 0) {
        unlock();
        printf("ERROR! File name is too long \r\n");
        return NULL;
    }

    /* POSIX flags -> FatFS open mode */
    BYTE openmode;
    if (flags & O_RDWR) {
        openmode = FA_READ|FA_WRITE;
    } else if(flags & O_WRONLY) {
        openmode = FA_WRITE;
    } else {
        openmode = FA_READ;
    }
    if(flags & O_CREAT) {
        if(flags & O_TRUNC) {
            openmode |= FA_CREATE_ALWAYS;
        } else {
            openmode |= FA_OPEN_ALWAYS;
        }
    }

    FIL fh;
    FRESULT res = f_open(&fh, (const TCHAR *)n, openmode);
    if (res) {
        debug_if(FFS_DBG, "f_open('w') failed: %d\n", res);
        unlock();
        return NULL;
    }
    if (flags & O_APPEND) {
        f_lseek(&fh, fh.obj.objsize);
    }
    FATFileHandle * handle = new FATFileHandle(fh, _mutex);
    unlock();
    return handle;
}

int FATFileSystem::remove(const char *filename) {
    lock();
    char n[_MAX_FN_LEN];

    int sn = snprintf(n, _MAX_FN_LEN, "%s:/%s", _fsid, filename);
    if (sn < 0) {
        unlock();
        printf("ERROR! File name is too long \r\n");
        return -1;
    }
    FRESULT res = f_unlink((const TCHAR *)n);
    if (res) {
        debug_if(FFS_DBG, "f_unlink() failed: %d\n", res);
        unlock();
        return -1;
    }
    unlock();
    return 0;
}

int FATFileSystem::rename(const char *oldname, const char *newname) {
    lock();
    char o[_MAX_FN_LEN], n[_MAX_FN_LEN];

    int sn = snprintf(o, _MAX_FN_LEN, "%s:/%s", _fsid, oldname);
    if (sn < 0) {
        unlock();
        printf("ERROR! File name is too long \r\n");
        return -1;
    }
    sn = snprintf(n, _MAX_FN_LEN, "%s:/%s", _fsid, newname);
    if (sn < 0) {
        unlock();
        printf("ERROR! File name is too long \r\n");
        return -1;
    }
     FRESULT res = f_rename(o, n);
    if (res) {
        debug_if(FFS_DBG, "f_rename() failed: %d\n", res);
        unlock();
        return -1;
    }
    unlock();
    return 0;
}

int FATFileSystem::format() {
    lock();
    BYTE work[FF_MAX_SS];
    char n[5];
    sprintf(n, "%s:/", _fsid);
    FRESULT res = f_mkfs((const TCHAR *)n, FM_ANY, 512, work, sizeof(work)); // Logical drive number, Partitioning rule, Allocation unit size (bytes per cluster)
    if (res) {
        debug_if(FFS_DBG, "f_mkfs() failed: %d\n", res);
        unlock();
        return -1;
    }
    unlock();
    return 0;
}

DirHandle *FATFileSystem::opendir(const char *name) {
    lock();
    FATFS_DIR dir;
    char n[_MAX_FN_LEN];

    int sn = snprintf(n, _MAX_FN_LEN, "%s:/%s", _fsid, name);
    if (sn < 0) {
        unlock();
        printf("ERROR! File name is too long \r\n");
        return NULL;
    }
    FRESULT res = f_opendir(&dir, (const TCHAR *)n);
    if (res != 0) {
        unlock();
        return NULL;
    }
    FATDirHandle *handle = new FATDirHandle(dir, _mutex);
    unlock();
    return handle;
}

int FATFileSystem::mkdir(const char *name, mode_t mode) {
    lock();
    char n[_MAX_FN_LEN];

    int sn = snprintf(n, _MAX_FN_LEN, "%s:/%s", _fsid, name);
    if (sn < 0) {
        unlock();
        printf("ERROR! File name is too long \r\n");
        return NULL;
    }

    FRESULT res = f_mkdir((const TCHAR *)n);
    unlock();
    return res;
}

int FATFileSystem::mount() {
    lock();
    char n[5];
    sprintf(n, "%s:/", _fsid);
    FRESULT res = f_mount(&_fs, (const TCHAR *)n, 1);
    unlock();
    return res == 0 ? 0 : -1;
}

int FATFileSystem::unmount() {
    lock();
    char n[5];
    sprintf(n, "%s:/", _fsid);
    if (disk_sync()) {
        unlock();
        return -1;
    }
    FRESULT res = f_mount(NULL, (const TCHAR *)n, 0);
    unlock();
    return res == 0 ? 0 : -1;
}

void FATFileSystem::lock() {
    _mutex->lock();
}

void FATFileSystem::unlock() {
    _mutex->unlock();
}
