#ifndef KERNEL_H
#define KERNEL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>

#include <vector>
#include <string>

/*------------------------------------------------------------------------------
 *  bing_rw kernel module -- userland client (2026-04 contract)
 *
 *  Re-verified end-to-end against output/5.10.ko via
 *  IDA Pro / Hex-Rays. The shipped binary is the new "bing_rw" driver
 *  authored by NULL1337 (.modinfo: author=NULL1337,
 *  description="bing memory rw driver tg @nullnb6"). It REPLACES the
 *  previous mem_tool driver and the contract is incompatible.
 *
 *  Driver surface (everything else returns -1):
 *
 *      cmd     handler                                arg layout
 *      ------  -------------------------------------  -------------------------
 *      0x100   verify auth key (must be first call)   uint8_t[0x31] (49)
 *      0x101   read_process_memory()                  COPY_MEMORY (32)
 *      0x102   write_process_memory()                 COPY_MEMORY (32)
 *      0x103   get_module_base()                      MODULE_BASE (24) + name[0x31]
 *      else    -- no case --                          returns -1
 *
 *  Authentication contract (KEY = "bingByNULL1337"):
 *
 *      The dispatcher gates every other opcode behind a global
 *      `is_verified` flag. The user buffer (49 bytes, copy_from_user) is
 *      checked with two xor masks against the literals "bingByNU" and
 *      "ULL1337\0" -- equivalent to strncmp(buf, "bingByNULL1337", 15)==0.
 *
 *      Only bytes [0..14] are inspected; bytes [15..48] are scratch but
 *      MUST be readable (the kernel copies all 0x31 bytes before checking).
 *
 *      Quirk: the verify call ALWAYS returns -1 (errno=EPERM) even when the
 *      key matches, because the dispatcher captures `v7 = is_verified`
 *      BEFORE updating the global, then the post-update switch on a2=0x100
 *      falls through to `default: return -1`. The match still latches the
 *      global, so the very next ioctl() (0x101 / 0x102 / 0x103) will be
 *      authorised. Treat ret==-1 && errno==EPERM as success on op 0x100.
 *
 *  State scope (matters for multi-process clients):
 *
 *      `is_verified` is a global in the .ko (.bss @ 0x208), NOT a per-fd
 *      flag. Any open fd benefits once any caller has authenticated. But
 *      `dispatch_close` resets is_verified to 0 unconditionally on every
 *      close(2) -- so if process A closes its fd while process B is mid-op,
 *      B's next ioctl will fail until B re-verifies. Re-call init_key()
 *      after any close.
 *
 *  Device path:
 *
 *      Fixed at /dev/bing_rw. The driver passes "%s","bing_rw" to
 *      device_create() and __class_create("bing_rw") -- no random naming
 *      and no /dev scan needed. (The previous mem_tool build used
 *      get_rand_str(); the bing_rw driver does NOT.)
 *
 *  Stealth performed at module load (driver_entry):
 *
 *      - list_del on __this_module.list   -> hidden from /proc/modules
 *      - kobject_del + sysfs_remove_link  -> hidden from /sys/module/bing_rw
 *      - NO remove_proc_entry calls       (sched_debug, uevents_records,
 *                                          etc. are NOT touched)
 *      - NO unregister_chrdev_region trick at load time -- the major shows
 *        up in /proc/devices as "bing_rw" until module unload.
 *
 *  Functions that USED TO exist in mem_tool but are GONE in bing_rw:
 *
 *      hide_process / hide_pid / recover_process / find_pid_by_comm /
 *      ClearHwBp -- none of these symbols are in the .ko. The kernel
 *      imports list contains zero hide/HWBP/pid-search helpers; the
 *      module is purely r/w + module-base. Pid-of selection is now the
 *      caller's job (popen pidof, /proc scan, etc.).
 *----------------------------------------------------------------------------*/

#define BING_DEVICE_PATH    "/dev/bing_rw"
#define BING_AUTH_KEY       "bingByNULL1337"      /* exactly 14 chars + NUL */

#define BING_OP_VERIFY      0x100
#define BING_OP_READ_MEM    0x101
#define BING_OP_WRITE_MEM   0x102
#define BING_OP_MODULE_BASE 0x103

#define BING_VERIFY_BUF_SZ  0x31    /* copy_from_user reads exactly 49 bytes */
#define BING_NAME_BUF_SZ    0x31    /* get_module_base reads 49 bytes of name */

class c_driver
{
private:
	int   fd;
	pid_t pid;

	/* 0x101 / 0x102: cross-process read/write. 32 bytes copied in. */
	typedef struct _COPY_MEMORY {
		pid_t     pid;      /* +0x00, low 4 bytes; +0x04 padding              */
		uintptr_t addr;     /* +0x08 target VA                                */
		void     *buffer;   /* +0x10 userland buffer (src for write, dst for read) */
		size_t    size;     /* +0x18 byte count                               */
	} COPY_MEMORY, *PCOPY_MEMORY;

	/* 0x103: module-base resolver. 24 bytes in/out; the name pointer is then
	 * dereferenced for an additional 49-byte copy_from_user. */
	typedef struct _MODULE_BASE {
		pid_t     pid;      /* +0x00, low 4 bytes; +0x04 padding              */
		char     *name;     /* +0x08 userland pointer to a >=49-byte name buf */
		uintptr_t base;     /* +0x10 kernel writes the first matching vm_start */
	} MODULE_BASE, *PMODULE_BASE;

public:
	c_driver()
	{
		fd = open(BING_DEVICE_PATH, O_RDWR);
		if (fd == -1) {
			fprintf(stderr,
				"\033[31m[!] failed to open %s: %s\033[0m\n",
				BING_DEVICE_PATH, strerror(errno));
			fprintf(stderr,
				"    (driver not loaded? insmod the matching .ko first)\n");
			exit(0);
		}
		fprintf(stderr,
			"\033[33m[-] driver: %s | fd: %d\033[0m\n",
			BING_DEVICE_PATH, fd);
	}

	~c_driver()
	{
		if (fd >= 0) close(fd);
	}

	/* ---- 0x100: authenticate. MUST be the first ioctl after open. ---------
	 *
	 * The driver checks `key` against "bingByNULL1337". It always returns -1
	 * with errno=EPERM on the first successful match (see header notes); we
	 * treat that exit case as success and let the caller proceed to r/w. */
	bool init_key(const char *key = BING_AUTH_KEY)
	{
		uint8_t buf[BING_VERIFY_BUF_SZ];
		memset(buf, 0, sizeof(buf));

		size_t n = strnlen(key, 15);     /* kernel only inspects bytes 0..14 */
		memcpy(buf, key, n);

		errno = 0;
		int res = ioctl(fd, BING_OP_VERIFY, buf);
		if (res == 0) {
			/* unexpected on this driver, but treat as success */
			return true;
		}
		if (errno == EPERM) {
			/* expected first-call quirk: -1/EPERM but is_verified now true */
			return true;
		}
		fprintf(stderr,
			"\033[31m[!] verify failed: ret=%d errno=%d (%s)\033[0m\n",
			res, errno, strerror(errno));
		return false;
	}

	void initialize(pid_t pid)
	{
		this->pid = pid;
	}

	/* ---- 0x101: cross-process memory read --------------------------------- */
	bool read(uintptr_t addr, void *buffer, size_t size)
	{
		COPY_MEMORY cm;
		cm.pid    = this->pid;
		cm.addr   = addr;
		cm.buffer = buffer;
		cm.size   = size;
		return ioctl(fd, BING_OP_READ_MEM, &cm) == 0;
	}

	template <typename T>
	T read(uintptr_t addr)
	{
		T res;
		if (this->read(addr, &res, sizeof(T)))
			return res;
		return {};
	}

	/* ---- 0x102: cross-process memory write -------------------------------- */
	bool write(uintptr_t addr, const void *buffer, size_t size)
	{
		COPY_MEMORY cm;
		cm.pid    = this->pid;
		cm.addr   = addr;
		cm.buffer = const_cast<void *>(buffer);
		cm.size   = size;
		return ioctl(fd, BING_OP_WRITE_MEM, &cm) == 0;
	}

	template <typename T>
	bool write(uintptr_t addr, const T &value)
	{
		return this->write(addr, &value, sizeof(T));
	}

	/* ---- 0x103: module-base resolver --------------------------------------
	 *
	 * The kernel copies 49 bytes from `name` -> internal scratch and walks
	 * the target's VMA list, taking the basename of each vm_file backing and
	 * strcmp()'ing it. First match wins; the search retries through merged
	 * .so segments (find_vma chase). */
	uintptr_t get_module_base(const char *name)
	{
		char namebuf[BING_NAME_BUF_SZ];
		memset(namebuf, 0, sizeof(namebuf));
		strncpy(namebuf, name, sizeof(namebuf) - 1);

		MODULE_BASE mb;
		mb.pid  = this->pid;
		mb.name = namebuf;
		mb.base = 0;
		if (ioctl(fd, BING_OP_MODULE_BASE, &mb) != 0)
			return 0;
		return mb.base;
	}
};

static c_driver *driver = []() {
	auto *d = new c_driver();
	if (!d->init_key(BING_AUTH_KEY)) {
		fprintf(stderr,
			"\033[31m[!] driver authentication failed -- aborting\033[0m\n");
		exit(1);
	}
	return d;
}();

/*--------------------------------------------------------------------------------------------------------*/

typedef char PACKAGENAME;
pid_t pid;

float Kernel_v()
{
	const char *command = "uname -r | sed 's/\\.[^.]*$//g'";
	FILE *file = popen(command, "r");
	if (file == NULL) return 0.0f;
	static char result[512];
	if (fgets(result, sizeof(result), file) == NULL) {
		pclose(file);
		return 0.0f;
	}
	pclose(file);
	result[strlen(result) - 1] = '\0';
	return atof(result);
}

char *GetVersion(char *PackageName)
{
	char command[256];
	snprintf(command, sizeof(command),
		"dumpsys package %s|grep versionName|sed 's/=/\\n/g'|tail -n 1",
		PackageName);
	FILE *file = popen(command, "r");
	if (file == NULL) return NULL;
	static char result[512];
	if (fgets(result, sizeof(result), file) == NULL) {
		pclose(file);
		return NULL;
	}
	pclose(file);
	result[strlen(result) - 1] = '\0';
	return result;
}

uint64_t GetTime()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec * 1000 + ts.tv_nsec / (1000 * 1000));
}

/* The bing_rw driver does NOT expose a kernel-side pidof opcode. Userland
 * is responsible for finding the target PID; we shell out to pidof and
 * fall back to scanning /proc/<n>/comm for the package's `comm` suffix
 * (TASK_COMM_LEN-1 = 15 chars, what the zygote leaves on the task). */
int getPID(char *PackageName)
{
	if (PackageName == NULL || *PackageName == '\0') return -1;

	pid = -1;
	char cmd[0x100] = "pidof ";
	strncat(cmd, PackageName, sizeof(cmd) - strlen(cmd) - 1);
	FILE *fp = popen(cmd, "r");
	if (fp) {
		if (fscanf(fp, "%d", &pid) != 1) pid = -1;
		pclose(fp);
	}

	if (pid <= 0) {
		size_t len = strlen(PackageName);
		const char *tail = len > 15 ? PackageName + (len - 15) : PackageName;

		DIR *proc = opendir("/proc");
		if (proc) {
			struct dirent *ent;
			while ((ent = readdir(proc)) != NULL) {
				int p = atoi(ent->d_name);
				if (p <= 0) continue;
				char commpath[64], comm[64] = {0};
				snprintf(commpath, sizeof(commpath), "/proc/%d/comm", p);
				FILE *cf = fopen(commpath, "r");
				if (!cf) continue;
				if (fgets(comm, sizeof(comm), cf)) {
					size_t cl = strlen(comm);
					if (cl && comm[cl - 1] == '\n') comm[cl - 1] = '\0';
					if (strstr(comm, tail)) { pid = p; fclose(cf); break; }
				}
				fclose(cf);
			}
			closedir(proc);
		}
	}

	if (pid > 0) driver->initialize(pid);
	return pid;
}

long GetModuleBaseAddr_Maps(char *module_name)
{
	long addr = 0;
	char filename[64];
	char line[1024];
	if (pid < 0)
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	else
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);

	FILE *fp = fopen(filename, "r");
	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, module_name)) {
				sscanf(line, "%lx-%*lx", &addr);
				break;
			}
		}
		fclose(fp);
	}
	return addr;
}

long ReadValue(long addr)
{
	long he = 0;
	if (addr < 0xFFFFFFFF) driver->read(addr, &he, 4);
	else                   driver->read(addr, &he, 8);
	return he;
}

long  ReadDword(long addr) { long  h = 0; driver->read(addr, &h, 4); return h; }
float ReadFloat(long addr) { float h = 0; driver->read(addr, &h, 4); return h; }

bool  WriteDword(long addr, int   v) { return driver->write(addr, &v, 4); }
bool  WriteFloat(long addr, float v) { return driver->write(addr, &v, 4); }

#endif
