#ifndef KERNEL_H
#define KERNEL_H

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <vector>
#include <string>


#define OP_CMD_HWBP_ADD      0x804
#define OP_CMD_HWBP_GET_HITS 0x805
#define OP_CMD_HWBP_ENABLE   0x806
#define OP_CMD_HWBP_CLEAR    0x807
#define OP_CMD_HWBP_DISABLE  0x809
#define OP_CMD_HIDE_PROCESS 0x810
#define OP_CMD_RECOVER_PROCESS 0x811

#define HW_BP_TYPE_R    1
#define HW_BP_TYPE_W    2
#define HW_BP_TYPE_RW   3
#define HW_BP_TYPE_X    4
#define MAX_MODIFY_REGS 10





class c_driver
{
private:
	int fd;
	pid_t pid;

	typedef struct _HW_BP_INFO {
    pid_t pid;
    uintptr_t addr;
    int type;      
    int len;

    bool is_write_gp_regs;                   
    int gp_reg_count;                        
    int gp_reg_indices[MAX_MODIFY_REGS];     
    uint64_t gp_reg_values[MAX_MODIFY_REGS]; 
    bool is_write_fp_regs;
    int fp_reg_count;                        
    int fp_reg_indices[MAX_MODIFY_REGS];     
    uint64_t fp_reg_values[MAX_MODIFY_REGS][2]; 
} HW_BP_INFO;

struct REGS_INFO {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

struct HWBP_HIT_ITEM {
    pid_t task_id;
    uintptr_t hit_addr;
    uint64_t hit_time;
    struct REGS_INFO regs_info;
};

typedef struct _HWBP_HIT_ARGS {
    pid_t pid;
    uintptr_t addr;
    void *out_buf;      
    int out_len;        
    int real_count;     
} HWBP_HIT_ARGS;


typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _proinf{
    uintptr_t cmaddr;
    uintptr_t mbaddr;
    uintptr_t isreadaddr;
    int isread;
} proinf, *PCOPY_proinf;

typedef struct _MODULE_BASE {
    pid_t pid;
    char* name;
    uintptr_t base;
    short index;
} MODULE_BASE, *PMODULE_BASE;

typedef struct _PROGRAM_PROCESS {
    char *package_name;
    int pid;
} PROGRAM_PROCESSS;

enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
};

	char *driver_path()
	{
		printf("\033[32m;1m welcome to kernel.h by Cycle1337 \033[0m\n");

		const char *dev_path = "/dev";
		DIR *dir = opendir(dev_path);
		if (dir == NULL)
		{
			printf("\033[31m;1m [!] failed to open /dev \033[0m\n");
			return NULL;
		}

		const std::vector<std::string> excluded_names = {
			"binder", "common", "ashmem", "stdin", "stdout", "stderr"};

		struct dirent *entry;
		char *file_path = NULL;
		while ((entry = readdir(dir)) != NULL)
		{
			const char *current_name = entry->d_name;

			if (strcmp(current_name, ".") == 0 || strcmp(current_name, "..") == 0)
			{
				continue;
			}

			if (strstr(current_name, "gpiochip") != NULL ||
				strchr(current_name, '_') != NULL ||
				strchr(current_name, '-') != NULL ||
				strchr(current_name, ':') != NULL)
			{
				continue;
			}

			bool is_excluded = false;
			for (const auto &name : excluded_names)
			{
				if (strcmp(current_name, name.c_str()) == 0)
				{
					is_excluded = true;
					break;
				}
			}
			if (is_excluded)
			{
				continue;
			}

			size_t path_length = strlen(dev_path) + strlen(current_name) + 2;
			file_path = (char *)malloc(path_length);
			if (!file_path)
				continue;

			snprintf(file_path, path_length, "%s/%s", dev_path, current_name);

			struct stat file_info;
			if (stat(file_path, &file_info) < 0)
			{
				free(file_path);
				file_path = NULL;
				continue;
			}

			if (S_ISCHR(file_info.st_mode) || S_ISBLK(file_info.st_mode))
			{
				if (localtime(&file_info.st_ctime)->tm_year + 1900 <= 1980)
				{
					free(file_path);
					file_path = NULL;
					continue;
				}

				if (file_info.st_atime == file_info.st_ctime &&
					file_info.st_size == 0 &&
					file_info.st_gid == 0 &&
					file_info.st_uid == 0 &&
					strlen(current_name) == 6)
				{
					closedir(dir);
					return file_path;
				}
			}

			free(file_path);
			file_path = NULL;
		}

		closedir(dir);
		return NULL;
	}

public:
	c_driver()
	{
		char *device_name = driver_path();
		fd = open(device_name, O_RDWR);

		if (fd == -1)
		{
			printf("\033[31m;1m [!] failed to open %s | fd: -1 \033[0m\n", device_name);
			free(device_name);
			exit(0);
		}

		printf("\033[33m;1m [-] driver path: %s | fd: %d \033[0m\n", device_name, fd);
		free(device_name);
	}

	void initialize(pid_t pid)
	{
		this->pid = pid;
	}

	bool init_key(char *key)
	{
		char buf[0x100];
		strcpy(buf, key);
		if (ioctl(fd, OP_INIT_KEY, buf) != 0)
		{
			return false;
		}
		return true;
	}

	bool read(uintptr_t addr, void *buffer, size_t size)
	{
		COPY_MEMORY cm;

		cm.pid = this->pid;
		cm.addr = addr;
		cm.buffer = buffer;
		cm.size = size;

		if (ioctl(fd, OP_READ_MEM, &cm) != 0)
		{
			return false;
		}
		return true;
	}

	bool write(uintptr_t addr, void *buffer, size_t size)
	{
		COPY_MEMORY cm;

		cm.pid = this->pid;
		cm.addr = addr;
		cm.buffer = buffer;
		cm.size = size;

		if (ioctl(fd, OP_WRITE_MEM, &cm) != 0)
		{
			return false;
		}
		return true;
	}

	template <typename T>
	T read(uintptr_t addr)
	{
		T res;
		if (this->read(addr, &res, sizeof(T)))
			return res;
		return {};
	}

	template <typename T>
	bool write(uintptr_t addr, T value)
	{
		return this->write(addr, &value, sizeof(T));
	}

	uintptr_t get_module_base(char *name)
	{
		MODULE_BASE mb;
		char buf[0x100];
		strcpy(buf, name);
		mb.pid = this->pid;
		mb.name = buf;

		if (ioctl(fd, OP_MODULE_BASE, &mb) != 0)
		{
			return 0;
		}
		return mb.base;
	}

    void hide_process() { 
        ioctl(fd, OP_CMD_HIDE_PROCESS); 
    }
  
    void recover_process() {
        ioctl(fd, OP_CMD_RECOVER_PROCESS);
    }

    bool AddHwBp(HW_BP_INFO* info) {
        if (ioctl(fd, OP_CMD_HWBP_ADD, info) != 0) {
            return false;
        }
        return true;
    }

    bool UpdateAndEnableHwBp(HW_BP_INFO* info) {
        if (ioctl(fd, OP_CMD_HWBP_ENABLE, info) != 0) {
            return false;
        }
        return true;
    }

    bool DisableHwBp(int target_pid, uintptr_t addr) {
        HW_BP_INFO info;
        memset(&info, 0, sizeof(info));
        info.pid = target_pid;
        info.addr = addr;
        if (ioctl(fd, OP_CMD_HWBP_DISABLE, &info) != 0) {
            return false;
        }
        return true;
    }


    bool ClearHwBp() {
        if (ioctl(fd, OP_CMD_HWBP_CLEAR, NULL) != 0) {
            return false;
        }
        return true;
    }


    int GetHwBpHits(HWBP_HIT_ARGS* args) {
        if (!args || !args->out_buf || args->out_len <= 0) return 0;
        int ret = ioctl(fd, OP_CMD_HWBP_GET_HITS, args);
        if (ret == 0) {
            return args->real_count; 
        }
        return -1;
    }
    
    
};

static c_driver *driver = new c_driver();

/*--------------------------------------------------------------------------------------------------------*/

typedef char PACKAGENAME;
pid_t pid;

float Kernel_v()
{
    const char* command = "uname -r | sed 's/\\.[^.]*$//g'";
    FILE* file = popen(command, "r");
    if (file == NULL) {
        return 0.0f;
    }
    static char result[512];
    if (fgets(result, sizeof(result), file) == NULL) {
        pclose(file);
        return 0.0f;
    }
    pclose(file);
    result[strlen(result)-1] = '\0';
    return atof(result);
}

char *GetVersion(char* PackageName)
{
    char command[256];
    sprintf(command, "dumpsys package %s|grep versionName|sed 's/=/\\n/g'|tail -n 1", PackageName);
    FILE* file = popen(command, "r");
    if (file == NULL) {
        return NULL;
    }
    static char result[512];
    if (fgets(result, sizeof(result), file) == NULL) {
        pclose(file);
        return NULL;
    }
    pclose(file);
    result[strlen(result)-1] = '\0';
    return result;
}

uint64_t GetTime()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    return (ts.tv_sec*1000 + ts.tv_nsec/(1000*1000));
}

int getPID(char* PackageName)
{
    FILE* fp;
    char cmd[0x100] = "pidof ";
    strcat(cmd, PackageName);
    fp = popen(cmd,"r");
    if (!fp) return -1;
    
    fscanf(fp,"%d", &pid);
    pclose(fp);
    if (pid > 0)
    {
        driver->initialize(pid);
    }
    return pid;
}

long GetModuleBaseAddr_Maps(char* module_name)
{
    long addr = 0;
    char filename[64];
    char line[1024];
    if (pid < 0)
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    else
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);

    FILE *fp = fopen(filename, "r");
    if (fp != NULL)
    {
        while (fgets(line, sizeof(line), fp))
        {
            if (strstr(line, module_name))
            {
                sscanf(line,"%lx-%*lx",&addr);
                break;
            }
        }
        fclose(fp);
    }
    return addr;
}




long ReadValue(long addr)
{
    long he=0;
    if (addr < 0xFFFFFFFF){
        driver->read(addr, &he, 4);
    }else{
        driver->read(addr, &he, 8);
    }
    return he;
}


long ReadDword(long addr)
{
    long he=0;
    driver->read(addr, &he, 4);
    return he;
}

float ReadFloat(long addr)
{
    float he=0;
    driver->read(addr, &he, 4);
    return he;
}

int WriteDword(long int addr, int value)
{
    driver->write(addr, &value, 4);
    return 0;
}

int WriteFloat(long int addr, float value)
{
    driver->write(addr, &value, 4);
    return 0;
}

#endif
