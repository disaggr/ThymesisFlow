/*
 * Copyright 2019 International Business Machines
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/// @file thymesisflow.c
#include "thymesisflow.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

char afu_name[] = "IBM,RMEM";
char probe_path[] = "/sys/devices/system/memory/probe";
char memory_path[] =  "/sys/devices/system/memory";

struct thymesisflow_config config = {
	.GLOBAL_MMIO_REG_COUNT = (0x300 / 8),
	.CTRL_REG = 0x000,
	.INIT_PROBE_ADDR = 0x2200000000000,
	.AFU_NAME = afu_name,
	.MEMBLOCK_SIZE = 0x10000000,
	.PROBE_PATH = probe_path,
	.MEMORY_PATH = memory_path,
	.CACHE_ALIGNMENT = 128
};

int unplug_memory_blocks(const uint64_t memory_size) {

    uint64_t probe_addr = config.INIT_PROBE_ADDR;

    char *offline_command = "offline";
    for (int i = 0; i < memory_size / config.MEMBLOCK_SIZE;
         i++, probe_addr += config.MEMBLOCK_SIZE) {
        char offline_buff[128];

        snprintf(offline_buff, sizeof(offline_buff),
                 "/sys/devices/system/memory/memory%lu/state",
                 probe_addr / config.MEMBLOCK_SIZE);

        // log_info("offlining - %s\n", offline_buff);

        if (access(offline_buff, W_OK) == -1) {

            log_error_ext("cannot get write access- %s\n", offline_buff);
            return -1;
        }

        FILE *fd = fopen(offline_buff, "w");
        if (fd == NULL) {
            log_error_ext("error opening - %s\n", offline_buff);
            return -1;
        }

        // printf("opened - %s\n", offline_buff);
        int res = fprintf(fd, "%s\n", offline_command);

        if (res <= 0) {
            log_error_ext("error offlining...\n");
        }
        // printf("written - %d\n", res);
        fflush(fd);
        fclose(fd);
    }
    return DETACH_OK;
}

int detach_memory(const char *circuit_id) {
    connection *conn = get_conn(circuit_id);
    if (conn == NULL) {
        log_error_ext("error fetching connection: %s", circuit_id);
        return ERR_MISSING_CID;
    }
    log_info_ext("thymesisflow - memory detach - circuit: %s\n", circuit_id);

    // free memory
    if (conn->ea == NULL) {
        log_warn_ext(
            "thymesisflow - cannot free memory for circuit -  %s - NULL "
            "ref pointer \n",
            circuit_id);
    } else {
        munmap(conn->ea, conn->size);
    }

    // delete connection
    int res_del_code;
    // remove connection even in case of errors
    if ((res_del_code = del_conn(circuit_id)) != CONN_SUCCESS) {
        log_error_ext(
            "error registering detachment for circuit %s - error: %d\n",
            circuit_id, res_del_code);
    }
    return DETACH_OK;
}

int detach_compute(const char *circuit_id) {
    connection *conn = get_conn(circuit_id);
    int res = DETACH_OK;
    if (conn == NULL) {
        log_error_ext("error fetching circuit: %s", circuit_id);
        return ERR_MISSING_CID;
    }
    log_info_ext("compute detach - circuit: %s\n", circuit_id);
    // Check return value in detach

#ifdef MOCK
    if (!conn->no_hotplug)
        log_debug_ext("This connection requires hot-unplug of the memory\n");
    else
        log_debug_ext("This connection does not require hot-unplug of the memory\n");
#else
    if (!conn->no_hotplug)
        res = unplug_memory_blocks(conn->size);
#endif

    int res_del_code;
    // remove connection even in case of errors
    if ((res_del_code = del_conn(circuit_id)) != CONN_SUCCESS) {
        log_error_ext(
            "thymesisflow - error registering detachment for circuit %s "
            "- error: %d\n",
            circuit_id, res_del_code);
        //We should probably notifier the caller that something went wrong with
        //registering the detachment
        res = ERR_REGISTER_DETACH;
    }

    return res;
}

static void *allocate_from_file_aligend(size_t size, size_t alignment) {
    int fd = open("/dev/mishmem-s1", O_RDWR);
    if (fd == -1) {
        log_error_ext("Could not open /dev/mishmem-s1\n");
        return NULL;
    }

    log_info_ext("/dev/mishmem-s1 opened\n");

    size_t address = 0x100000000;

    while (address >= alignment) {
        void *result = mmap((void *)address, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if ((size_t)result % alignment == 0) {
            log_info_ext("Allocated aligned from /dev/mishmem-s1 at %p\n", result);
            close(fd);
            return result;
        }

        if (result == MAP_FAILED) {
            log_error_ext("MMAP failed: %i\n", errno);
            return NULL;
        }

        munmap(result, size);
        address += alignment;
    }


    log_info_ext("Unable to find address to map memory file\n");

    close(fd);
    return NULL;
}

int attach_memory(const char *circuit_id, const char *afu_name,
                  iport_list *ports, const uint64_t size, uint64_t *eaptr) {

    connection *conn = new_conn(circuit_id, afu_name, size, 0);

    add_conn(conn);

#ifdef MOCK
    log_info_ext("mocking memory connection by allocating only 256 MB...\n");

    if (posix_memalign((void **)&conn->ea, config.CACHE_ALIGNMENT, (256 >> 20)) != 0) {
        log_error_ext("unable to allocate %ld bytes memory\n", size);
        return 1;
    }

    // set effective address reference for caller
    *eaptr = (uint64_t)conn->ea;

#else

    log_info_ext("Allocating aligned memory\n");
    //if (posix_memalign((void **)&conn->ea, config.CACHE_ALIGNMENT, size) != 0) {
    //TODO: implement switch to choose wether to malloc or to shmem
    conn->ea = allocate_from_file_aligend(size, config.CACHE_ALIGNMENT);
    if (conn->ea == NULL) {
        log_error_ext("unable to allocate %ld bytes memory\n", size);
        return 1;
    }
    if (mlock(conn->ea, size) < 0) {
        // error mem lock ERR_MLOCK
        log_error_ext("cannot mlock memory for circuit - %s\n", circuit_id);
        return 1;
    }

    log_info_ext("memsetting to zero\n");
    memset(conn->ea, '\0', size);

    int open_res = 0;
    if ((open_res = setup_afu_memory(conn, ports)) != 0) {
        return open_res;
    }

    log_info("successfully opened afu: %s\n", afu_name);

    // set effective address reference for caller
    *eaptr = (uint64_t)conn->ea;

#endif
    return ATTACH_OK;
}

int hotplug_memory_blocks(uint64_t memory_size) {

    char file_buff[128];

    uint64_t probe_addr = config.INIT_PROBE_ADDR;

    char *online_command = "online_movable";
    for (int i = 0; i < memory_size / config.MEMBLOCK_SIZE;
         i++, probe_addr += config.MEMBLOCK_SIZE) {

        snprintf(file_buff, sizeof(file_buff), "%s/memory%lu", config.MEMORY_PATH,
                 probe_addr / config.MEMBLOCK_SIZE);

        if (access(file_buff, F_OK) == -1) {
            // file does not exist
            FILE *fd = fopen(config.PROBE_PATH, "w");

            if (fd == NULL) {
                log_error_ext("error opening probe file: %s\n", config.PROBE_PATH);
            } else {
                int res = fprintf(fd, "%lu", probe_addr);
                if (res <= 0) {
                    log_error_ext("error probing %lu - res: %d...\n",
                                  probe_addr, res);
                }
                fflush(fd);
                fclose(fd);
            }
        }

        char online_buff[128];

        snprintf(online_buff, sizeof(online_buff),
                 "/sys/devices/system/memory/memory%lu/state",
                 probe_addr / config.MEMBLOCK_SIZE);

        if (access(online_buff, W_OK) == -1) {

            log_error_ext("Unable to get write access on    %s\n", online_buff);
            return ERR_PROBE;
        }

        FILE *fd = fopen(online_buff, "w");
        if (fd == NULL) {
            log_error_ext("Error opening %s\n", online_buff);
            return ERR_PROBE;
        }

        int res = fprintf(fd, "%s\n", online_command);

        if (res <= 0) {
            log_error_ext("error onlining...\n");
            return ERR_PROBE;
        }
        fflush(fd);
        fclose(fd);
    }
    return ATTACH_OK;
}

int attach_compute(const char *circuit_id, const char *afu_name,
                   iport_list *ports, const uint64_t effective_addr,
                   const uint64_t size, int no_hotplug) {

    if (ports == NULL) {
        log_error_ext("ports cannot be null\n");
        return ERR_PORT_UNSUPPORTED;
    } else if (ports->next != NULL) {
        log_warn_ext("Only single port setup supported\n");
        return ERR_PORT_UNSUPPORTED;
    }

    connection *conn = new_conn(circuit_id, afu_name, size, no_hotplug);

    add_conn(conn);
#ifdef MOCK
    log_info_ext("mocking memory attachment on compute side\n");
    if (no_hotplug == 1)
        log_info_ext("Request with no_hotplug flag set\n");
    else if (no_hotplug == 0)
	log_info_ext("Request without no_hotplug flag set\n");
    return ATTACH_OK;
#else

    int open_res = 0;
    if ((open_res = setup_afu_compute(conn, effective_addr, ports)) != 0) {
        return open_res;
    }

    log_info_ext("AFU %s succesfully opened\n", afu_name);

    // Allow the AURORA channel to finish the setup step
    // evaluate if we can decrease this value
    sleep(5);

    if (no_hotplug){
        log_debug_ext("No need to hoplug this memory chunk");
        return ATTACH_OK;
    }

    return hotplug_memory_blocks(size); // add size to
#endif
}
