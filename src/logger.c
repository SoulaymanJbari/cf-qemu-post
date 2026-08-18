#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <errno.h>

typedef struct LogRecord {
    uint64_t insn_count;
    uint64_t address;
    char cpu;
    char store;
    char access_size;
    char padding[5];
} LogRecord;

void transfer_logs(const char *output_dir, size_t buf_size_per_cpu) {
    const char *meta_file = "/dev/shm/qemu_trace_metadata";
    const char *shm_file  = "/dev/shm/ramulator_qemu_shm";
    
    FILE *meta = fopen(meta_file, "r");
    if (!meta) {
        return;
    }

    int fd_in = open(shm_file, O_RDONLY);
    if (fd_in < 0) {
        fprintf(stderr, "Erreur lecture SHM %s: %s\n", shm_file, strerror(errno));
        fclose(meta);
        return;
    }

    printf("[LOGGER] Signal recu. Slot SHM par CPU : %zu octets. Debut du transfert vers %s...\n", 
           buf_size_per_cpu, output_dir);

    int cpu;
    uint64_t count;
    
    while (fscanf(meta, "CPU_%d:%lu\n", &cpu, &count) == 2) {
        if (count == 0) {
            continue;
        }

        uint64_t bytes_to_copy = count * sizeof(LogRecord);
        char out_path[256];
        snprintf(out_path, sizeof(out_path), "%s/log.txt.%d", output_dir, cpu);

        int fd_out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd_out < 0) {
            fprintf(stderr, "Erreur ecriture %s: %s\n", out_path, strerror(errno));
            continue;
        }

        off_t offset = (off_t)cpu * buf_size_per_cpu;
        uint64_t remaining = bytes_to_copy;
        
        while (remaining > 0) {
            ssize_t sent = sendfile(fd_out, fd_in, &offset, remaining);
            if (sent <= 0) {
                break;
            }
            remaining -= sent;
        }

        close(fd_out);
        printf("[LOGGER] CPU %d : %lu logs (%lu octets) transferes.\n", 
               cpu, (unsigned long)count, (unsigned long)bytes_to_copy);
    }

    close(fd_in);
    fclose(meta);
    unlink(meta_file);
    printf("[LOGGER] Transfert termine.\n");
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <dossier_destination> <taille_buffer_par_cpu_en_Mo>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *output_dir = argv[1];
    long mb = atol(argv[2]);
    if (mb <= 0) {
        fprintf(stderr, "Erreur : taille de buffer invalide (%s)\n", argv[2]);
        exit(EXIT_FAILURE);
    }
    size_t buf_size_per_cpu = (size_t)mb * (1024 * 1024);

    struct stat st = {0};
    if (stat(output_dir, &st) == -1) {
        mkdir(output_dir, 0700);
    }

    transfer_logs(output_dir, buf_size_per_cpu);
    return 0;
}
