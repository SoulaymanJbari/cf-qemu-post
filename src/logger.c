#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
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

void transfer_logs(const char *output_dir) {
    const char *meta_file = "/dev/shm/qemu_trace_metadata";
    FILE *meta = fopen(meta_file, "r");
    if (!meta) return;

    printf("[LOGGER] Signal recu. Debut du transfert vers %s...\n", output_dir);

    int cpu;
    uint64_t count;
    
    while (fscanf(meta, "CPU_%d:%lu\n", &cpu, &count) == 2) {
        if (count == 0) continue;

        uint64_t bytes_to_copy = count * sizeof(LogRecord);
        char shm_path[256], out_path[256];
        
        snprintf(shm_path, sizeof(shm_path), "/dev/shm/log.txt.%d", cpu);
        snprintf(out_path, sizeof(out_path), "%s/log.txt.%d", output_dir, cpu);

        int fd_in = open(shm_path, O_RDONLY);
        if (fd_in < 0) {
            fprintf(stderr, "Erreur lecture %s: %s\n", shm_path, strerror(errno));
            continue;
        }

        int fd_out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd_out < 0) {
            fprintf(stderr, "Erreur ecriture %s: %s\n", out_path, strerror(errno));
            close(fd_in);
            continue;
        }

        // Transfert Kernel-Space ultra-rapide
        off_t offset = 0;
        uint64_t remaining = bytes_to_copy;
        while (remaining > 0) {
            ssize_t sent = sendfile(fd_out, fd_in, &offset, remaining);
            if (sent <= 0) break;
            remaining -= sent;
        }

        close(fd_in);
        close(fd_out);

        unlink(shm_path);
        printf("[LOGGER] CPU %d : %lu logs (%lu octets) transferes et RAM liberee.\n", cpu, count, bytes_to_copy);
    }

    fclose(meta);
    unlink(meta_file);
    printf("[LOGGER] Transfert termine. En attente du prochain signal...\n");
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <dossier_stockage_destination>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *output_dir = argv[1];
    struct stat st = {0};
    if (stat(output_dir, &st) == -1) {
        mkdir(output_dir, 0700);
    }

    printf("[LOGGER] Demarrage en tache de fond. Surveillance de /dev/shm...\n");
    transfer_logs(output_dir);

    return 0;
}