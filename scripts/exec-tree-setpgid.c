#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s MARKER\n", argv[0]);
        return 2;
    }
    if (setpgid(0, 0) != 0) {
        fprintf(stderr, "setpgid: %s\n", strerror(errno));
        return 3;
    }
    int marker = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (marker < 0 || write(marker, "ready\n", 6) != 6 || close(marker) != 0) {
        fprintf(stderr, "marker: %s\n", strerror(errno));
        return 4;
    }
    execl("/bin/sleep", "sleep", "30", (char *)NULL);
    fprintf(stderr, "exec sleep: %s\n", strerror(errno));
    return 5;
}
