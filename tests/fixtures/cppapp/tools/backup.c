#include <stdio.h>
#include <stdlib.h>

static void run_backup(const char *target) {
  char cmd[128];
  sprintf(cmd, "cp notes.db %s", target);
  system(cmd);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    return 1;
  }
  printf(argv[1]);
  run_backup(argv[1]);
  return 0;
}
