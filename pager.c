#include "pager.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <sys/wait.h>

pid_t pager_start(const char *mode)
{
    int pipefd[2];

    if (!isatty(STDOUT_FILENO))
        return 0;

    if (pipe2(pipefd, O_CLOEXEC) < 0)
        err(1, "failed to create pipe");

    pid_t pid = fork();
    switch (pid) {
    case -1:
        err(1, "failed to fork");
        break;
    case 0:
        setenv("LESS", mode, true);
        dup2(pipefd[STDIN_FILENO], STDIN_FILENO);
        execlp("less", "less", NULL);
        err(1, "failed to start pager");
        break;
    }

    dup2(pipefd[STDOUT_FILENO], STDOUT_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);

    return pid;
}

int pager_wait(pid_t pid)
{
    int stat;

    fflush(stdout);
    fclose(stdout);

    if (waitpid(pid, &stat, 0) < 0)
        err(1, "Failed to get pager status");

    if (stat) {
        if (WIFEXITED(stat))
            return WEXITSTATUS(stat);
        if (WIFSIGNALED(stat))
            return -1;
    }

    return 0;
}

