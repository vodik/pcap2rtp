#pragma once

#include <sys/types.h>

pid_t pager_start(const char *mode);
int pager_wait(pid_t pid);
