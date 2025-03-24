/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <signal.h>

const char ev_close[] = "/usr/lib/easyevse/SIGBRD_SYNC EV_CLOSE";

static void sig_handler(int sig)
{
    system(ev_close);
    exit(1);
}

int main(int argc, char * argv[])
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    stx_startup(argc, argv);
    return 0;
}
