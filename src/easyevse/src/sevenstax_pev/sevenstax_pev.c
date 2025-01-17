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
#include <pthread.h>
#include <signal.h>
#include <mqueue.h>
#include "easyevse/stx_startup.h"

typedef enum TAG_V2G_STATE
{
    PAUSE,
    RESUME,
    STOP
} V2G_STATE;

struct sigevent sig_ev;
const char* states[] = {"PAUSE", "RESUME", "STOP"};

static void notify_thread_func(union sigval sv)
{
    ssize_t num;
    void *rev_buf = NULL;
    struct mq_attr attr;
    mqd_t *mqdp = sv.sival_ptr;
    bool result = true, tempb = true;
    if (mq_getattr(*mqdp, &attr) == -1)
        printf("mq_getattr err\n");

    rev_buf = malloc(attr.mq_msgsize + 1);
    if (rev_buf == NULL)
        printf("malloc err\n");

    if (mq_notify(*mqdp, &sig_ev) == -1)
        printf("mq_notify err1\n");

    while ((num = mq_receive(*mqdp, rev_buf, attr.mq_msgsize + 1, NULL)) >=0 )
    {
    }

    if (strcmp(rev_buf, states[0]) == 0)
    {
        stxV2GApplExt_EVSetChargingSessionPause(&result);
        if (!result)
        {
            printf("Pause request is invalid\n");
        }
    }
    else if (strcmp(rev_buf, states[1]) == 0)
    {
        stxV2GApplExt_EVSetChargingSessionResume(&result);
        if (!result)
        {
            printf("Resume request is invalid\n");
        }
    }
    else if (strcmp(rev_buf, states[2]) == 0)
    {
        stxV2GApplExt_EVStopCharging(&result);
        if (!result)
        {
            printf("Stop request is invalid\n");
        }
    }

    free(rev_buf);
    pthread_exit(NULL);
}

int main(int argc, char * argv[])
{
    char name[] = "/stx_mqd";
    mqd_t mqd = mq_open(name, O_RDONLY | O_NONBLOCK, 0666, NULL);
    sig_ev.sigev_notify = SIGEV_THREAD;
    sig_ev.sigev_notify_function = notify_thread_func;
    sig_ev.sigev_notify_attributes = NULL;
    sig_ev.sigev_value.sival_ptr = &mqd;

    if (mq_notify(mqd, &sig_ev) == -1)
        printf("mq_notify err\n");

    stx_startup(argc, argv);
}
