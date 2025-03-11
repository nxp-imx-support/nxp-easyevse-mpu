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

struct sigevent sig_ev1;
const char* const states[] = {"PAUSE", "RESUME", "STOP", "SOC"};
const char mq_name1[] = "/stx_mqd1";
const char mq_name2[] = "/stx_mqd2";
char soc[3];
static mqd_t mqd1 = -1;
static mqd_t mqd2 = -1;

static void sig_handler(int sig)
{
    mq_close(mqd1);
    mq_close(mqd2);
    exit(1);
}

static void notify_thread_func(union sigval sv)
{
    ssize_t num;
    void *rev_buf = NULL;
    struct mq_attr attr;
    mqd_t *mqdp = sv.sival_ptr;
    unsigned int msg_prio = 0;
    ssize_t msg_len = 8;
    bool result = true, tempb = true;
    uint8_t battery_level = 0;
    if (mq_getattr(*mqdp, &attr) == -1)
    {
        printf("mq_getattr: errno=%d, desc=%s \n", errno, strerror(errno));
    }

    rev_buf = malloc(attr.mq_msgsize + 1);
    if (rev_buf == NULL)
    {
        printf("malloc: errno=%d, desc=%s \n", errno, strerror(errno));
    }

    if (mq_notify(*mqdp, &sig_ev1) == -1)
    {
        printf("mq_notify: errno=%d, desc=%s \n", errno, strerror(errno));
    }

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
    else if (strcmp(rev_buf, states[3]) == 0)
    {
        stxV2GApplExt_EVStopCharging(&result);
        stxV2GApplExt_GetEVBatteryLevel(&battery_level, &result);
        snprintf(soc, sizeof(soc), "%d", battery_level);
        if (mq_send(mqd2, soc, msg_len, msg_prio) == -1)
        {
            printf("mqd2: mq_send: errno=%d, desc=%s \n", errno, strerror(errno));
        }
    }
    free(rev_buf);
    pthread_exit(NULL);
}

int main(int argc, char * argv[])
{
    mqd1 = mq_open(mq_name1, O_RDONLY | O_NONBLOCK);
    if (mqd1 == (mqd_t)-1)
    {
        printf("mqd1: mq_open: errno=%d, desc=%s \n", errno, strerror(errno));
        return -1;
    }
    sig_ev1.sigev_notify = SIGEV_THREAD;
    sig_ev1.sigev_notify_function = notify_thread_func;
    sig_ev1.sigev_notify_attributes = NULL;
    sig_ev1.sigev_value.sival_ptr = &mqd1;

    if (mq_notify(mqd1, &sig_ev1) == -1)
    {
        printf("mqd1: mq_notify: errno=%d, desc=%s \n", errno, strerror(errno));
        return -1;
    }

    mqd2 = mq_open(mq_name2, O_WRONLY | O_NONBLOCK);
    if (mqd2 == (mqd_t)-1)
    {
        printf("mqd2: mq_open: errno=%d, desc=%s \n", errno, strerror(errno));
        return -1;
    }
    signal(SIGTERM, sig_handler);
    stx_startup(argc, argv);
}
