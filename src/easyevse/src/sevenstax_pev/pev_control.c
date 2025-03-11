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
#include <linux/input.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <signal.h>
#include <mqueue.h>

typedef enum TAG_ENERGY_TRANSFER_MODE
{
    CHARGING,
    DISCHARGING
} TRANSFER_Mode;

pid_t pev_stx_pid;
static TRANSFER_Mode pev_transfer_mode = CHARGING;
const char* const pev_charging_pnc_argument_list[] = {"/usr/lib/easyevse/SEVENSTAX_PEV_PNC", "-t", "c", "-s", NULL, NULL};
const char* const pev_discharging_pnc_argument_list[] = {"/usr/lib/easyevse/SEVENSTAX_PEV_PNC", "-t", "d", "-s", NULL, NULL};
const char* const pev_charging_eim_argument_list[] = {"/usr/lib/easyevse/SEVENSTAX_PEV_EIM", "-t", "c", "-s", NULL, NULL};
const char* const pev_discharging_eim_argument_list[] = {"/usr/lib/easyevse/SEVENSTAX_PEV_EIM", "-t", "d", "-s", NULL, NULL};
char* pev_charging_argument_list[] = {NULL, NULL, NULL, NULL, NULL, NULL};
char* pev_discharging_argument_list[] = {NULL, NULL, NULL, NULL, NULL, NULL};
const char* const states[] = {"PAUSE", "RESUME", "STOP", "SOC"};
const char mq_name1[] = "/stx_mqd1";
const char mq_name2[] = "/stx_mqd2";
const char event[] = "/dev/input/event1";
const char ev_close[] = "/usr/lib/easyevse/SIGBRD_SYNC EV_CLOSE";
static unsigned long send_time = 0;
struct sigevent sig_ev2;
const char soc_start1[] = "20";
const char soc_start2[] = "100";
char soc_start[4];
bool switch_tranfer_mode = false;
static mqd_t mqd1;
static mqd_t mqd2;

static void sig_handler(int sig)
{
    int ret = -1;
    mq_close(mqd1);
    mq_close(mqd2);
    ret = kill(pev_stx_pid, 0);
    if (!ret)
    {
        kill(pev_stx_pid, SIGTERM);
        sleep(1);
        ret = kill(pev_stx_pid, 0);
        if (!ret)
        {
            kill(pev_stx_pid, SIGKILL);
        }
        wait(NULL);
    }
    else
    {
        printf("pev sig_handler: errno=%d, desc=%s \n", errno, strerror(errno));
    }
    mq_unlink(mq_name1);
    mq_unlink(mq_name2);
    system(ev_close);
    exit(1);
}

static void notify_thread_func(union sigval sv)
{
    ssize_t num;
    void *rev_buf = NULL;
    struct mq_attr attr;
    mqd_t *mqdp = sv.sival_ptr;
    bool result = true, tempb = true;
    if (mq_getattr(*mqdp, &attr) == -1)
    {
        printf("mq_getattr: errno=%d, desc=%s \n", errno, strerror(errno));
    }

    rev_buf = malloc(attr.mq_msgsize + 1);
    if (rev_buf == NULL)
    {
        printf("malloc: errno=%d, desc=%s \n", errno, strerror(errno));
    }

    if (mq_notify(*mqdp, &sig_ev2) == -1)
    {
        printf("mq_notify: errno=%d, desc=%s \n", errno, strerror(errno));
    }

    while ((num = mq_receive(*mqdp, rev_buf, attr.mq_msgsize + 1, NULL)) >=0 )
    {
    }
    strncpy(soc_start, rev_buf, 4);

    kill(pev_stx_pid, SIGTERM);
    wait(NULL);
    system(ev_close);
    switch_tranfer_mode = true;

    free(rev_buf);
    pthread_exit(NULL);
}

static void * mqd2_init(void)
{
    mqd2 = mq_open(mq_name2, O_RDONLY | O_CREAT | O_NONBLOCK, 0666, NULL);
    if (mqd2 == (mqd_t)-1)
    {
        printf("mqd2: mq_open: errno=%d, desc=%s \n", errno, strerror(errno));
    }
    sig_ev2.sigev_notify = SIGEV_THREAD;
    sig_ev2.sigev_notify_function = notify_thread_func;
    sig_ev2.sigev_notify_attributes = NULL;
    sig_ev2.sigev_value.sival_ptr = &mqd2;
    if (mq_notify(mqd2, &sig_ev2) == -1)
    {
        printf("mqd2: mq_notify: errno=%d, desc=%s \n", errno, strerror(errno));
    }
}

int main(int argc, char * argv[])
{
    int key_fd, ret;
    struct input_event ev;
    fd_set readfds;
    unsigned long count = 0;
    struct timeval tv;
    bool start_count = false, end_count = false;
    unsigned int msg_prio = 0;
    ssize_t msg_len = 8;
    int i = 0, j = 0;

    gettimeofday(&tv, NULL);
    send_time = tv.tv_sec;

    if (argc < 3)
    {
        printf("Please specify the first argument as \"EIM\" or \"PNC\" \n");
        printf("and the second argument as \"C\" or \"D\" \n");
        return -1;
    }

    if (strcmp(argv[1],"EIM") == 0)
    {
        for (i = 0; i < 4; i++)
        {
            pev_charging_argument_list[i] = pev_charging_eim_argument_list[i];
            pev_discharging_argument_list[i] = pev_discharging_eim_argument_list[i];
        }
        printf("EV will select External Authorization \n");
    }
    else if (strcmp(argv[1],"PNC") == 0)
    {
        for (j = 0; j < 4; j++)
        {
            pev_charging_argument_list[j] = pev_charging_pnc_argument_list[j];
            pev_discharging_argument_list[j] = pev_discharging_pnc_argument_list[j];
        }
        printf("EV will select PnC Authorization \n");
    }
    else
    {
        printf("Please specify Authorization is \"EIM\" or \"PNC\" \n");
        return -1;
    }
    pev_charging_argument_list[4] = soc_start;
    pev_discharging_argument_list[4] = soc_start;

    if (strcmp(argv[2],"C") == 0)
    {
        pev_transfer_mode = CHARGING;
        strcpy(soc_start, soc_start1);
    }
    else if (strcmp(argv[2],"D") == 0)
    {
        pev_transfer_mode = DISCHARGING;
        strcpy(soc_start, soc_start2);
    }
    else
    {
        printf("Please specify Transfer Mode\n");
        printf("\"C\" for charging, \"D\" for discharging.\n");
        return -1;
    }

    mqd1 = mq_open(mq_name1, O_WRONLY | O_CREAT | O_NONBLOCK, 0666, NULL);
    if (mqd1 == (mqd_t)-1)
    {
        printf("mqd1: mq_open: errno=%d, desc=%s \n", errno, strerror(errno));
        return -1;
    }

    mqd2_init();
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    key_fd = open (event, O_RDONLY | O_NONBLOCK);
    if (key_fd <= 0)
    {
        printf ("open %s device error!\n", event);
        return -1;
    }

    pid_t pid_1 = vfork();
    if (pid_1 < 0)
    {
        printf("vfork: errno=%d, desc=%s \n", errno, strerror(errno));
    }
    else if (pid_1 == 0)
    {
        if (pev_transfer_mode == CHARGING)
        {
            ret = execvp(pev_charging_argument_list[0], pev_charging_argument_list);
        }
        else if (pev_transfer_mode == DISCHARGING)
        {
            ret = execvp(pev_discharging_argument_list[0], pev_discharging_argument_list);
        }
        if (ret == -1)
        {
            printf("execvp: errno=%d, desc=%s \n", errno, strerror(errno));
        }
    }
    else
    {
        pev_stx_pid = pid_1;
    }

    for(;;)
    {
        FD_ZERO(&readfds);
        FD_SET(key_fd, &readfds);

        ret = select(key_fd + 1,&readfds, NULL, NULL, NULL);
        switch(ret)
        {
        case -1:
            perror("select failed\n");
            break;
        case 0:
            perror("select timeout\n");
            break;
        default:
            if (FD_ISSET(key_fd, &readfds))
            {
                read(key_fd, &ev, sizeof(ev));
                /* Press BTN1 to pause and resume */
                if ((ev.type == EV_KEY) && (ev.code == KEY_PAUSE) && (ev.value == 1))
                {
                    start_count = true;
                }
                else if ((ev.type == EV_KEY) && (ev.code == KEY_PAUSE) && (ev.value == 0))
                {
                    start_count = false;
                    end_count = true;
                }
                else if ((ev.type == EV_KEY) && (ev.code == KEY_PAUSE) && (ev.value == 2))
                {
                    if (start_count)
                        count ++;
                }
                /* Press BTN2 to switch charging and discharging */
                else if ((ev.type == EV_KEY) && (ev.code == KEY_NEW) && (ev.value == 1))
                {
                    gettimeofday(&tv, NULL);
                    if ((tv.tv_sec - send_time) > 5)
                    {
                        if (mq_send(mqd1, states[3], msg_len, msg_prio) == -1)
                        {
                            printf("mqd1: mq_send: errno=%d, desc=%s \n", errno, strerror(errno));
                        }
                        else
                        {
                            send_time = tv.tv_sec;
                        }
                    }
                    else
                    {
                        break;
                    }
                }
            }
            break;
        }

        if (end_count)
        {
            gettimeofday(&tv, NULL);
            if ((tv.tv_sec - send_time) > 5)
            {
                if (count > 10) /* Long press BTN1 to pause */
                {
                    if (mq_send(mqd1, states[0], msg_len, msg_prio) == -1)
                    {
                        printf("mqd1: mq_send: errno=%d, desc=%s \n", errno, strerror(errno));
                    }
                    else
                    {
                        send_time = tv.tv_sec;
                    }
                }
                else if (count <= 5) /* Short press BTN1 to resume */
                {
                    if (mq_send(mqd1, states[1], msg_len, msg_prio) == -1)
                    {
                        printf("mqd1: mq_send: errno=%d, desc=%s \n", errno, strerror(errno));
                    }
                    else
                    {
                        send_time = tv.tv_sec;
                    }
                }
            }
            end_count = false;
            count = 0;
        }

        if (switch_tranfer_mode)
        {
            if (pev_transfer_mode == CHARGING)
            {
                pid_t pid_2 = vfork();
                if (pid_2 < 0)
                {
                    printf("vfork: errno=%d, desc=%s \n", errno, strerror(errno));
                }
                else if (pid_2 == 0)
                {
                    ret = execvp(pev_discharging_argument_list[0], pev_discharging_argument_list);
                    if (ret == -1)
                    {
                        printf("execvp: errno=%d, desc=%s \n", errno, strerror(errno));
                    }
                }
                else
                {
                    pev_stx_pid = pid_2;
                    pev_transfer_mode = DISCHARGING;
                    switch_tranfer_mode = false;
                    continue;
                }
             }
             else if (pev_transfer_mode == DISCHARGING)
             {
                pid_t pid_3 = vfork();
                if (pid_3 < 0)
                {
                    printf("vfork: errno=%d, desc=%s \n", errno, strerror(errno));
                }
                else if (pid_3 == 0)
                {
                    ret = execvp(pev_charging_argument_list[0], pev_charging_argument_list);
                    if (ret == -1)
                    {
                        printf("execvp: errno=%d, desc=%s \n", errno, strerror(errno));
                    }
                }
                else
                {
                    pev_stx_pid = pid_3;
                    pev_transfer_mode = CHARGING;
                    switch_tranfer_mode = false;
                    continue;
                }
             }
        }
    }
    close(key_fd);
    return 0;
}
