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

typedef enum TAG_V2G_STATE
{
    PAUSE,
    STOP
} V2G_STATE;

pid_t evse_stx_pid;
const char* const evse_charging_argument_list[] = {"/usr/lib/easyevse/SEVENSTAX", NULL};
const char* const states[] = {"PAUSE", "STOP"};
const char event[] = "/dev/input/event1";
const char mq_name[] = "/stx_mqd";
const char evse_close[] = "/usr/lib/easyevse/SIGBRD_SYNC EVSE_CLOSE";
static unsigned long send_time = 0;
mqd_t mqd = -1;

void sig_handler(int sig)
{
    int ret = -1;
    mq_close(mqd);
    ret = kill(evse_stx_pid, 0);
    if (!ret)
    {
        kill(evse_stx_pid, SIGTERM);
        ret = kill(evse_stx_pid, 0);
        if (!ret)
        {
            kill(evse_stx_pid, SIGKILL);
        }
        wait(NULL);
    }
    else
    {
        printf("evse sig_handler: errno=%d, desc=%s \n", errno, strerror(errno));
    }
    mq_unlink(mq_name);
    system(evse_close);
    exit(1);
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
    mqd = mq_open(mq_name, O_WRONLY | O_CREAT | O_NONBLOCK, 0666, NULL);
    if (mqd == (mqd_t)-1)
    {
        printf("mq_open: errno=%d, desc=%s \n", errno, strerror(errno));
    }
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    key_fd = open (event, O_RDONLY | O_NONBLOCK);
    if (key_fd <= 0)
    {
        printf ("open %s device error!\n", event);
        return 0;
    }

    pid_t pid_1 = vfork();
    if (pid_1 < 0)
    {
        printf("vfork: errno=%d, desc=%s \n", errno, strerror(errno));
    }
    else if (pid_1 == 0)
    {
        ret = execvp(evse_charging_argument_list[0], evse_charging_argument_list);
        if (ret == 0)
        {
            sleep(2);
            system("ros2 run easyevse SEVENSTAX");
        }
        else
        {
            printf("execvp: errno=%d, desc=%s \n", errno, strerror(errno));
        }
    }
    else
    {
        evse_stx_pid = pid_1;
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
                /* Press BTN1 to pause */
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
                /* Press BTN2 to restart evse stx */
                else if ((ev.type == EV_KEY) && (ev.code == KEY_NEW) && (ev.value == 1))
                {
                    gettimeofday(&tv, NULL);
                    if ((tv.tv_sec - send_time) > 5)
                    {
                        if (mq_send(mqd, states[1], msg_len, msg_prio) == -1)
                        {
                            printf("mq_send: errno=%d, desc=%s \n", errno, strerror(errno));
                        }
                        else
                        {
                            send_time = tv.tv_sec;
                        }
                    }
                    sleep(3);
                    kill(evse_stx_pid, SIGTERM);
                    wait(NULL);
                    system(evse_close);

                    pid_t pid_2 = vfork();
                    if (pid_2 < 0)
                    {
                        printf("\nINFO: evse_stx_pid fork failed\n");
                    }
                    else if (pid_2 == 0)
                    {
                        ret = execvp(evse_charging_argument_list[0], evse_charging_argument_list);
                        if (ret == 0)
                        {
                            sleep(2);
                            system("ros2 run easyevse SEVENSTAX");
                        }
                        else
                        {
                            printf("execvp: errno=%d, desc=%s \n", errno, strerror(errno));
                        }
                    }
                    else
                    {
                        evse_stx_pid = pid_2;
                        break;
                    }
                }
            }

            if (end_count)
            {
                gettimeofday(&tv, NULL);
                if ((tv.tv_sec - send_time) > 5)
                {
                    if (count > 10) /* Long press BTN1 to pause */
                    {
                        if (mq_send(mqd, states[0], msg_len, msg_prio) == -1)
                        {
                            printf("mq_send: errno=%d, desc=%s \n", errno, strerror(errno));
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
            break;
        }
    }
    close(key_fd);
    return 0;
}
