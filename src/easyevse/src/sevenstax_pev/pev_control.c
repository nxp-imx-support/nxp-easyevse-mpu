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
const char* pev_charging_argument_list[] = {"/usr/lib/easyevse/SEVENSTAX_PEV", "-t", "c", NULL};
const char* pev_discharging_argument_list[] = {"/usr/lib/easyevse/SEVENSTAX_PEV", "-t", "d", NULL};
const char* states[] = {"PAUSE", "RESUME", "STOP"};
static unsigned long send_time = 0;

void sig_handler(int sig)
{
    kill(pev_stx_pid, SIGKILL);
    wait(NULL);
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
    char name[] = "/stx_mqd";
    mqd_t mqd;
    mqd = mq_open(name, O_WRONLY | O_CREAT | O_NONBLOCK, 0666, NULL);

    signal(SIGINT, sig_handler);

    key_fd = open ("/dev/input/event1", O_RDONLY | O_NONBLOCK);
    if (key_fd <= 0)
    {
        printf ("open /dev/input/event1 device error!\n");
        return 0;
    }

    pid_t pid_1 = vfork();
    if (pid_1 < 0)
    {
        printf("pev_stx_pid fork failed\n");
    }
    else if (pid_1 == 0)
    {
        execvp(pev_charging_argument_list[0], pev_charging_argument_list);
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
            printf("select failed\n");
            break;
        case 0:
            printf("select timeout\n");
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
                        if (mq_send(mqd, states[2], msg_len, msg_prio) == -1)
                        {
                            printf("errno=%d, desc=%s \n", errno, strerror(errno));
                        }
                        else
                        {
                            send_time = tv.tv_sec;
                        }
                    }
                    sleep(3);
                    kill(pev_stx_pid, SIGKILL);
                    wait(NULL);
                    if (pev_transfer_mode == CHARGING)
                    {
                        pid_t pid_2 = vfork();
                        if (pid_2 < 0)
                        {
                            printf("\n pev_stx_pid fork failed\n");
                        }
                        else if (pid_2 == 0)
                        {
                            execvp(pev_discharging_argument_list[0], pev_discharging_argument_list);
                        }
                        else
                        {
                            pev_stx_pid = pid_2;
                            pev_transfer_mode = DISCHARGING;
                            break;
                        }
                    }
                    else if (pev_transfer_mode == DISCHARGING)
                    {
                        pid_t pid_3 = vfork();
                        if (pid_3 < 0)
                        {
                            printf("\nINFO: pev_stx_pid fork failed\n");
                        }
                        else if (pid_3 == 0)
                        {
                            execvp(pev_charging_argument_list[0], pev_charging_argument_list);
                        }
                        else
                        {
                            pev_stx_pid = pid_3;
                            pev_transfer_mode = CHARGING;
                            break;
                        }
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
                    else if (count <= 5) /* Short press BTN1 to resume */
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
