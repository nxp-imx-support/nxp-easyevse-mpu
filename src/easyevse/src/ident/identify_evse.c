/***********************************************************************
 *
 *
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 *
 *************************************************************************/

#ifndef UART_BD_DEV
#define UART_BD_DEV "/dev/ttyLP2"
#endif

/* standard includes */
#include "string.h"
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    CMD_ERR             = -1,
    CP_STATE            = 'c',
    CP_RESISTOR_VALUE   = 'h',
    CMD_UNKNOWN         = 'n',
} COMMAND_CODE;

enum {
    EVSE,
    PEV,
    UNKNOWN
};
/*! @brief Ring buffer size (Unit: Byte). */
#define BUFFER_SIZE     4

static int ubd_fd = -1; /* UART Bridge file description*/

/* Select() timeout, dependent on UART speed and SIGBRD response time */
static struct timeval timeout = {0, 20000};

static void Init_SigBrd_Uart(void)
{
    int ret;
    struct termios uart_cfg_opt;
    speed_t speed = B115200;
    ubd_fd = open(UART_BD_DEV, O_RDWR | O_NOCTTY | O_NONBLOCK);

    if(ubd_fd < 0)
    {
        perror("Init_SigBrd_Uart() - Open UART DEV error\n");
    }

    ret = tcgetattr(ubd_fd, &uart_cfg_opt);
    if(ret == -1)
    {
        perror("Init_SigBrd_Uart() - tcgetattr error\n");
    }

    uart_cfg_opt.c_cflag &= ~PARENB;
    uart_cfg_opt.c_cflag &= ~CSTOPB;
    uart_cfg_opt.c_cflag &= ~CSIZE;
    uart_cfg_opt.c_cflag |= CS8;
    uart_cfg_opt.c_cflag &= ~CRTSCTS;
    uart_cfg_opt.c_cflag |= CREAD | CLOCAL;

    uart_cfg_opt.c_lflag |= ICANON;
    uart_cfg_opt.c_lflag &= ~ECHO; /* mask rx re-send */
    uart_cfg_opt.c_lflag &= ~ECHOE;
    uart_cfg_opt.c_lflag &= ~ECHONL;
    uart_cfg_opt.c_lflag &= ~ISIG;
    uart_cfg_opt.c_iflag &= ~(IXON | IXOFF | IXANY);
    uart_cfg_opt.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR);
    uart_cfg_opt.c_iflag |= ICRNL;

    uart_cfg_opt.c_oflag &= ~OPOST;
    uart_cfg_opt.c_oflag &= ~ONLCR;
    cfsetospeed(&uart_cfg_opt, speed);
    cfsetispeed(&uart_cfg_opt, speed);
    ret = tcsetattr(ubd_fd, TCSANOW, &uart_cfg_opt);
    if(ret == -1)
    {
        perror("Init_SigBrd_Uart() - tcsetattr error\n");
    }
}

static ssize_t nblk_write_uart(const char * const buf, size_t size, struct timeval *timeout)
{
    ssize_t len = 0;
    fd_set writefds;
    int ret;

    struct timeval write_timeout;
    write_timeout.tv_sec = timeout->tv_sec;
    write_timeout.tv_usec = timeout->tv_usec;

    FD_ZERO(&writefds);
    FD_SET(ubd_fd, &writefds);

    ret = select(ubd_fd + 1, NULL, &writefds, NULL, &write_timeout);
    if (ret == -1)
    {
        return ret;
    }
    else if(ret == 0)
    {
        perror("nblk_write_uart() - write select timeout\n");
    }
    else if(ret > 0)
    {
        len = write(ubd_fd, buf, size);
        if(len < 0)
        {
            perror("UART_BRIDGE Message Sent error\n");
        }
    }
    return len;
}

static ssize_t nblk_read_uart(void *buf, size_t size, struct timeval *timeout)
{
    ssize_t len = 0;
    fd_set readfds;
    int ret;

    struct timeval read_timeout;
    read_timeout.tv_sec = timeout->tv_sec;
    read_timeout.tv_usec = timeout->tv_usec;

    FD_ZERO(&readfds);
    FD_SET(ubd_fd, &readfds);

    ret = select(ubd_fd + 1, &readfds, NULL, NULL, &read_timeout);
    if (ret == -1)
    {
        return ret;
    }
    else if(ret == 0)
    {
        perror("nblk_read_uart() - read select timeout\n");
    }
    else if(ret > 0)
    {
        len = read(ubd_fd, buf, size);
        if(len < 0)
        {
            perror("UART_BRIDGE Message Receive error\n");
        }
    }
    return len;
}

static COMMAND_CODE parse_reply(char *messageBuffer)
{
    char *cmd;
    if(messageBuffer[0] == '\0')
    {
        messageBuffer[0] = '0';
    }

    cmd = strsep(&messageBuffer, "]");
    strsep(&cmd, "[");
    if(cmd == NULL)
    {
        return CMD_ERR;
    }
    return cmd[0];
}

/*******************************************************************************
 * DESCRIPTION:
 * Only EVSE can support CP_STATE command
 * Only EV can support CP_RESISTOR_VALUE command
 *
 ******************************************************************************/
static int SIGBRD_UARTCommsProcess(char command_code)
{
    int len;
    char messageBuffer[BUFFER_SIZE];
    char command[BUFFER_SIZE] = {' ',' ',' ','\r'};
    COMMAND_CODE reply_code;

    uint8_t bSize_command = 0;

    switch (command_code)
    {
        case CP_STATE:
            command[1] = '\r';
            bSize_command = 2;
            break;
        case CP_RESISTOR_VALUE:
            command[1] = (char)1;
            command[2] = '\r';
            bSize_command = 3;
            break;
        default:
            printf("Command error \n\r");
            return CMD_ERR;
            break;
    }

    command[0] = command_code;
    memset(messageBuffer, 0, sizeof(messageBuffer));

    len = nblk_write_uart(command, bSize_command, &timeout);
    if(len < 0)
    {
        perror("Message Sent error\n");
    }
    else if(len == 0)
    {
        perror("SIGBRD_UARTCommsProcess() - empty write or select timeout\n");
    }

    reply_code = CMD_ERR;
    while(reply_code != command_code)
    {
        len = nblk_read_uart(messageBuffer, sizeof(messageBuffer), &timeout);
        if(len < 0)
        {
            perror("Reading data Error\n");
            return CMD_ERR;
        }
        else if(len == 0)
        {
            perror("SIGBRD_UARTCommsProcess() - empty read or select timeout\n");
            return CMD_ERR;
        }
        else
        {
            reply_code = parse_reply(messageBuffer);
            if((reply_code == CMD_ERR) || (reply_code == CMD_UNKNOWN))
            {
                return reply_code;
            }
        }
    }
}

int main(int argc, char * argv[])
{
    COMMAND_CODE code1 = -1, code2 = -1;

    Init_SigBrd_Uart();
    code1 = SIGBRD_UARTCommsProcess(CP_STATE);
    code2 = SIGBRD_UARTCommsProcess(CP_RESISTOR_VALUE);
    close(ubd_fd);

    if (code1 == CP_STATE)
    {
        printf("EVSE be identified\n");
        return EVSE;
    }
    else if (code2 == CP_RESISTOR_VALUE)
    {
        printf("PEV be identified\n");
        return PEV;
    }
    else
    {
        printf("UNKNOWN\n");
        return UNKNOWN;
    }
}
