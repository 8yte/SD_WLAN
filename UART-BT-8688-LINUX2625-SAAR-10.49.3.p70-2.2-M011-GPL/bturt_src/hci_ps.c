/*
 *
 *  Bluetooth HCI UART driver
 *
 *
 *  Copyright (C) 2009, Marvell International Ltd.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/poll.h>

#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/signal.h>
#include <linux/ioctl.h>
#include <linux/skbuff.h>

#ifdef BT_AMP
#include <amp/bluetooth/bluetooth.h>
#include <amp/bluetooth/hci_core.h>
#else
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>
#endif
#include <linux/proc_fs.h>

#ifdef PXA9XX
#if defined(PXA950) || defined(PXA920)
#include <mach/mfp.h>
#include <mach/gpio.h>
#else
#include <asm/arch/mfp-pxa9xx.h>
#include <asm/arch/gpio.h>
#endif
#endif
#include "hci_uart.h"

u32 drvdbg = 0;

#ifndef CONFIG_BT_HCIUART_DEBUG
#undef  BT_DBG
#define	BT_DBG(fmt, arg...)  do {if (drvdbg)   printk(KERN_ALERT "%s: " fmt "\n" , __FUNCTION__ , ## arg);} while(0)
#endif

/** proc diretory root */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#define PROC_DIR    NULL
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define PROC_DIR    &proc_root
#else
#define PROC_DIR    proc_net
#endif

#define DEFAULT_BUF_SIZE 512

/** Default file permission */
#define DEFAULT_FILE_PERM  0644

/** Default time period in mili-second */
#define DEFAULT_TIME_PERIOD 2000

/** wakeup method DTR */
#define WAKEUP_METHOD_DTR       0
/** wakeup method break */
#define WAKEUP_METHOD_BREAK     1
/** wake up method EX break */
#define WAKEUP_METHOD_EXT_BREAK  2
/** wake up method RTS */
#define WAKEUP_METHOD_RTS       3

/** wakeup method invalid */
#define  WAKEUP_METHOD_INVALID  0xff
/** ps mode disable */
#define PS_MODE_DISABLE         0
/** ps mode enable */
#define PS_MODE_ENABLE          1
/** ps cmd exit ps  */
#define PS_CMD_EXIT_PS          1
/** ps cmd enter ps */
#define PS_CMD_ENTER_PS         2
/** ps state awake */
#define PS_STATE_AWAKE                0
/** ps state SLEEP */
#define PS_STATE_SLEEP                1

/** OGF */
#define OGF				0x3F
/** Bluetooth command : Sleep mode */
#define BT_CMD_AUTO_SLEEP_MODE		0x23
/** Bluetooth Power State : Enable */
#define BT_PS_ENABLE			0x02
/** Bluetooth Power State : Disable */
#define BT_PS_DISABLE			0x03
/** Bluetooth command: Wakeup method */
#define BT_CMD_WAKEUP_METHOD    0x53

#define BT_HOST_WAKEUP_METHOD_NONE      0x00
#define BT_HOST_WAKEUP_METHOD_DTR       0x01
#define BT_HOST_WAKEUP_METHOD_BREAK     0x02
#define BT_HOST_WAKEUP_METHOD_GPIO      0x03
#define BT_HOST_WAKEUP_DEFAULT_GPIO     5

#define BT_CTRL_WAKEUP_METHOD_DSR       0x00
#define BT_CTRL_WAKEUP_METHOD_BREAK     0x01
#define BT_CTRL_WAKEUP_METHOD_GPIO      0x02
#define BT_CTRL_WAKEUP_METHOD_EXT_BREAK  0x04
#define BT_CTRL_WAKEUP_METHOD_RTS       0x05

#define BT_CTRL_WAKEUP_DEFAULT_GPIO     4

#define  HCI_OP_AUTO_SLEEP_MODE 0xfc23
#define  HCI_OP_WAKEUP_METHOD   0xfc53
#define SEND_WAKEUP_METHOD_CMD          0x01
#define SEND_AUTO_SLEEP_MODE_CMD        0x02

typedef struct _BT_CMD
{
    /** OCF OGF */
    u16 ocf_ogf;
    /** Length */
    u8 length;
    /** Data */
    u8 data[4];
} __attribute__ ((packed)) BT_CMD;

/** Proc directory entry */
static struct proc_dir_entry *proc_bt = NULL;

struct ps_data
{
    u32 ps_mode;
    u32 cur_psmode;
    u32 ps_state;
    u32 ps_cmd;
    u32 interval;
    u32 wakeupmode;
    u32 cur_wakeupmode;
    u32 send_cmd;
    struct work_struct work;
    struct tty_struct *tty;
    struct timer_list ps_timer;
    u32 timer_on;
};

static struct ps_data g_data;
int wakeupmode = WAKEUP_METHOD_BREAK;
struct proc_data
{
    /** Read length */
    int rdlen;
    /** Read buffer */
    char *rdbuf;
    /** Write length */
    int wrlen;
    /** Maximum write length */
    int maxwrlen;
    /** Write buffer */
    char *wrbuf;
};

/** Debug dump buffer length */
#define DBG_DUMP_BUF_LEN 	64
/** Maximum number of dump per line */
#define MAX_DUMP_PER_LINE	16
/** Maximum data dump length */
#define MAX_DATA_DUMP_LEN	48
#define DBG_RAW_DATA        0x10
void
hexdump(char *prompt, u8 * buf, int len)
{
    int i;
    char dbgdumpbuf[DBG_DUMP_BUF_LEN];
    char *ptr = dbgdumpbuf;

    if (!drvdbg)
        return;
    printk(KERN_DEBUG "%s: len=%d\n", prompt, len);
    if (!(drvdbg & DBG_RAW_DATA))
        return;
    for (i = 1; i <= len; i++) {
        ptr += sprintf(ptr, "%02x ", *buf);
        buf++;
        if (i % MAX_DUMP_PER_LINE == 0) {
            *ptr = 0;
            printk(KERN_DEBUG "%s\n", dbgdumpbuf);
            ptr = dbgdumpbuf;
        }
    }
    if (len % MAX_DUMP_PER_LINE) {
        *ptr = 0;
        printk(KERN_DEBUG "%s\n", dbgdumpbuf);
    }
}

/** convert string to number */
int
string_to_number(char *s)
{
    int r = 0;
    int base = 0;
    int pn = 1;

    if (strncmp(s, "-", 1) == 0) {
        pn = -1;
        s++;
    }
    if ((strncmp(s, "0x", 2) == 0) || (strncmp(s, "0X", 2) == 0)) {
        base = 16;
        s += 2;
    } else
        base = 10;

    for (s = s; *s != 0; s++) {
        if ((*s >= '0') && (*s <= '9'))
            r = (r * base) + (*s - '0');
        else if ((*s >= 'A') && (*s <= 'F'))
            r = (r * base) + (*s - 'A' + 10);
        else if ((*s >= 'a') && (*s <= 'f'))
            r = (r * base) + (*s - 'a' + 10);
        else
            break;
    }

    return (r * pn);
}

static int
is_device_ready(struct hci_uart *hu)
{
    struct hci_dev *hdev = NULL;
    if (!hu) {
        BT_ERR("hu is NULL");
        return -ENODEV;
    }
    if (!hu->proto || !hu->hdev || !hu->tty) {
        BT_ERR("Device not ready! proto=%p, hdev=%p, tty=%p", hu->proto,
               hu->hdev, hu->tty);
        return -ENODEV;
    }
    hdev = hu->hdev;
    if (!test_bit(HCI_RUNNING, &hdev->flags)) {
        BT_ERR("HCI_RUNNING is not set");
        return -EBUSY;
    }
    return 0;
}

/*
 * Builds and sends an PS command packet.
 */
static int
send_ps_cmd(u8 cmd, struct hci_uart *hu)
{
    int err = 0;
    struct sk_buff *skb = NULL;
    BT_CMD *pCmd;

    BT_DBG("hu %p cmd 0x%x", hu, cmd);

    /* allocate packet */
    skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
    if (!skb) {
        BT_ERR("cannot allocate memory for HCILL packet");
        err = -ENOMEM;
        goto out;
    }

    pCmd = (BT_CMD *) skb->tail;
    pCmd->ocf_ogf = (OGF << 10) | BT_CMD_AUTO_SLEEP_MODE;
    pCmd->length = 1;
    if (cmd == PS_MODE_ENABLE)
        pCmd->data[0] = BT_PS_ENABLE;
    else
        pCmd->data[0] = BT_PS_DISABLE;

    bt_cb(skb)->pkt_type = HCI_COMMAND_PKT;
    skb_put(skb, sizeof(BT_CMD) - 4 + pCmd->length);
    skb->dev = (void *) hu->hdev;

    /* send packet */
    hu->proto->enqueue(hu, skb);
    hci_uart_tx_wakeup(hu);

  out:
    return err;
}

/*
 * Builds and sends an wake up method command packet.
 */
static int
send_wakeup_method_cmd(u8 cmd, struct hci_uart *hu)
{
    int err = 0;
    struct sk_buff *skb = NULL;
    BT_CMD *pCmd;

    BT_DBG("hu %p cmd 0x%x", hu, cmd);

    /* allocate packet */
    skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
    if (!skb) {
        BT_ERR("cannot allocate memory for HCILL packet");
        err = -ENOMEM;
        goto out;
    }

    pCmd = (BT_CMD *) skb->tail;
    pCmd->ocf_ogf = (OGF << 10) | BT_CMD_WAKEUP_METHOD;
    pCmd->length = 4;
    pCmd->data[0] = BT_HOST_WAKEUP_METHOD_NONE;
    pCmd->data[1] = BT_HOST_WAKEUP_DEFAULT_GPIO;
    switch (cmd) {
    case WAKEUP_METHOD_DTR:
        pCmd->data[2] = BT_CTRL_WAKEUP_METHOD_DSR;
        break;
    case WAKEUP_METHOD_EXT_BREAK:
        pCmd->data[2] = BT_CTRL_WAKEUP_METHOD_EXT_BREAK;
        break;
    case WAKEUP_METHOD_RTS:
        pCmd->data[2] = BT_CTRL_WAKEUP_METHOD_RTS;
        break;
    case WAKEUP_METHOD_BREAK:
    default:
        pCmd->data[2] = BT_CTRL_WAKEUP_METHOD_BREAK;
        break;
    }
    pCmd->data[3] = BT_CTRL_WAKEUP_DEFAULT_GPIO;

    bt_cb(skb)->pkt_type = HCI_COMMAND_PKT;

    skb_put(skb, sizeof(BT_CMD) - 4 + pCmd->length);
    skb->dev = (void *) hu->hdev;

    /* send packet */
    hu->proto->enqueue(hu, skb);
    hci_uart_tx_wakeup(hu);

  out:
    return err;
}

/*
 * Builds and sends an char packet.
 */
static int
send_char(char ch, struct hci_uart *hu)
{
    int err = 0;
    struct sk_buff *skb = NULL;

    BT_DBG("hu %p char=%c 0x%x", hu, ch, ch);

    /* allocate packet */
    skb = bt_skb_alloc(1, GFP_ATOMIC);
    if (!skb) {
        BT_ERR("cannot allocate memory for HCILL packet");
        err = -ENOMEM;
        goto out;
    }
    bt_cb(skb)->pkt_type = ch;
    skb->dev = (void *) hu->hdev;

    /* send packet */
    if (hu->tx_skb)
        hu->proto->enqueue(hu, skb);
    else {
        memcpy(skb_push(skb, 1), &bt_cb(skb)->pkt_type, 1);
        hu->tx_skb = skb;
    }
    hci_uart_tx_wakeup(hu);

  out:
    return err;
}

/** This function handle the generic file close */
static void
proc_on_close(struct inode *inode, struct file *file)
{
    struct proc_data *pdata = file->private_data;
    char *line;
    struct hci_uart *hu = NULL;
    u32 ps_mode = g_data.ps_mode;
    u32 wakeup = g_data.cur_wakeupmode;
    if (!pdata->wrlen)
        return;
    line = pdata->wrbuf;
    while (line[0]) {
        if (!strncmp(line, "psmode", strlen("psmode"))) {
            line += strlen("psmode") + 1;
            ps_mode = (u32) string_to_number(line);
            if (ps_mode > PS_MODE_ENABLE)
                ps_mode = g_data.ps_mode;
        }
        if (!strncmp(line, "interval", strlen("interval"))) {
            line += strlen("interval") + 1;
            g_data.interval = (u32) string_to_number(line);
        }
        if (!strncmp(line, "drvdbg", strlen("drvdbg"))) {
            line += strlen("drvdbg") + 1;
            drvdbg = (u32) string_to_number(line);
        }
        if (!strncmp(line, "wakeupmode", strlen("wakeupmode"))) {
            line += strlen("wakeupmode") + 1;
            wakeup = (u32) string_to_number(line);
            if (wakeup > WAKEUP_METHOD_RTS)
                wakeup = g_data.cur_wakeupmode;
        }
        while (line[0] && line[0] != '\n')
            line++;
        if (line[0])
            line++;
    }
    if ((g_data.cur_psmode == PS_MODE_DISABLE) &&
        (ps_mode == PS_MODE_DISABLE) && (wakeup != g_data.cur_wakeupmode)) {
        g_data.wakeupmode = wakeup;
        if (g_data.tty) {
            hu = (void *) g_data.tty->disc_data;
            if (0 == is_device_ready(hu)) {
                g_data.send_cmd |= SEND_WAKEUP_METHOD_CMD;
                send_wakeup_method_cmd(g_data.wakeupmode, hu);
            }
        }
    }
    if (ps_mode != g_data.ps_mode)
        g_data.ps_mode = ps_mode;
    if (ps_mode != g_data.cur_psmode) {
        if (g_data.tty) {
            hu = (void *) g_data.tty->disc_data;
            if (0 == is_device_ready(hu)) {
                g_data.send_cmd |= SEND_AUTO_SLEEP_MODE_CMD;
                send_ps_cmd(g_data.ps_mode, hu);
            }
        }
    }
    return;
}

/** This function handle generic proc file close */
static int
proc_close(struct inode *inode, struct file *file)
{
    struct proc_data *pdata = file->private_data;
    if (pdata) {
        proc_on_close(inode, file);
        if (pdata->rdbuf)
            kfree(pdata->rdbuf);
        if (pdata->wrbuf)
            kfree(pdata->wrbuf);
        kfree(pdata);
    }
    return 0;
}

/** This function handle generic proc file read */
static ssize_t
proc_read(struct file *file, char __user * buffer, size_t len, loff_t * offset)
{
    loff_t pos = *offset;
    struct proc_data *pdata = (struct proc_data *) file->private_data;
    if ((!pdata->rdbuf) || (pos < 0))
        return -EINVAL;
    if (pos >= pdata->rdlen)
        return 0;
    if (len > pdata->rdlen - pos)
        len = pdata->rdlen - pos;
    if (copy_to_user(buffer, pdata->rdbuf + pos, len))
        return -EFAULT;
    *offset = pos + len;
    return len;
}

/** This function handle generic proc file write */
static ssize_t
proc_write(struct file *file,
           const char __user * buffer, size_t len, loff_t * offset)
{
    loff_t pos = *offset;
    struct proc_data *pdata = (struct proc_data *) file->private_data;

    if (!pdata->wrbuf || (pos < 0))
        return -EINVAL;
    if (pos >= pdata->maxwrlen)
        return 0;
    if (len > pdata->maxwrlen - pos)
        len = pdata->maxwrlen - pos;
    if (copy_from_user(pdata->wrbuf + pos, buffer, len))
        return -EFAULT;
    if (pos + len > pdata->wrlen)
        pdata->wrlen = len + file->f_pos;
    *offset = pos + len;
    return len;
}

/** This function handle the generic file open */
static int
proc_open(struct inode *inode, struct file *file)
{
    struct proc_data *pdata;
    char *p;
    if ((file->private_data =
         kzalloc(sizeof(struct proc_data), GFP_KERNEL)) == NULL) {
        BT_ERR("Can not allocate memmory for proc_data\n");
        return -ENOMEM;
    }
    pdata = (struct proc_data *) file->private_data;
    if ((pdata->rdbuf = kmalloc(DEFAULT_BUF_SIZE, GFP_KERNEL)) == NULL) {
        BT_ERR("Can not allocate memory for rdbuf\n");
        kfree(file->private_data);
        return -ENOMEM;
    }
    if ((pdata->wrbuf = kzalloc(DEFAULT_BUF_SIZE, GFP_KERNEL)) == NULL) {
        BT_ERR("Can not allocate memory for wrbuf\n");
        kfree(pdata->rdbuf);
        kfree(file->private_data);
        return -ENOMEM;
    }
    pdata->maxwrlen = DEFAULT_BUF_SIZE;
    p = pdata->rdbuf;
    p += sprintf(p, "psmode=%d\n", g_data.ps_mode);
    p += sprintf(p, "psstate=%d\n", g_data.ps_state);
    p += sprintf(p, "interval=%d\n", g_data.interval);
    p += sprintf(p, "wakeupmode=%d\n", g_data.wakeupmode);
    p += sprintf(p, "current psmode=%d\n", g_data.cur_psmode);
    p += sprintf(p, "current wakeupmode=%d\n", g_data.cur_wakeupmode);
    p += sprintf(p, "sendcmd=%d\n", g_data.send_cmd);
    p += sprintf(p, "drvdbg=%d\n", drvdbg);
    pdata->rdlen = strlen(pdata->rdbuf);
    return 0;
}

static struct file_operations proc_rw_ops = {
    .read = proc_read,
    .write = proc_write,
    .open = proc_open,
    .release = proc_close
};

void
ps_timeout_func(unsigned long context)
{
    struct ps_data *data = (struct ps_data *) context;
    struct tty_struct *tty = data->tty;
    struct hci_uart *hu = NULL;
    data->timer_on = 0;
    if (!data->tty)
        return;
    hu = (struct hci_uart *) tty->disc_data;
    if (!hu)
        return;
    if (test_bit(HCI_UART_SENDING, &hu->tx_state)) {
        ps_start_timer();
    } else {
        data->ps_cmd = PS_CMD_ENTER_PS;
        schedule_work(&data->work);
    }
}

static void
set_dtr(struct tty_struct *tty, int on_off)
{
#ifdef PXA9XX
    if (on_off) {
        gpio_set_value(mfp_to_gpio(MFP_PIN_GPIO13), 0);
        BT_DBG("Set DTR ON");
    } else {
        gpio_set_value(mfp_to_gpio(MFP_PIN_GPIO13), 1);
        BT_DBG("Clear DTR");
    }
#else
    u32 old_state = 0;
    u32 new_state = 0;
    if (TTY_FUNC->tiocmget) {
        old_state = TTY_FUNC->tiocmget(tty, NULL);
        if (on_off)
            new_state = old_state | TIOCM_DTR;
        else
            new_state = old_state & ~TIOCM_DTR;
        if (new_state == old_state)
            return;
        if (TTY_FUNC->tiocmset) {
            if (on_off) {
                BT_DBG("Set DTR ON");
                TTY_FUNC->tiocmset(tty, NULL, TIOCM_DTR, 0);
            } else {
                BT_DBG("Clear DTR ");
                TTY_FUNC->tiocmset(tty, NULL, 0, TIOCM_DTR);
            }
        }
    }
#endif
    return;
}

static void
set_break(struct tty_struct *tty, int on_off)
{
    if (TTY_FUNC->break_ctl) {
        if (on_off) {
            BT_DBG("Turn on break");
            TTY_FUNC->break_ctl(tty, -1);       /* turn on break */
        } else {
            BT_DBG("Turn off break");
            TTY_FUNC->break_ctl(tty, 0);        /* turn off break */
        }
    }
    return;
}

static int
get_cts(struct tty_struct *tty)
{
    u32 state = 0;
    if (TTY_FUNC->tiocmget) {
        state = TTY_FUNC->tiocmget(tty, NULL);
        if (state & TIOCM_CTS) {
            BT_DBG("CTS is low");
            return 1;           // CTS LOW 
        } else {
            BT_DBG("CTS is high");
            return 0;           // CTS HIGH
        }
    }
    return -1;
}

static void
set_rts(struct tty_struct *tty, int on_off)
{
    u32 old_state = 0;
    u32 new_state = 0;
    if (TTY_FUNC->tiocmget) {
        old_state = TTY_FUNC->tiocmget(tty, NULL);
        if (on_off)
            new_state = old_state | TIOCM_RTS;
        else
            new_state = old_state & ~TIOCM_RTS;
        if (new_state == old_state)
            return;
        if (TTY_FUNC->tiocmset) {
            if (on_off) {
                BT_DBG("Set RTS ON");   // set RTS high
                TTY_FUNC->tiocmset(tty, NULL, TIOCM_RTS, 0);
            } else {
                BT_DBG("Clear RTS ");   // set RTS LOW
                TTY_FUNC->tiocmset(tty, NULL, 0, TIOCM_RTS);
            }
        }
    }
    return;
}

static void
ps_control(struct ps_data *data, u8 ps_state)
{
    struct hci_uart *hu = NULL;
    if (data->ps_state == ps_state)
        return;
    if (data->tty) {
        switch (data->cur_wakeupmode) {
        case WAKEUP_METHOD_DTR:
            if (ps_state == PS_STATE_AWAKE)
                set_dtr(data->tty, 1);  // DTR ON
            else
                set_dtr(data->tty, 0);  // DTR OFF
            data->ps_state = ps_state;
            break;
        case WAKEUP_METHOD_BREAK:
            if (ps_state == PS_STATE_AWAKE)
                set_break(data->tty, 0);        // break OFF
            else
                set_break(data->tty, 1);        // break ON
            data->ps_state = ps_state;
            break;
        case WAKEUP_METHOD_EXT_BREAK:
            if (ps_state == PS_STATE_AWAKE) {
                set_break(data->tty, 1);        // break ON
                set_break(data->tty, 0);        // break OFF
                data->ps_state = ps_state;
            } else {
                hu = (struct hci_uart *) data->tty->disc_data;
                if (0 == is_device_ready(hu))
                    send_char(MRVL_ENTER_PS_CHAR, hu);
            }
            break;
        case WAKEUP_METHOD_RTS:
            if (ps_state == PS_STATE_AWAKE) {
                set_rts(data->tty, 0);  // RTS to high
                mdelay(5);
                set_rts(data->tty, 1);  // RTS to low
                data->ps_state = ps_state;
                hu = (struct hci_uart *) data->tty->disc_data;
                if (0 == is_device_ready(hu))
                    send_char(MRVL_EXIT_PS_CHAR, hu);
            } else {
                hu = (struct hci_uart *) data->tty->disc_data;
                if (0 == is_device_ready(hu))
                    send_char(MRVL_ENTER_PS_CHAR, hu);
            }
            break;
        default:
            break;
        }
        if (ps_state == PS_STATE_AWAKE) {
            hu = (struct hci_uart *) data->tty->disc_data;
            /* actually send the packets */
            BT_DBG("Send tx data");
            if (hu)
                hci_uart_tx_wakeup(hu);
        }
    }
}

static void
ps_work_func(struct work_struct *work)
{
    struct ps_data *data = container_of(work, struct ps_data, work);
    if (data->tty) {
        if ((data->ps_cmd == PS_CMD_ENTER_PS) &&
            (data->cur_psmode == PS_MODE_ENABLE)) {
            ps_control(data, PS_STATE_SLEEP);
        } else if (data->ps_cmd == PS_CMD_EXIT_PS) {
            ps_control(data, PS_STATE_AWAKE);
        }
    }
}

void
ps_init_work(void)
{
    memset(&g_data, 0, sizeof(g_data));
    g_data.interval = DEFAULT_TIME_PERIOD;
    g_data.timer_on = 0;
    g_data.tty = NULL;
    g_data.ps_state = PS_STATE_AWAKE;
    g_data.ps_mode = PS_MODE_ENABLE;
    g_data.ps_cmd = 0;
    g_data.send_cmd = 0;
    switch (wakeupmode) {
    case WAKEUP_METHOD_DTR:
        g_data.wakeupmode = WAKEUP_METHOD_DTR;
        break;
    case WAKEUP_METHOD_EXT_BREAK:
        g_data.wakeupmode = WAKEUP_METHOD_EXT_BREAK;
        break;
    case WAKEUP_METHOD_RTS:
        g_data.wakeupmode = WAKEUP_METHOD_RTS;
        break;
    case WAKEUP_METHOD_BREAK:
    default:
        g_data.wakeupmode = WAKEUP_METHOD_BREAK;
        break;
    }
    g_data.cur_psmode = PS_MODE_DISABLE;
    g_data.cur_wakeupmode = WAKEUP_METHOD_INVALID;
    INIT_WORK(&g_data.work, ps_work_func);
}

/** This function init proc entry  */
int
proc_init(void)
{
    u8 ret = 0;
    struct proc_dir_entry *entry;
    if (!proc_bt) {
        proc_bt = proc_mkdir("mbt_uart", PROC_DIR);
        if (!proc_bt) {
            BT_ERR("Could not mkdir mbt_uart!\n");
            ret = -1;
            goto done;
        }
        entry =
            create_proc_entry("config", S_IFREG | DEFAULT_FILE_PERM, proc_bt);
        if (entry) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
            entry->owner = THIS_MODULE;
#endif
            entry->proc_fops = &proc_rw_ops;
        }
    }
    ps_init_work();
  done:
    return ret;
}

/** remove proc file */
void
proc_remove(void)
{
    if (proc_bt) {
        remove_proc_entry("config", proc_bt);
        remove_proc_entry("mbt_uart", PROC_DIR);
        proc_bt = NULL;
    }
    return;
}

void
ps_send_char_complete(u8 ch)
{
    BT_DBG("Send char %c done", ch);
    if (g_data.ps_mode == PS_MODE_ENABLE) {
        if (ch == MRVL_ENTER_PS_CHAR)
            g_data.ps_state = PS_STATE_SLEEP;
        else if (ch == MRVL_EXIT_PS_CHAR)
            g_data.ps_state = PS_STATE_AWAKE;
    }
}

void
ps_init_timer(struct tty_struct *tty)
{
    init_timer(&g_data.ps_timer);
    g_data.timer_on = 0;
    g_data.tty = tty;
    g_data.ps_timer.function = ps_timeout_func;
    g_data.ps_timer.data = (u32) & g_data;
    return;
}

void
ps_start_timer(void)
{
    if (g_data.cur_psmode == PS_MODE_ENABLE) {
        g_data.timer_on = 1;
        mod_timer(&g_data.ps_timer, jiffies + (g_data.interval * HZ) / 1000);
    }
}

void
ps_cancel_timer(void)
{
    flush_scheduled_work();
    if (g_data.timer_on)
        del_timer(&g_data.ps_timer);
    if ((g_data.cur_psmode == PS_MODE_ENABLE) &&
        (g_data.cur_wakeupmode == WAKEUP_METHOD_BREAK)) {
        // set_break off
        set_break(g_data.tty, 0);
    }
    g_data.tty = NULL;
    return;
}

int
ps_wakeup(void)
{
    if (g_data.ps_state == PS_STATE_AWAKE)
        return 0;
    g_data.ps_cmd = PS_CMD_EXIT_PS;
    schedule_work(&g_data.work);
    return 1;
}

void
ps_init(void)
{
    struct hci_uart *hu = NULL;
    int mode = 0;
    struct ktermios old_termios;
    BT_DBG("BT open");
    if (!g_data.tty)
        return;
    if (1 != get_cts(g_data.tty)) {
        /* firmware is sleeping */
        mode = g_data.cur_wakeupmode;
        if (mode == WAKEUP_METHOD_INVALID)
            mode = wakeupmode;
        switch (mode) {
        case WAKEUP_METHOD_BREAK:
            // set RTS
            set_rts(g_data.tty, 1);
            // break on
            set_break(g_data.tty, 1);
            // break off
            set_break(g_data.tty, 0);
            mdelay(5);
            break;
        case WAKEUP_METHOD_DTR:
            // set RTS
            set_rts(g_data.tty, 1);
            set_dtr(g_data.tty, 0);
            set_dtr(g_data.tty, 1);
            mdelay(5);
            break;
        default:
            break;
        }
        old_termios = *(g_data.tty->termios);
        g_data.tty->termios->c_cflag &= ~CRTSCTS;       /* Clear the flow
                                                           control */
        g_data.TTY_FUNC->set_termios(g_data.tty, &old_termios);
        old_termios = *(g_data.tty->termios);
        g_data.tty->termios->c_cflag |= CRTSCTS;        /* Enable the flow
                                                           control */
        g_data.TTY_FUNC->set_termios(g_data.tty, &old_termios);
    }

    g_data.send_cmd = 0;
    hu = (void *) g_data.tty->disc_data;
    if (0 == is_device_ready(hu)) {

        if (g_data.cur_wakeupmode != g_data.wakeupmode) {
            g_data.send_cmd |= SEND_WAKEUP_METHOD_CMD;
            send_wakeup_method_cmd(g_data.wakeupmode, hu);
        }
        if (g_data.cur_psmode != g_data.ps_mode) {
            g_data.send_cmd |= SEND_AUTO_SLEEP_MODE_CMD;
            send_ps_cmd(g_data.ps_mode, hu);
        }
    }
}

void
ps_check_event_packet(struct sk_buff *skb)
{
    struct hci_event_hdr *hdr = (void *) skb->data;
    struct hci_ev_cmd_complete *ev = NULL;
    u8 event = hdr->evt;
    u16 opcode;
    u8 status = 0;
    if (!g_data.send_cmd)
        return;
    if (event == HCI_EV_CMD_COMPLETE) {
        ev = (void *) (skb->data + sizeof(struct hci_event_hdr));
        opcode = __le16_to_cpu(ev->opcode);
        switch (opcode) {
        case HCI_OP_AUTO_SLEEP_MODE:
            status = *((u8 *) ev + sizeof(struct hci_ev_cmd_complete));
            if (!status)
                g_data.cur_psmode = g_data.ps_mode;
            else
                g_data.ps_mode = g_data.cur_psmode;
            g_data.send_cmd &= ~SEND_AUTO_SLEEP_MODE_CMD;
            if (g_data.cur_psmode == PS_MODE_ENABLE)
                ps_start_timer();
            else
                ps_wakeup();
            BT_DBG("status=%d,ps_mode=%d", status, g_data.cur_psmode);
            break;
        case HCI_OP_WAKEUP_METHOD:
            status = *((u8 *) ev + sizeof(struct hci_ev_cmd_complete));
            g_data.send_cmd &= ~SEND_WAKEUP_METHOD_CMD;
            if (!status)
                g_data.cur_wakeupmode = g_data.wakeupmode;
            else
                g_data.wakeupmode = g_data.cur_wakeupmode;
            BT_DBG("status=%d,wakeupmode=%d", status, g_data.cur_wakeupmode);
            break;
        default:
            break;
        }
    }
    return;
}

module_param(wakeupmode, int, WAKEUP_METHOD_BREAK);
