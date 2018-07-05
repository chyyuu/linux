#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <uapi/asm-generic/errno-base.h>

#include <linux/lwip/lwip/sockets.h>
#include <linux/lwip/lwip/tcpip.h>

SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	printk(KERN_ERR "you called socket!\n");
	return lwip_socket(family, type, protocol);
}

/*
 *	Send a datagram down a socket.
 */

SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags)
{
	printk(KERN_ERR "you called send!\n");
	if (len > 4096) { // stupid hardcode
		printk(KERN_ERR "send: len too large for lwip port\n");
		return -ENOMEM;
	}
	void* kbuf = kmalloc(len, GFP_KERNEL);
	if (kbuf == NULL) {
		return -ENOMEM;
		printk(KERN_ERR "send: can't kmalloc kbuf\n");
	}
	if (copy_from_user(kbuf, buff, len)) {
		printk(KERN_ERR "send: can't copy from user\n");
		goto bad;
	}
	printk(KERN_ERR "send: delegate to lwip_send\n");
	int ret = lwip_send(fd, kbuf, len, flags);

	kfree(kbuf);
	return ret;

bad:
	kfree(kbuf);
	return -EFAULT;
}

SYSCALL_DEFINE4(recv, int, fd, void __user *, ubuf, size_t, size,
		unsigned int, flags)
{
	printk(KERN_ERR "you called recv!\n");
	if (size > 4096) { // stupid hardcode
		printk(KERN_ERR "recv: len too large for lwip port\n");
		return -ENOMEM;
	}
	void* kbuf = kmalloc(size, GFP_KERNEL);
	if (kbuf == NULL)
		return -ENOMEM;
	int ret = lwip_recv(fd, kbuf, size, flags);
	if (copy_to_user(ubuf, kbuf, size))
		goto bad;

	kfree(kbuf);
	return ret;
bad:
	kfree(kbuf);
	return -EFAULT;
}

SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
{
	printk(KERN_ERR "you called bind!\n");
	struct sockaddr kmyaddr;
	if (copy_from_user(&kmyaddr, umyaddr, addrlen))
		return -EFAULT;
	return lwip_bind(fd, &kmyaddr, addrlen);
}

SYSCALL_DEFINE2(listen, int, fd, int, backlog)
{
	printk(KERN_ERR "you called listen!\n");
	return lwip_listen(fd, backlog);
}

SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr,
		int __user *, upeer_addrlen) // why linux kernel using int here?
{
	printk(KERN_ERR "you called accept!\n");
	struct sockaddr kpeer_sockaddr;
	socklen_t kpeer_addrlen;
	int ret = lwip_accept(fd, &kpeer_sockaddr, &kpeer_addrlen);
	if (copy_to_user(upeer_sockaddr, &kpeer_sockaddr, kpeer_addrlen))
		return -EFAULT;
	if (copy_to_user(upeer_addrlen, &kpeer_addrlen, sizeof(int)))
		return -EFAULT;
	return ret;
}

SYSCALL_DEFINE1(lwip_closesock, int, fd)
{
	printk(KERN_ERR "you called closesock!\n");
	return lwip_close(fd);
}

SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
		int, addrlen)
{
	printk(KERN_ERR "you called connect!\n");
	struct sockaddr kvaddr;
	if (copy_from_user(&kvaddr, uservaddr, addrlen))
		return -EFAULT;
	return lwip_connect(fd, &kvaddr, addrlen);
}

static int __init lwip_initall(void)
{
	tcpip_init(NULL, NULL);
	printk(KERN_INFO "lwIP TCP/IP init done.\n");
	return 0;
}

subsys_initcall(lwip_initall);
