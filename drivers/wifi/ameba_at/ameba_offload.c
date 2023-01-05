/*
 * Copyright (c) 2019 Tobias Svehagen
 * Copyright (c) 2020 Grinn
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ameba_offload, CONFIG_WIFI_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_offload.h>
#include <zephyr/net/socket_offload.h>

#include "ameba.h"

#define DNS_ADDR_RES "123.123.123."

static int ameba_bind(struct net_context *context, const struct sockaddr *addr,
			socklen_t addrlen)
{
	LOG_DBG("Calling ameba bind");
	if (IS_ENABLED(CONFIG_NET_IPV4) && addr->sa_family == AF_INET) {
		return 0;
	}
	LOG_ERR("Ameba config not supported");
	return -EAFNOSUPPORT;
}

static int ameba_listen(struct net_context *context, int backlog)
{
	LOG_DBG("");
	return -ENOTSUP;
}

MODEM_CMD_DEFINE(on_cmd_connect)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data, cmd_handler_data);
	uint8_t link_id;

	link_id = strtol(argv[0], NULL, 10);
	LOG_DBG("got connection id %d", link_id);
	
	dev->directed_sock->link_id = link_id;
	
	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&dev->sem_response);

	return 0;
}

static int _sock_connect(struct ameba_data *dev, struct ameba_socket *sock)
{
	static const struct modem_cmd cmds[] = {
		MODEM_CMD("[ATPC] con_id=", on_cmd_connect, 1U, "")
	};
	char connect_msg[sizeof("ATPC=0,\"\",65535") 
		+ MAX(NET_IPV4_ADDR_LEN, CONFIG_WIFI_AMEBA_AT_DNS_STR_BUFFER)
		+ 1];
	char addr_str[NET_IPV4_ADDR_LEN + 1];
	struct sockaddr dst;
	int ret;

	if (!ameba_flags_are_set(dev, STA_CONNECTED)) {
		LOG_ERR("AMEBA not connected");
		return -ENETUNREACH;
	}

	k_mutex_lock(&sock->lock, K_FOREVER);
	dst = sock->dst;
	k_mutex_unlock(&sock->lock);

	net_addr_ntop(dst.sa_family,
		&net_sin(&dst)->sin_addr,
		addr_str, 
		sizeof(addr_str));

	if (ameba_socket_ip_proto(sock) == IPPROTO_TCP) {
		if(strncmp(addr_str, DNS_ADDR_RES, sizeof(DNS_ADDR_RES)-1) == 0)
		{
			int dns_idx =  atoi(&addr_str[sizeof(DNS_ADDR_RES)-1]);
			snprintk(connect_msg, 
				sizeof(connect_msg),
			 	"ATPC=0,\"%s\",%d",
				dev->dns_addresses[dns_idx].ai_canonname,
				ntohs(net_sin(&dst)->sin_port));

		}
		else
		{

			snprintk(connect_msg, 
				sizeof(connect_msg),
			 	"ATPC=0,%s,%d",
				addr_str,
				ntohs(net_sin(&dst)->sin_port));
		}
	} else {
		LOG_ERR("Only TCP is fully supported");
		return -1;
	}

	k_mutex_lock(&dev->directed_lock, K_FOREVER);
	dev->directed_sock = sock;

	ret = ameba_cmd_send(dev, cmds, ARRAY_SIZE(cmds), connect_msg, AMEBA_CMD_TIMEOUT);
	if (ret == 0 && dev->directed_sock->link_id > 0 && dev->directed_sock->link_id <= AMEBA_MAX_SOCKETS) {
		ameba_socket_flags_set(sock, AMEBA_SOCK_CONNECTED);
		if (ameba_socket_type(sock) == SOCK_STREAM) {
			net_context_set_state(sock->context,
						  NET_CONTEXT_CONNECTED);
		}
	} else if (ret == -ETIMEDOUT) {
		LOG_ERR("Connect timed out %s", connect_msg);
		/* FIXME:
		 * What if the connection finishes after we return from
		 * here? The caller might think that it can discard the
		 * socket. Set some flag to indicate that the link should
		 * be closed if it ever connects?
		 */
	} else {
		LOG_ERR("Invalid link id %d", dev->directed_sock->link_id);
	}
	dev->directed_sock = NULL;
	k_mutex_unlock(&dev->directed_lock);
	return ret;
}

void ameba_connect_work(struct k_work *work)
{
	struct ameba_socket *sock = CONTAINER_OF(work, struct ameba_socket,
						   connect_work);
	struct ameba_data *dev = ameba_socket_to_dev(sock);
	int ret;
	ret = _sock_connect(dev, sock);

	k_mutex_lock(&sock->lock, K_FOREVER);
	if (sock->connect_cb) {
		sock->connect_cb(sock->context, ret, sock->conn_user_data);
	}
	k_mutex_unlock(&sock->lock);
}

static int ameba_connect(struct net_context *context,
			   const struct sockaddr *addr,
			   socklen_t addrlen,
			   net_context_connect_cb_t cb,
			   int32_t timeout,
			   void *user_data)
{
	struct ameba_socket *sock;
	struct ameba_data *dev;
	int ret;

	sock = (struct ameba_socket *)context->offload_context;
	dev = ameba_socket_to_dev(sock);

	LOG_DBG("link %d, timeout %d", sock->link_id, timeout);

	if (!IS_ENABLED(CONFIG_NET_IPV4) || addr->sa_family != AF_INET) {
		LOG_ERR("CONFIG_NET_IPV4 not enabled");
		return -EAFNOSUPPORT;
	}

	if (ameba_socket_connected(sock)) {
		LOG_ERR("socket is already connected");
		return -EISCONN;
	}

	k_mutex_lock(&sock->lock, K_FOREVER);
	sock->dst = *addr;
	sock->connect_cb = cb;
	sock->conn_user_data = user_data;
	k_mutex_unlock(&sock->lock);

	if (timeout == 0) {
		ameba_socket_work_submit(sock, &sock->connect_work);
		return 0;
	}

	ret = _sock_connect(dev, sock);

	if (ret != -ETIMEDOUT && cb) {
		cb(context, ret, user_data);
	}

	return ret;
}

static int ameba_accept(struct net_context *context,
				 net_tcp_accept_cb_t cb, int32_t timeout,
				 void *user_data)
{
	return -ENOTSUP;
}

MODEM_CMD_DEFINE(on_cmd_send_ok)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data,
						cmd_handler_data);

	LOG_DBG("Send is ok: %d", argc);
	for(int i = 0; i < argc; i++)
		LOG_DBG("%s", argv[i]);
	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&dev->sem_response);

	return 0;
}

MODEM_CMD_DEFINE(on_cmd_send_fail)
{
	int ret;
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data,
						cmd_handler_data);

	LOG_ERR("send fail");
	ret = strtol(argv[0], NULL, 10);
	ret *= -1;
	modem_cmd_handler_set_error(data,  ret);
	k_sem_give(&dev->sem_response);

	return 0;
}

static int _sock_send(struct ameba_socket *sock, struct net_pkt *pkt)
{
	struct ameba_data *dev = ameba_socket_to_dev(sock);
	char cmd_buf[sizeof("ATPT=,0,,:") +
			 sizeof(STRINGIFY(AMEBA_MTU)) - 1 +
			 NET_IPV4_ADDR_LEN 
			 + sizeof("65535") - 1];
	int ret, write_len, pkt_len;
	struct net_buf *frag;
	static const struct modem_cmd cmds[] = {
		MODEM_CMD("[ATPT] OK,", on_cmd_send_ok, 1U, ""),
		MODEM_CMD(AMEBA_CMD_ERROR("ATPT"), on_cmd_send_fail, 1U, ""),
	};

	if (!ameba_flags_are_set(dev, STA_CONNECTED)) {
		return -ENETUNREACH;
	}

	pkt_len = net_pkt_get_len(pkt);

	LOG_DBG("link %d, len %d", sock->link_id, pkt_len);

	if (ameba_socket_ip_proto(sock) == IPPROTO_TCP) {
		snprintk(cmd_buf, sizeof(cmd_buf), "ATPT=%d,%d:",pkt_len, sock->link_id);
	} else {
		LOG_ERR("UDP NOT SUPPORTED");
		return -EOPNOTSUPP;
	}

	k_sem_take(&dev->cmd_handler_data.sem_tx_lock, K_FOREVER);
	k_sem_reset(&dev->sem_response);

	ret = modem_cmd_handler_update_cmds(&dev->cmd_handler_data,
					    cmds,
					    ARRAY_SIZE(cmds),
					    true);
	if (ret < 0) {
		goto out;
	}

	dev->mctx.iface.write(&dev->mctx.iface, cmd_buf, strlen(cmd_buf));

	frag = pkt->frags;
	while (frag && pkt_len) {
		write_len = MIN(pkt_len, frag->len);
		dev->mctx.iface.write(&dev->mctx.iface, frag->data, write_len);
		pkt_len -= write_len;
		frag = frag->frags;
	}

	LOG_DBG("waiting for response");
	ret = k_sem_take(&dev->sem_response, AMEBA_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("No send response");
		goto out;
	}

	ret = modem_cmd_handler_get_error(&dev->cmd_handler_data);
	if (ret != 0) {
		LOG_ERR("Failed to send data");
	}
	LOG_DBG("Getting error %d", ret);

out:
	(void)modem_cmd_handler_update_cmds(&dev->cmd_handler_data,
						NULL, 0U, false);
	k_sem_give(&dev->cmd_handler_data.sem_tx_lock);
	
	// Queue RX if no issues with send
	if(!ret)
		ameba_socket_queue_rx(sock);

	LOG_DBG("Returning with val %d", ret);
	return ret;
}

/**
 * [ATPR] OK,<data size>,<con_id>[,<dst_ip>,<dst_port>]:<data>
 */

#define MIN_RECV_LEN (sizeof("[ATPR] OK,X,X:") - 1)
#define MAX_RECV_LEN (sizeof("[ATPR] OK,65535,X,XXX.XXX.XXX.XXX,65535:") - 1)

static int cmd_recv_parse_hdr(struct net_buf *buf, uint16_t len,
			     uint8_t *link_id,
			     int *data_offset, int *data_len)
{
	char *endptr, ipd_buf[MAX_RECV_LEN + 1];
	size_t frags_len;
	size_t match_len;
	int data_len_offset = 0;
	int link_id_offset = 0;
	char end = 0;

	frags_len = net_buf_frags_len(buf);

	/* Wait until minimum cmd length is available */
	if (frags_len < MIN_RECV_LEN) {
		return -EAGAIN;
	}
	match_len = net_buf_linearize(ipd_buf, MAX_RECV_LEN,
				      buf, 0, MAX_RECV_LEN);

	*data_offset = MAX_RECV_LEN;
	for(size_t i = 0; i < match_len; i++)
	{
		if(ipd_buf[i] == ':')
		{
			end = ipd_buf[i];
			*data_offset = i+1;
			break;
		}
		else if(ipd_buf[i] == ',')
		{
			if(data_len_offset == 0)
				data_len_offset = i+1;
			else if(link_id_offset == 0)
				link_id_offset = i+1;
		}
	}
	if(*data_offset == MAX_RECV_LEN 
		&& end != ':' 
		&& match_len == MAX_RECV_LEN)
	{
		LOG_ERR("Header Parse Fail %d,%d : %s", 
			*data_offset, 
			match_len, 
			ipd_buf);
		return -EBADMSG;
	}
	if(end != ':')
	{
		return -EAGAIN;
	}

	*link_id = ipd_buf[link_id_offset] - '0';
	*data_len = strtol(&ipd_buf[data_len_offset], &endptr, 10);

	if (endptr == &ipd_buf[data_len_offset]){
		LOG_ERR("Invalid IPD len: %s", ipd_buf);
		return -EBADMSG;
	}

	return 0;
}


MODEM_CMD_DIRECT_DEFINE(on_cmd_recv)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data,
						cmd_handler_data);
	struct ameba_socket *sock;
	int data_offset, data_len;
	uint8_t link_id;
	int err;
	int ret = len;
	err = cmd_recv_parse_hdr(data->rx_buf, len, &link_id, &data_offset, &data_len);
	if (err) {
		if (err == -EAGAIN) {
			return -EAGAIN;
		}
		return len;
	}

	if(data_len == 0)
	{
		modem_cmd_handler_set_error(data, 0);
		k_sem_give(&dev->sem_response);
		return len;
	}

	sock = ameba_socket_ref_from_link_id(dev, link_id);
	if (!sock) {
		LOG_ERR("No socket for link %d size: %d", link_id, data_len);
		return len;
	}

	if (data_offset + data_len > net_buf_frags_len(data->rx_buf)) {
		ret = -EAGAIN;
		// LOG_ERR("Trying again");
		goto socket_unref;
	}
	ameba_socket_rx(sock, data->rx_buf, data_offset, data_len);
	ret = data_offset + data_len;
	
	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&dev->sem_response);

socket_unref:
	ameba_socket_unref(sock);

	return ret;
}



MODEM_CMD_DEFINE(on_cmd_recv_fail)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data,
		cmd_handler_data);
	int ret;

	ret = strtol(argv[0], NULL, 10);
	modem_cmd_handler_set_error(data, ret);
	k_sem_give(&dev->sem_response);

	return 0;
}

void ameba_recv_work(struct k_work *work)
{
	struct ameba_socket *sock = CONTAINER_OF(work, struct ameba_socket,
						   recv_work);
	struct ameba_data *data = ameba_socket_to_dev(sock);
	int rx_count = 0;
	atomic_val_t flags;

	LOG_DBG("RX Started");
	static const struct modem_cmd cmds[] = {
		MODEM_CMD(AMEBA_CMD_ERROR("ATPR"), on_cmd_recv_fail, 1U, ""),
		MODEM_CMD_DIRECT(AMEBA_CMD_OK("ATPR"), on_cmd_recv),
	};
	int ret;

	char cmd_buf[sizeof("ATPR=X,XXXX")];
	snprintk(cmd_buf, sizeof(cmd_buf),
		"ATPR=%d,1500", sock->link_id);

	do {
		k_sleep(K_MSEC(50));
		ret = ameba_cmd_send(data,
			   cmds, ARRAY_SIZE(cmds),
			   cmd_buf,
			   AMEBA_CMD_TIMEOUT);
		rx_count++;
		flags = ameba_socket_flags(sock);
	}while (ret == 0 && rx_count < 50 && (flags & AMEBA_SOCK_CONNECTED));

	k_work_submit_to_queue(&data->workq, &data->clean_work);
	LOG_DBG("RX Done");

}


static int ameba_sendto(struct net_pkt *pkt,
			  const struct sockaddr *dst_addr,
			  socklen_t addrlen,
			  net_context_send_cb_t cb,
			  int32_t timeout,
			  void *user_data)
{
	struct net_context *context;
	struct ameba_socket *sock;
	struct ameba_data *dev;
	int ret = 0;
	atomic_val_t flags;

	context = pkt->context;
	sock = (struct ameba_socket *)context->offload_context;
	dev = ameba_socket_to_dev(sock);

	if (!ameba_flags_are_set(dev, STA_CONNECTED)) {
		LOG_ERR("Station not connected");
		return -ENETUNREACH;
	}
	flags = ameba_socket_flags(sock);
	if (ameba_socket_type(sock) != SOCK_STREAM) {
		
		LOG_ERR("Socket is not set to streaming");
		ret = -ENOTSUP;
		goto pkt_unref;
	} else if (!(flags & AMEBA_SOCK_CONNECTED) ||
			(flags & AMEBA_SOCK_CLOSE_PENDING)) {
		LOG_ERR("Socket not connected");
		ret = -ENOTCONN;
		goto pkt_unref;
	}

	ret = _sock_send(sock, pkt);
	if (ret < 0) {
		LOG_ERR("Failed to send data: link %d, ret %d",
			sock->link_id, ret);
		/*
		 * If this is stream data, then we should stop pushing anything
		 * more to this socket, as there will be a hole in the data
		 * stream, which application layer is not expecting.
		 */
		if (!ameba_socket_flags_test_and_set(sock,
					AMEBA_SOCK_CLOSE_PENDING)) {
			ameba_socket_work_submit(sock, &sock->close_work);
		}
	} else if (context->send_cb) {
		context->send_cb(context, ret, context->user_data);
	}

pkt_unref:
	net_pkt_unref(pkt);
	return ret;
}

static int ameba_send(struct net_pkt *pkt,
			net_context_send_cb_t cb,
			int32_t timeout,
			void *user_data)
{
	return ameba_sendto(pkt, NULL, 0, cb, timeout, user_data);
}

void ameba_close_work(struct k_work *work)
{
	struct ameba_socket *sock = CONTAINER_OF(work, struct ameba_socket,
						   close_work);
	atomic_val_t old_flags;
	LOG_DBG("Closing Socket");

	old_flags = ameba_socket_flags_clear(sock,
				(AMEBA_SOCK_CONNECTED | AMEBA_SOCK_CLOSE_PENDING));

	if ((old_flags & AMEBA_SOCK_CONNECTED) &&
		(old_flags & AMEBA_SOCK_CLOSE_PENDING)) {
		ameba_socket_close(sock);
	}

	/* Should we notify that the socket has been closed? */
	if (old_flags & AMEBA_SOCK_CONNECTED) {
		k_mutex_lock(&sock->lock, K_FOREVER);
		if (sock->recv_cb) {
			sock->recv_cb(sock->context, NULL, NULL, NULL, 0,
					  sock->recv_user_data);
			k_sem_give(&sock->sem_data_ready);
		}
		k_mutex_unlock(&sock->lock);
	}

	sock->link_id = 0;

	LOG_DBG("Done with ameba_close_work");
}

MODEM_CMD_DEFINE(on_cmd_link_id_connected)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data, cmd_handler_data);
	uint8_t link_id = strtol(argv[argc-1], NULL, 10);;
	struct ameba_socket *sock;
	
	sock = ameba_socket_ref_from_link_id(dev, link_id);
	if (!sock) {
		LOG_ERR("No socket for link %d", link_id);
		modem_cmd_handler_set_error(data, -ENXIO);
	}

	ameba_socket_flags_clear(sock, AMEBA_SOCK_WILL_CLEAN);
	ameba_socket_unref(sock);
	return 0;
}


MODEM_CMD_DEFINE(on_cmd_atpi)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data, cmd_handler_data);
	struct ameba_socket *sock = dev->sockets;
	struct ameba_socket *sock_end = sock + ARRAY_SIZE(dev->sockets);
	atomic_val_t flags;
	uint8_t i = 0;

	for (; sock < sock_end; sock++)
	{
		flags = ameba_socket_flags(sock);
		if(flags & AMEBA_SOCK_WILL_CLEAN)
		{
			ameba_socket_flags_clear(sock, AMEBA_SOCK_WILL_CLEAN);
			ameba_socket_work_submit(sock, &sock->close_work);
		}
		i++;
	}
	k_sem_give(&dev->sem_response);
	return 0;
}

void ameba_socket_clean_work(struct k_work *work)
{
	int ret;
	atomic_val_t flags;
	struct ameba_data *dev = CONTAINER_OF(work, struct ameba_data, clean_work);
	struct ameba_socket *sock = dev->sockets;
	struct ameba_socket *sock_end = sock + ARRAY_SIZE(dev->sockets);
	static const struct modem_cmd cmds[] = {
		MODEM_CMD(AMEBA_CMD_OK("ATPI"), on_cmd_atpi, 0U, ""),
		MODEM_CMD("con_id:", on_cmd_link_id_connected, 1U, ",")
	};

	for (; sock < sock_end; sock++) 
	{
		flags = ameba_socket_flags(sock);
		if(flags & AMEBA_SOCK_CONNECTED)
			ameba_socket_flags_set(sock, AMEBA_SOCK_WILL_CLEAN);
	}
	ret = ameba_cmd_send(dev, cmds, ARRAY_SIZE(cmds), "ATPI", AMEBA_CMD_TIMEOUT);
}

static int ameba_recv(struct net_context *context,
			net_context_recv_cb_t cb,
			int32_t timeout,
			void *user_data)
{
	struct ameba_socket *sock = context->offload_context;
	atomic_val_t flags;
	int ret;
	flags = ameba_socket_flags(sock);
	if(!(flags & AMEBA_SOCK_CONNECTED))
		return -ENOTCONN;

	if(timeout)
		LOG_WRN("ameba_rcv has to: %d", timeout);

	k_mutex_lock(&sock->lock, K_FOREVER);
	// HTTP bug fix: there's a case where http support needs rx to report end of file
	if(!(flags & AMEBA_SOCK_RX_OCCURRED) 
	  && !cb 
	  && sock->recv_cb)
	{
		LOG_WRN("RX HAS NOT OCCURRED");
		sock->recv_cb(sock->context, NULL, NULL, NULL, 0,
						sock->recv_user_data);
	}
	sock->recv_cb = cb;
	sock->recv_user_data = user_data;
	k_sem_reset(&sock->sem_data_ready);
	// TODO: there has never been a case where timeout was not 0
	k_mutex_unlock(&sock->lock);

	if (timeout == 0) {
		return 0;
	}
	ret = k_sem_take(&sock->sem_data_ready, K_MSEC(timeout));

	k_mutex_lock(&sock->lock, K_FOREVER);
	sock->recv_cb = NULL;
	sock->recv_user_data = NULL;
	k_mutex_unlock(&sock->lock);

	return 0;
}

static int ameba_put(struct net_context *context)
{
	struct ameba_socket *sock = context->offload_context;
	ameba_socket_workq_stop_and_flush(sock);

	ameba_flags_to_string(sock);
	if (ameba_socket_flags_test_and_clear(sock, AMEBA_SOCK_CONNECTED)) {
		ameba_socket_close(sock);
	}

	k_mutex_lock(&sock->lock, K_FOREVER);

	sock->connect_cb = NULL;
	sock->recv_cb = NULL;
	k_mutex_unlock(&sock->lock);

	k_sem_reset(&sock->sem_free);

	ameba_socket_unref(sock);

	LOG_DBG("acquiring sem_free %d", sock->link_id);
	/*
	 * Let's get notified when refcount reaches 0. Call to
	 * ameba_socket_unref() in this function might or might not be the last
	 * one. The reason is that there might be still some work in progress in
	 * ameba_rx thread (parsing unsolicited AT command), so we want to wait
	 * until it finishes.
	 */
	k_sem_take(&sock->sem_free, K_FOREVER);
	LOG_DBG("Done with sem_free");

	sock->context = NULL;

	ameba_socket_put(sock);
	return 0;
}

static int ameba_get(sa_family_t family,
		   enum net_sock_type type,
		   enum net_ip_protocol ip_proto,
		   struct net_context **context)
{
	struct ameba_socket *sock;
	struct ameba_data *dev;

	if (family != AF_INET) {
		LOG_ERR("family incorrect");
		return -EAFNOSUPPORT;
	}

	/* FIXME:
	 * iface has not yet been assigned to context so there is currently
	 * no way to know which interface to operate on. Therefore this driver
	 * only supports one device node.
	 */
	dev = &ameba_driver_data;
	LOG_DBG("ameba flags %x", dev->flags);
	if (!ameba_flags_are_set(dev, STA_CONNECTED)) {
		LOG_ERR("AMEBA not connected");
		return -ENETUNREACH;
	}

	LOG_DBG("calling ameba_socket_get");

	sock = ameba_socket_get(dev, *context);
	if (!sock) {
		LOG_ERR("No socket available!");
		return -ENOMEM;
	}
	LOG_DBG("success");

	return 0;
}

static struct net_offload ameba_offload = {
	.get	       = ameba_get,
	.bind	       = ameba_bind,
	.listen	       = ameba_listen,
	.connect       = ameba_connect,
	.accept	       = ameba_accept,
	.send	       = ameba_send,
	.sendto	       = ameba_sendto,
	.recv	       = ameba_recv,
	.put	       = ameba_put,
};




int ameba_offload_init(struct net_if *iface)
{
	iface->if_dev->offload = &ameba_offload;

	return 0;
}

struct ameba_data *ameba_dev;


static int offload_getaddrinfo(const char *node, const char *service,
	const struct zsock_addrinfo *hints,
	struct zsock_addrinfo **res)
{

	struct zsock_addrinfo *result = 0;
	char addr_str[NET_IPV4_ADDR_LEN + 1];
	for(size_t i = 0; i < ARRAY_SIZE(ameba_dev->dns_addresses); i++)
	{
		if(!ameba_dev->dns_addr_in_use[i])
		{
			ameba_dev->dns_addr_in_use[i] = true;
			result = &ameba_dev->dns_addresses[i];

			memset(result , 0, sizeof(struct zsock_addrinfo));
			result->ai_addr = &result->_ai_addr;
			result->ai_addrlen = sizeof(struct sockaddr_in);
			
			snprintk(addr_str, 
				sizeof(addr_str),
			 	"%s%d",
				DNS_ADDR_RES,
				i);
			inet_pton(AF_INET, addr_str, &net_sin(result->ai_addr)->sin_addr);

			net_sin(result->ai_addr )->sin_family = AF_INET;
			net_sin(result->ai_addr )->sin_port = htons(atoi(service));

			result->ai_family = AF_INET;
			result->ai_socktype = SOCK_STREAM;
			result->ai_protocol = IPPROTO_TCP;

			strncpy(ameba_dev->dns_ai_canonname[i], node, sizeof(ameba_dev->dns_ai_canonname[i]));
			result->ai_canonname = ameba_dev->dns_ai_canonname[i];
			*res = result;

			return 0;
		}
	}

	LOG_ERR("Ran out of DNS Space");
	return -ENOBUFS;

}

static void offload_freeaddrinfo(struct zsock_addrinfo *res)
{
	/* using static result from offload_getaddrinfo() -- no need to free */
	for(size_t i = 0; i < ARRAY_SIZE(ameba_dev->dns_addresses); i++)
	{
		if(res == &ameba_dev->dns_addresses[i])
		{
			ameba_dev->dns_addr_in_use[i] = false;
			return;
		}
	}
}

const struct socket_dns_offload ameba_socket_offload = {
	.getaddrinfo = offload_getaddrinfo,
	.freeaddrinfo = offload_freeaddrinfo,
};

void ameba_register_socket_offload(struct ameba_data *data)
{
	ameba_dev = data;
	socket_offload_dns_register(&ameba_socket_offload);
}