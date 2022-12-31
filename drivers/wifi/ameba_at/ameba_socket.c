/*
 * SPDX-License-Identifier: Apache-2.0
 */


#include <logging/log.h>
LOG_MODULE_REGISTER(ameba_socket, CONFIG_WIFI_LOG_LEVEL);
#include "ameba.h"

#define RX_NET_PKT_ALLOC_TIMEOUT				\
	K_MSEC(CONFIG_WIFI_AMEBA_AT_RX_NET_PKT_ALLOC_TIMEOUT)

struct esp_workq_flush_data {
	struct k_work work;
	struct k_sem sem;
};

struct ameba_socket *ameba_socket_get(struct ameba_data *data,
				  struct net_context *context)
{
	struct ameba_socket *sock = data->sockets;
	struct ameba_socket *sock_end = sock + ARRAY_SIZE(data->sockets);

	for (; sock < sock_end; sock++) {
		if (!ameba_socket_flags_test_and_set(sock, AMEBA_SOCK_IN_USE)) {
			LOG_DBG("got socket");
			/* here we should configure all the stuff needed */
			sock->context = context;
			context->offload_context = sock;

			sock->connect_cb = NULL;
			sock->recv_cb = NULL;
			
			atomic_inc(&sock->refcount);
			return sock;
		}
	}

	return NULL;
}

int ameba_socket_put(struct ameba_socket *sock)
{
	atomic_clear(&sock->flags);

	return 0;
}

struct ameba_socket *ameba_socket_ref(struct ameba_socket *sock)
{
	atomic_val_t ref;

	do {
		ref = atomic_get(&sock->refcount);
		if (!ref) {
			return NULL;
		}
	} while (!atomic_cas(&sock->refcount, ref, ref + 1));

	return sock;
}

void ameba_socket_unref(struct ameba_socket *sock)
{
	atomic_val_t ref;
	do {
		ref = atomic_get(&sock->refcount);
		if (!ref) {
			return;
		}
	} while (!atomic_cas(&sock->refcount, ref, ref - 1));

	k_sem_give(&sock->sem_free);
}

void ameba_socket_init(struct ameba_data *data)
{
	struct ameba_socket *sock;
	int i;

	for (i = 0; i < ARRAY_SIZE(data->sockets); ++i) {
		sock = &data->sockets[i];
		sock->idx = i;
		sock->link_id = 0;
		atomic_clear(&sock->refcount);
		atomic_clear(&sock->flags);
		k_mutex_init(&sock->lock);
		k_sem_init(&sock->sem_data_ready, 0, 1);
		k_work_init(&sock->connect_work, ameba_connect_work);
		k_work_init(&sock->close_work, ameba_close_work);
		k_work_init(&sock->recv_work, ameba_recv_work);
		k_fifo_init(&sock->tx_fifo);
	}
}

static struct net_pkt *ameba_socket_prepare_pkt(struct ameba_socket *sock,
					      struct net_buf *src,
					      size_t offset, size_t len)
{
	struct ameba_data *data = ameba_socket_to_dev(sock);
	struct net_buf *frag;
	struct net_pkt *pkt;
	size_t to_copy;

	pkt = net_pkt_rx_alloc_with_buffer(data->net_iface, len, AF_UNSPEC,
					   0, RX_NET_PKT_ALLOC_TIMEOUT);
	if (!pkt) {
		return NULL;
	}

	frag = src;
	/* find the right fragment to start copying from */
	while (frag && offset >= frag->len) {
		offset -= frag->len;
		frag = frag->frags;
	}

	/* traverse the fragment chain until len bytes are copied */
	while (frag && len > 0) {
		to_copy = MIN(len, frag->len - offset);
		if (net_pkt_write(pkt, frag->data + offset, to_copy) != 0) {
			net_pkt_unref(pkt);
			return NULL;
		}
		/* to_copy is always <= len */
		len -= to_copy;
		frag = frag->frags;

		/* after the first iteration, this value will be 0 */
		offset = 0;
	}

	net_pkt_set_context(pkt, sock->context);
	net_pkt_cursor_init(pkt);

	return pkt;
}

void ameba_socket_rx(struct ameba_socket *sock, struct net_buf *buf,
		   size_t offset, size_t len)
{
	struct net_pkt *pkt;
	atomic_val_t flags;

	flags = ameba_socket_flags(sock);

	if(!(flags & AMEBA_SOCK_RX_OCCURRED))
		ameba_socket_flags_set(sock, AMEBA_SOCK_RX_OCCURRED);

	if (!(flags & AMEBA_SOCK_CONNECTED) ||
	    (flags & AMEBA_SOCK_CLOSE_PENDING)) {
		LOG_ERR("Received data on closed link %d", sock->link_id);
		return;
	}

	pkt = ameba_socket_prepare_pkt(sock, buf, offset, len);
	if (!pkt) {
		LOG_ERR("Failed to get net_pkt: len %zu", len);
		if (ameba_socket_type(sock) == SOCK_STREAM) {
			if (!ameba_socket_flags_test_and_set(sock,
						AMEBA_SOCK_CLOSE_PENDING)) {
				ameba_socket_work_submit(sock, &sock->close_work);
			}
		}
		return;
	}

	k_mutex_lock(&sock->lock, K_FOREVER);
	if (sock->recv_cb) {
		sock->recv_cb(sock->context, pkt, NULL, NULL,
			      0, sock->recv_user_data);
		k_sem_give(&sock->sem_data_ready);
	} else {
		/* Discard */
		net_pkt_unref(pkt);
	}
	k_mutex_unlock(&sock->lock);
}

MODEM_CMD_DEFINE(on_cmd_closed)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data,
			cmd_handler_data);
	struct ameba_socket *sock;
	atomic_val_t old_flags;


	sock = dev->directed_sock;
	if (!sock) {
		k_sem_give(&dev->sem_response);
		return 0;
	}

	old_flags = ameba_socket_flags_clear_and_set(sock,
				AMEBA_SOCK_CONNECTED, AMEBA_SOCK_CLOSE_PENDING);

	if (!(old_flags & AMEBA_SOCK_CONNECTED)) {
		goto complete_response;
	}

	if (!(old_flags & AMEBA_SOCK_CLOSE_PENDING)) {
		ameba_socket_work_submit(sock, &sock->close_work);
	}

complete_response:
	k_sem_give(&dev->sem_response);
	return 0;
}

void ameba_socket_close(struct ameba_socket *sock)
{
	struct ameba_data *dev = ameba_socket_to_dev(sock);
	char cmd_buf[sizeof("ATPD=0")];
	static const struct modem_cmd cmds[] = {
		MODEM_CMD(AMEBA_CMD_OK("ATPD"), on_cmd_closed, 0U, ""),
		MODEM_CMD(AMEBA_CMD_ERROR("ATPD"), on_cmd_closed, 0U, ""), 
	};
	int ret;

	k_mutex_lock(&dev->directed_lock, K_FOREVER);
	dev->directed_sock = sock;

	if (sock->link_id == 0 || sock->link_id > AMEBA_MAX_SOCKETS)
	{
		LOG_ERR("Invalid link id %d", sock->link_id);
		return;
	}

	snprintk(cmd_buf, sizeof(cmd_buf), "ATPD=%d", sock->link_id);
	
	ret = ameba_cmd_send(dev, cmds, ARRAY_SIZE(cmds), cmd_buf, AMEBA_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Failed to close link %d, ret %d",
			sock->link_id, ret);
	}
	dev->directed_sock = NULL;
	k_mutex_unlock(&dev->directed_lock);
}

static void ameba_workq_flush_work(struct k_work *work)
{
	struct esp_workq_flush_data *flush =
		CONTAINER_OF(work, struct esp_workq_flush_data, work);

	k_sem_give(&flush->sem);
}

void ameba_socket_workq_stop_and_flush(struct ameba_socket *sock)
{
	struct esp_workq_flush_data flush;

	k_work_init(&flush.work, ameba_workq_flush_work);
	k_sem_init(&flush.sem, 0, 1);

	k_mutex_lock(&sock->lock, K_FOREVER);
	ameba_socket_flags_set(sock, AMEBA_SOCK_WORKQ_STOPPED);
	__ameba_socket_work_submit(sock, &flush.work);
	k_mutex_unlock(&sock->lock);

	k_sem_take(&flush.sem, K_FOREVER);
}
