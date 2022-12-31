/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_WIFI_AMEBA_AT_H_
#define ZEPHYR_INCLUDE_DRIVERS_WIFI_AMEBA_AT_H_

#include <kernel.h>
#include <net/net_context.h>
#include <net/net_if.h>
#include <net/net_ip.h>
#include <net/net_pkt.h>
#include <net/wifi_mgmt.h>
#include <net/socket.h>

#include "modem_context.h"
#include "modem_cmd_handler.h"
#include "modem_iface_uart.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Define the commands that differ between the AT versions */

#define _CWMODE "CWMODE"
#define _CWSAP  "CWSAP"
#define _CWJAP  "CWJAP"
#define _CIPSTA "CIPSTA"
#define _CIPSTAMAC "CIPSTAMAC"
#define _CIPRECVDATA "+CIPRECVDATA:"
#define _CIPRECVDATA_END ','

/*
 * Passive mode differs a bit between firmware versions and the macro
 * AMEBA_PROTO_PASSIVE is therefore used to determine what protocol operates in
 * passive mode. For AT version 1.7 passive mode only affects TCP but in AT
 * version 2.0 it affects both TCP and UDP.
 */
#if defined(CONFIG_WIFI_AMEBA_AT_PASSIVE_MODE)
#if defined(CONFIG_WIFI_AMEBA_AT_VERSION_1_7)
#define AMEBA_PROTO_PASSIVE(proto) (proto == IPPROTO_TCP)
#else
#define AMEBA_PROTO_PASSIVE(proto) \
	(proto == IPPROTO_TCP || proto == IPPROTO_UDP)
#endif /* CONFIG_WIFI_AMEBA_AT_VERSION_1_7 */
#else
#define AMEBA_PROTO_PASSIVE(proto) 0
#endif /* CONFIG_WIFI_AMEBA_AT_PASSIVE_MODE */

#define AMEBA_BUS DT_INST_BUS(0)

#if DT_PROP(AMEBA_BUS, hw_flow_control) == 1
#define _FLOW_CONTROL "3"
#else
#define _FLOW_CONTROL "0"
#endif

#if DT_INST_NODE_HAS_PROP(0, target_speed)
#define _UART_BAUD	DT_INST_PROP(0, target_speed)
#else
#define _UART_BAUD	DT_PROP(AMEBA_BUS, current_speed)
#endif

#define _UART_CUR \
	STRINGIFY(_UART_BAUD)",8,1,0,"_FLOW_CONTROL

#define CONN_CMD_MAX_LEN (sizeof("AT+"_CWJAP"=\"\",\"\"") + \
			  WIFI_SSID_MAX_LEN + WIFI_PSK_MAX_LEN)

#define AMEBA_MAX_SOCKETS	5

/* Maximum amount that can be sent with CIPSEND and read with CIPRECVDATA */
#define AMEBA_MTU		2048
#define CIPRECVDATA_MAX_LEN	AMEBA_MTU

#define INVALID_LINK_ID		255

#define MDM_RING_BUF_SIZE	CONFIG_WIFI_AMEBA_AT_MDM_RING_BUF_SIZE
#define MDM_RECV_MAX_BUF	CONFIG_WIFI_AMEBA_AT_MDM_RX_BUF_COUNT
#define MDM_RECV_BUF_SIZE	CONFIG_WIFI_AMEBA_AT_MDM_RX_BUF_SIZE

#define AMEBA_CMD_TIMEOUT		K_SECONDS(10)
#define AMEBA_SCAN_TIMEOUT	K_SECONDS(10)
#define AMEBA_CONNECT_TIMEOUT	K_SECONDS(20)
#define AMEBA_INIT_TIMEOUT	K_SECONDS(10)

#define AMEBA_MODE_NONE		0
#define AMEBA_MODE_STA		1
#define AMEBA_MODE_AP		2
#define AMEBA_MODE_STA_AP	3

#define AMEBA_RECV_ERR_LOST	7


#define AMEBA_DHCP_MODE_STATION		"1"
#define AMEBA_DHCP_MODE_SOFTAP		"0"

#define AMEBA_CMD_OK(cmd) \
			"[" cmd "]" " OK"

#define AMEBA_CMD_ERROR(cmd) \
			"[" cmd "]" " ERROR:"

#define AMEBA_CMD_ATPE(ip, gateway, mask) "ATPE="=\"" \
			  ip "\",\""  gateway  "\",\""  mask "\""


extern struct ameba_data ameba_driver_data;

enum ameba_socket_flags {
	AMEBA_SOCK_IN_USE     = BIT(1),
	AMEBA_SOCK_CONNECTING = BIT(2),
	AMEBA_SOCK_CONNECTED  = BIT(3),
	AMEBA_SOCK_CLOSE_PENDING = BIT(4),
	AMEBA_SOCK_WORKQ_STOPPED = BIT(5),
	AMEBA_SOCK_RX_OCCURRED = BIT(6),
	AMEBA_SOCK_WILL_CLEAN = BIT(7),
};

struct ameba_socket {
	/* internal */
	struct k_mutex lock;
	atomic_t refcount;

	uint8_t idx;
	uint8_t link_id;
	atomic_t flags;

	/* socket info */
	struct sockaddr dst;

	/* sem */
	union {
		/* handles blocking receive */
		struct k_sem sem_data_ready;

		/* notifies about reaching 0 refcount */
		struct k_sem sem_free;
	};

	/* work */
	struct k_work connect_work;
	struct k_work recv_work;
	struct k_work close_work;

	/* net context */
	struct net_context *context;
	net_context_connect_cb_t connect_cb;
	net_context_recv_cb_t recv_cb;

	/* callback data */
	void *conn_user_data;
	void *recv_user_data;
};

enum ameba_data_flag {
	STA_CONNECTING = BIT(1),
	STA_CONNECTED  = BIT(2),
	STA_LOCK       = BIT(3),
	AP_ENABLED     = BIT(4),
};

/* driver data */
struct ameba_data {
	struct net_if *net_iface;

	uint8_t flags;
	uint8_t mode;

	char conn_cmd[CONN_CMD_MAX_LEN];

	/* addresses  */
	struct in_addr ip;
	struct in_addr gw;
	struct in_addr nm;
	uint8_t mac_addr[6];

	
	struct zsock_addrinfo dns_addresses[CONFIG_WIFI_AMEBA_AT_DNS_RES_LEN];
	bool dns_addr_in_use[CONFIG_WIFI_AMEBA_AT_DNS_RES_LEN];
	char dns_ai_canonname[CONFIG_WIFI_AMEBA_AT_DNS_RES_LEN][CONFIG_WIFI_AMEBA_AT_DNS_STR_BUFFER];

	/* modem context */
	struct modem_context mctx;

	/* modem interface */
	struct modem_iface_uart_data iface_data;
	uint8_t iface_rb_buf[MDM_RING_BUF_SIZE];
	const struct device *uart;

	/* modem cmds */
	struct modem_cmd_handler_data cmd_handler_data;
	uint8_t cmd_match_buf[MDM_RECV_BUF_SIZE];

	/* socket data */
	struct ameba_socket sockets[AMEBA_MAX_SOCKETS];
	struct ameba_socket *directed_sock;
	struct k_mutex directed_lock;

	/* work */
	struct k_work_q workq;
	struct k_work init_work;
	struct k_work scan_work;
	struct k_work connect_work;
	struct k_work mode_switch_work;
	struct k_work clean_work;

	scan_result_cb_t scan_cb;

	/* semaphores */
	struct k_sem sem_tx_ready;
	struct k_sem sem_response;
	struct k_sem sem_if_ready;
};

int ameba_offload_init(struct net_if *iface);

struct ameba_socket *ameba_socket_get(struct ameba_data *data,
				  struct net_context *context);
int ameba_socket_put(struct ameba_socket *sock);
void ameba_socket_init(struct ameba_data *data);
void ameba_socket_close(struct ameba_socket *sock);
void ameba_socket_rx(struct ameba_socket *sock, struct net_buf *buf,
		   size_t offset, size_t len);
void ameba_socket_workq_stop_and_flush(struct ameba_socket *sock);
struct ameba_socket *ameba_socket_ref(struct ameba_socket *sock);
void ameba_socket_unref(struct ameba_socket *sock);

static inline void ameba_flags_to_string(struct ameba_socket *sock)
{
	atomic_val_t flags = atomic_get(&sock->flags);
	if(flags & AMEBA_SOCK_IN_USE)
		LOG_DBG("Socket %d: AMEBA_SOCK_IN_USE", sock->link_id);
	if(flags & AMEBA_SOCK_CONNECTING)
		LOG_DBG("Socket %d: AMEBA_SOCK_CONNECTING", sock->link_id);
	if(flags & AMEBA_SOCK_CONNECTED)
		LOG_DBG("Socket %d: AMEBA_SOCK_CONNECTED", sock->link_id);
	if(flags & AMEBA_SOCK_CLOSE_PENDING)
		LOG_DBG("Socket %d: AMEBA_SOCK_CLOSE_PENDING", sock->link_id);
	if(flags & AMEBA_SOCK_WORKQ_STOPPED)
		LOG_DBG("Socket %d: AMEBA_SOCK_WORKQ_STOPPED", sock->link_id);
	if(flags & AMEBA_SOCK_RX_OCCURRED)
		LOG_DBG("Socket %d: AMEBA_SOCK_RX_OCCURRED", sock->link_id);
	if(flags & AMEBA_SOCK_WILL_CLEAN)
		LOG_DBG("Socket %d: AMEBA_SOCK_WILL_CLEAN", sock->link_id);
}

static inline
struct ameba_socket *ameba_socket_ref_from_link_id(struct ameba_data *data,
					       uint8_t link_id)
{
	struct ameba_socket *sock = data->sockets;
	struct ameba_socket *sock_end = sock + ARRAY_SIZE(data->sockets);

	for (; sock < sock_end; sock++) {
		if (sock->link_id == link_id) {
			return ameba_socket_ref(sock);
		}
	}

	return NULL;
}

static inline atomic_val_t ameba_socket_flags_update(struct ameba_socket *sock,
						   atomic_val_t value,
						   atomic_val_t mask)
{
	atomic_val_t flags;
	do {
		flags = atomic_get(&sock->flags);
	} while (!atomic_cas(&sock->flags, flags, (flags & ~mask) | value));

	return flags;
}

static inline
atomic_val_t ameba_socket_flags_clear_and_set(struct ameba_socket *sock,
					    atomic_val_t clear_flags,
					    atomic_val_t set_flags)
{
	return ameba_socket_flags_update(sock, set_flags,
				       clear_flags | set_flags);
}

static inline atomic_val_t ameba_socket_flags_set(struct ameba_socket *sock,
						atomic_val_t flags)
{
	return atomic_or(&sock->flags, flags);
}

static inline bool ameba_socket_flags_test_and_clear(struct ameba_socket *sock,
						   atomic_val_t flags)
{
	return (atomic_and(&sock->flags, ~flags) & flags);
}

static inline bool ameba_socket_flags_test_and_set(struct ameba_socket *sock,
						 atomic_val_t flags)
{
	return (atomic_or(&sock->flags, flags) & flags);
}

static inline atomic_val_t ameba_socket_flags_clear(struct ameba_socket *sock,
						  atomic_val_t flags)
{
	return atomic_and(&sock->flags, ~flags);
}

static inline atomic_val_t ameba_socket_flags(struct ameba_socket *sock)
{
	return atomic_get(&sock->flags);
}

static inline struct ameba_data *ameba_socket_to_dev(struct ameba_socket *sock)
{
	return CONTAINER_OF(sock - sock->idx, struct ameba_data, sockets);
}

static inline void __ameba_socket_work_submit(struct ameba_socket *sock,
					    struct k_work *work)
{
	struct ameba_data *data = ameba_socket_to_dev(sock);

	k_work_submit_to_queue(&data->workq, work);
}

static inline int ameba_socket_work_submit(struct ameba_socket *sock,
					  struct k_work *work)
{
	int ret = -EBUSY;

	k_mutex_lock(&sock->lock, K_FOREVER);
	if (!(ameba_socket_flags(sock) & AMEBA_SOCK_WORKQ_STOPPED)) {
		__ameba_socket_work_submit(sock, work);
		ret = 0;
	}
	k_mutex_unlock(&sock->lock);

	return ret;
}

static inline int ameba_socket_queue_rx(struct ameba_socket *sock)
{
	int ret = -EBUSY;

	k_mutex_lock(&sock->lock, K_FOREVER);
	if (!(ameba_socket_flags(sock) & AMEBA_SOCK_WORKQ_STOPPED)) {
		__ameba_socket_work_submit(sock, &sock->recv_work);
		ret = 0;
	}
	k_mutex_unlock(&sock->lock);

	return ret;
}

static inline bool ameba_socket_connected(struct ameba_socket *sock)
{
	return (ameba_socket_flags(sock) & AMEBA_SOCK_CONNECTED) != 0;
}

static inline void ameba_flags_set(struct ameba_data *dev, uint8_t flags)
{
	dev->flags |= flags;
}

static inline void ameba_flags_clear(struct ameba_data *dev, uint8_t flags)
{
	dev->flags &= (~flags);
}

static inline bool ameba_flags_are_set(struct ameba_data *dev, uint8_t flags)
{
	return (dev->flags & flags) != 0;
}

static inline enum net_sock_type ameba_socket_type(struct ameba_socket *sock)
{
	return net_context_get_type(sock->context);
}

static inline enum net_ip_protocol ameba_socket_ip_proto(struct ameba_socket *sock)
{
	return net_context_get_ip_proto(sock->context);
}

static inline int ameba_cmd_send(struct ameba_data *data,
			       const struct modem_cmd *handlers,
			       size_t handlers_len, const char *buf,
			       k_timeout_t timeout)
{
	return modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
			      handlers, handlers_len, buf, &data->sem_response,
			      timeout);
}

void ameba_connect_work(struct k_work *work);
void ameba_close_work(struct k_work *work);
void ameba_recv_work(struct k_work *work);
void ameba_socket_clean_work(struct k_work *work);

void ameba_register_socket_offload(struct ameba_data *data);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_DRIVERS_WIFI_AMEBA_AT_AMEBA_H_ */
