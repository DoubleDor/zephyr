/*
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT realtek_ameba_at

#include <logging/log.h>
LOG_MODULE_REGISTER(ameba, CONFIG_WIFI_LOG_LEVEL);

#include <kernel.h>
#include <ctype.h>
#include <errno.h>
#include <zephyr.h>
#include <device.h>
#include <init.h>
#include <stdlib.h>

#include <pm/pm.h>
#include <pm/device.h>

#include <drivers/gpio.h>
#include <drivers/uart.h>

#include <net/dns_resolve.h>
#include <net/net_if.h>
#include <net/net_ip.h>
#include <net/net_offload.h>
#include <net/wifi_mgmt.h>

#include "ameba.h"


/* pin settings */
enum modem_control_pins {
#if DT_INST_NODE_HAS_PROP(0, power_gpios)
	AMEBA_POWER,
#endif
#if DT_INST_NODE_HAS_PROP(0, reset_gpios)
	AMEBA_RESET,
#endif
	NUM_PINS,
};

static struct modem_pin modem_pins[] = {
#if DT_INST_NODE_HAS_PROP(0, power_gpios)
	MODEM_PIN(DT_INST_GPIO_LABEL(0, power_gpios),
		  DT_INST_GPIO_PIN(0, power_gpios),
		  DT_INST_GPIO_FLAGS(0, power_gpios) | GPIO_OUTPUT_INACTIVE),
#endif
#if DT_INST_NODE_HAS_PROP(0, reset_gpios)
	MODEM_PIN(DT_INST_GPIO_LABEL(0, reset_gpios),
		  DT_INST_GPIO_PIN(0, reset_gpios),
		  DT_INST_GPIO_FLAGS(0, reset_gpios) | GPIO_OUTPUT_INACTIVE),
#endif
};

NET_BUF_POOL_DEFINE(mdm_recv_pool, MDM_RECV_MAX_BUF, MDM_RECV_BUF_SIZE,
		    0, NULL);

/* RX thread structures */
K_KERNEL_STACK_DEFINE(ameba_rx_stack,
		      CONFIG_WIFI_AMEBA_AT_RX_STACK_SIZE);
struct k_thread ameba_rx_thread;

/* RX thread work queue */
K_KERNEL_STACK_DEFINE(ameba_workq_stack,
		      CONFIG_WIFI_AMEBA_AT_WORKQ_STACK_SIZE);

struct ameba_data ameba_driver_data;

static inline uint8_t ameba_mode_from_flags(struct ameba_data *data)
{
	uint8_t flags = data->flags;
	uint8_t mode = 0;

	if (flags & (STA_CONNECTED | STA_LOCK)) {
		mode |= AMEBA_MODE_STA;
	}

	if (flags & AP_ENABLED) {
		mode |= AMEBA_MODE_AP;
	}

	/*
	 * ESP AT 1.7 does not allow to disable radio, so enter STA mode
	 * instead.
	 */
	if (mode == AMEBA_MODE_NONE) {
		mode = AMEBA_MODE_STA;
	}

	return mode;
}

static char *str_unquote(char *str)
{
	char *end;

	if (str[0] != '"') {
		return str;
	}

	str++;

	end = strrchr(str, '"');
	if (end != NULL) {
		*end = 0;
	}

	return str;
}

static int ameba_mode_switch(struct ameba_data *data, uint8_t mode)
{
	char cmd[] = "ATPW=X";
	int err;

	cmd[sizeof(cmd) - 2] = ('0' + mode);
	LOG_DBG("Switch to mode %hhu", mode);

	err = ameba_cmd_send(data, NULL, 0, cmd, AMEBA_CMD_TIMEOUT);
	if (err) {
		LOG_WRN("Failed to switch to mode %d: %d", (int) mode, err);
	}

	return err;
}

static int ameba_mode_switch_if_needed(struct ameba_data *data)
{
	uint8_t new_mode = ameba_mode_from_flags(data);
	uint8_t old_mode = data->mode;
	int err;

	if (old_mode == new_mode) {
		return 0;
	}
	LOG_DBG("%d %d", old_mode, new_mode);

	data->mode = new_mode;

	err = ameba_mode_switch(data, new_mode);
	if (err) {
		return err;
	}

	return 0;
}

#if 0 //TODO: needed to handle edge case on wifi disconnected and switching to ap mode
static void ameba_mode_switch_submit_if_needed(struct ameba_data *data)
{
	if (data->mode != ameba_mode_from_flags(data)) {
		k_work_submit_to_queue(&data->workq, &data->mode_switch_work);
	}
}
#endif

static void ameba_mode_switch_work(struct k_work *work)
{
	struct ameba_data *data =
		CONTAINER_OF(work, struct ameba_data, mode_switch_work);

	(void)ameba_mode_switch_if_needed(data);
}

static inline int ameba_mode_flags_set(struct ameba_data *data, uint8_t flags)
{
	ameba_flags_set(data, flags);
	return ameba_mode_switch_if_needed(data);
}

static inline int ameba_mode_flags_clear(struct ameba_data *data, uint8_t flags)
{
	ameba_flags_clear(data, flags);
	return ameba_mode_switch_if_needed(data);
}

/*
 * Modem Response Command Handlers
 */

/* Handler: OK */
MODEM_CMD_DEFINE(on_cmd_ok)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data,
					    cmd_handler_data);

	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&dev->sem_response);

	return 0;
}

/* Handler: ERROR */
MODEM_CMD_DEFINE(on_cmd_error)
{
	int ret;
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data,
					    cmd_handler_data);
	LOG_ERR("cmd error %s", str_unquote(argv[0]));
	ret = strtol(argv[0], NULL, 10);
	ret *= -1;
	modem_cmd_handler_set_error(data,  ret);
	k_sem_give(&dev->sem_response);

	return 0;
}

/* RX thread */
static void ameba_rx(struct ameba_data *data)
{
	LOG_INF("AMEBA RX INIT DONE");
	while (true) {
		/* wait for incoming data */
		k_sem_take(&data->iface_data.rx_sem, K_FOREVER);

		data->mctx.cmd_handler.process(&data->mctx.cmd_handler,
					       &data->mctx.iface);

		/* give up time if we have a solid stream of data */
		k_yield();
	}
}


/* +CIPSTAMAC:"xx:xx:xx:xx:xx:xx" */
MODEM_CMD_DEFINE(on_cmd_wifi_info)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data,
					    cmd_handler_data);
	char *mac;

	mac = str_unquote(argv[5]);
	LOG_DBG("got parsed command: %s_%s_%s", str_unquote(argv[0]), str_unquote(argv[1]), str_unquote(argv[5]));
	LOG_DBG("first %s", mac);
	net_bytes_from_str(dev->mac_addr, sizeof(dev->mac_addr), mac);
	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&dev->sem_response);

	return 0;
}

/* AP : <num>,<ssid>,<chl>,<sec>,<rssi>,<bssid> */
MODEM_CMD_DEFINE(on_cmd_scan_ap)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data,
					    cmd_handler_data);
	struct wifi_scan_result res = { 0 };
	int i;

	/** ssid **/
	argv[1] = str_unquote(argv[1]);
	i = strlen(argv[1]);
	if (i > sizeof(res.ssid)) {
		i = sizeof(res.ssid);
	}
	memcpy(res.ssid, argv[1], i);
	res.ssid_length = i;

	/** channel **/
	res.channel = strtol(argv[2], NULL, 10);

	
	/** security **/
	argv[3] = str_unquote(argv[3]);
	if (strcmp("Open", argv[3]) == 0){
		res.security = WIFI_SECURITY_TYPE_NONE;
	} else {
		res.security = WIFI_SECURITY_TYPE_PSK;
	}

	/** rssi **/
	res.rssi = strtol(argv[4], NULL, 10);

	/** bssid **/
	argv[5] = str_unquote(argv[5]);
	res.mac_length = WIFI_MAC_ADDR_LEN;
	if (net_bytes_from_str(res.mac, sizeof(res.mac), argv[5]) < 0) {
		LOG_ERR("Invalid MAC address");
		res.mac_length = 0;
	}

	if (dev->scan_cb) {
		dev->scan_cb(dev->net_iface, 0, &res);
	}

	return 0;
}

MODEM_CMD_DEFINE(on_cmd_wifi_disconnected)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data,
		cmd_handler_data);

	if (!ameba_flags_are_set(dev, STA_CONNECTED)) {
		LOG_ERR("Invalid Disconnect State");
		return 0;
	}

	ameba_flags_clear(dev, STA_CONNECTED);
#if 0 //TODO: station mode not yet supported
	ameba_mode_switch_submit_if_needed(dev);
#endif
	net_if_ipv4_addr_rm(dev->net_iface, &dev->ip);
	wifi_mgmt_raise_disconnect_result_event(dev->net_iface, 0);

	return 0;
}



// Common response commands
static const struct modem_cmd response_cmds_common[] = {
	MODEM_CMD(AMEBA_CMD_OK("ATPW"), on_cmd_ok, 0U, ""),
	MODEM_CMD(AMEBA_CMD_OK("ATWD"), on_cmd_wifi_disconnected, 0U, ""),
};


/*
 * The 'ready' command is sent when device has booted and is ready to receive
 * commands. It is only expected after a reset of the device.
 */
MODEM_CMD_DEFINE(on_cmd_ready)
{
	struct ameba_data *dev = CONTAINER_OF(data, struct ameba_data,
					    cmd_handler_data);

	LOG_DBG("RXed CMD RDY");
	k_sem_give(&dev->sem_if_ready);

	if (net_if_is_up(dev->net_iface)) {
		net_if_down(dev->net_iface);
		LOG_ERR("Unexpected reset");
	}

	if (ameba_flags_are_set(dev, STA_CONNECTING)) {
		wifi_mgmt_raise_connect_result_event(dev->net_iface, -1);
	} else if (ameba_flags_are_set(dev, STA_CONNECTED)) {
		wifi_mgmt_raise_disconnect_result_event(dev->net_iface, 0);
	}

	dev->flags = 0;
	dev->mode = 0;

	net_if_ipv4_addr_rm(dev->net_iface, &dev->ip);
	k_work_submit_to_queue(&dev->workq, &dev->init_work);

	return 0;
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
			log_strdup(ipd_buf));
		return -EBADMSG;
	}
	if(end != ':')
	{
		return -EAGAIN;
	}

	*link_id = ipd_buf[link_id_offset] - '0';
	*data_len = strtol(&ipd_buf[data_len_offset], &endptr, 10);

	if (endptr == &ipd_buf[data_len_offset]){
		LOG_ERR("Invalid IPD len: %s", log_strdup(ipd_buf));
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
	int ret;
	err = cmd_recv_parse_hdr(data->rx_buf, len, &link_id, &data_offset, &data_len);
	if (err) {
		if (err == -EAGAIN) {
			return -EAGAIN;
		}
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

	if(ret == AMEBA_RECV_ERR_LOST)
	{
		k_work_submit_to_queue(&dev->workq, &dev->clean_work);
	}
	else
	{
		LOG_ERR("receive fail: %d", ret);
	}


	return 0;
}

static const struct modem_cmd unsol_cmds[] = {
	MODEM_CMD("AT COMMAND READY", on_cmd_ready, 0U, ""),
	MODEM_CMD(AMEBA_CMD_ERROR("ATPR"), on_cmd_recv_fail, 1U, ""),
	MODEM_CMD_DIRECT(AMEBA_CMD_OK("ATPR"), on_cmd_recv),
};

static void ameba_mgmt_scan_work(struct k_work *work)
{
	struct ameba_data *dev;
	int ret;
	static const struct modem_cmd cmds[] = {
		MODEM_CMD("AP :", on_cmd_scan_ap, 6U, ","),
		MODEM_CMD(AMEBA_CMD_OK("ATWS"), on_cmd_ok, 0U, ""),
	};

	dev = CONTAINER_OF(work, struct ameba_data, scan_work);
	LOG_DBG("Setting flags");
	ret = ameba_mode_flags_set(dev, STA_LOCK);
	if (ret < 0) {
		goto out;
	}
	LOG_DBG("Sending scan cmd");
	ret = ameba_cmd_send(dev,
			   cmds, ARRAY_SIZE(cmds),
			   "ATWS",
			   AMEBA_SCAN_TIMEOUT);
	ameba_mode_flags_clear(dev, STA_LOCK);

	if (ret < 0) {
		LOG_ERR("Failed to scan: ret %d", ret);
	}

out:
	dev->scan_cb(dev->net_iface, 0, NULL);
	dev->scan_cb = NULL;
}

static int ameba_mgmt_scan(const struct device *dev, scan_result_cb_t cb)
{
	struct ameba_data *data = dev->data;
	LOG_DBG("Calling ameba scan");

	if (data->scan_cb != NULL) {
		LOG_ERR("scan cb is null");
		return -EINPROGRESS;
	}

	if (!net_if_is_up(data->net_iface)) {
		LOG_ERR("net iface is down");
		return -EIO;
	}

	data->scan_cb = cb;

	k_work_submit_to_queue(&data->workq, &data->scan_work);

	return 0;
};


static void ameba_mgmt_connect_work(struct k_work *work)
{
	struct ameba_data *dev;
	int ret;
	static const struct modem_cmd cmds[] = {
		MODEM_CMD(AMEBA_CMD_OK("ATPN"), on_cmd_ok, 0U, ""),
		MODEM_CMD(AMEBA_CMD_ERROR("ATPN"), on_cmd_error, 1U, ""),
	};

	dev = CONTAINER_OF(work, struct ameba_data, connect_work);

	ret = ameba_mode_flags_set(dev, STA_LOCK);
	if (ret < 0) {
		goto out;
	}
	ret = ameba_cmd_send(dev, cmds, ARRAY_SIZE(cmds), dev->conn_cmd,
			   AMEBA_CONNECT_TIMEOUT);
	memset(dev->conn_cmd, 0, sizeof(dev->conn_cmd));
	if (ret < 0) {
		if (ameba_flags_are_set(dev, STA_CONNECTED)) {
			ameba_flags_clear(dev, STA_CONNECTED);
			wifi_mgmt_raise_disconnect_result_event(dev->net_iface,
								0);
		} else {
			wifi_mgmt_raise_connect_result_event(dev->net_iface,
							     ret);
		}
	} else if (!ameba_flags_are_set(dev, STA_CONNECTED)) {
		ameba_flags_set(dev, STA_CONNECTED);
		wifi_mgmt_raise_connect_result_event(dev->net_iface, 0);
	}
	ameba_mode_flags_clear(dev, STA_LOCK);
out:
	ameba_flags_clear(dev, STA_CONNECTING);
}

static int ameba_mgmt_connect(const struct device *dev,
			    struct wifi_connect_req_params *params)
{
	struct ameba_data *data = dev->data;
	int len;

	if (!net_if_is_up(data->net_iface)) {
		LOG_DBG("Net iface is down");
		return -EIO;
	}

	if (ameba_flags_are_set(data, STA_CONNECTED | STA_CONNECTING)) {
		return -EALREADY;
	}

	ameba_flags_set(data, STA_CONNECTING);

	len = snprintk(data->conn_cmd, sizeof(data->conn_cmd),
		       "ATPN=\"");
	memcpy(&data->conn_cmd[len], params->ssid, params->ssid_length);
	len += params->ssid_length;

	len += snprintk(&data->conn_cmd[len],
				sizeof(data->conn_cmd) - len, "\"");

	if (params->security == WIFI_SECURITY_TYPE_PSK) {
		len += snprintk(&data->conn_cmd[len], sizeof(data->conn_cmd) - len, ",\"");
		memcpy(&data->conn_cmd[len], params->psk, params->psk_length);
		len += params->psk_length;
		len += snprintk(&data->conn_cmd[len], sizeof(data->conn_cmd) - len, "\"");
	}


	k_work_submit_to_queue(&data->workq, &data->connect_work);

	return 0;
}

static int ameba_mgmt_disconnect(const struct device *dev)
{
	struct ameba_data *data = dev->data;
	int ret;
	ret = ameba_cmd_send(data, NULL, 0, "ATWD", K_NO_WAIT);
	if(ret)
		LOG_ERR("Disconnect Failed (%d)", ret);
	return ret;
}

static int ameba_mgmt_ap_enable(const struct device *dev,
			      struct wifi_connect_req_params *params)
{
	LOG_ERR("AP Mode Not Supported");
	return -1;
}

static int ameba_mgmt_ap_disable(const struct device *dev)
{
	LOG_ERR("AP Mode Not Supported");
	return -1;
}

static void ameba_init_work(struct k_work *work)
{
	struct ameba_data *dev;
	int ret;
	LOG_DBG("Initializaing Work");
	static const struct setup_cmd setup_cmds[] = {
		SETUP_CMD("AT", AMEBA_CMD_OK("AT"), on_cmd_ok, 0, ""),
#if !CONFIG_WIFI_LOG_LEVEL_DBG // TODO: Disabling wifi echo causes parsing to fail
		/* turn off echo */
		// SETUP_CMD("ATSE=0,0x0,0x0", AMEBA_CMD_OK("ATSE"), on_cmd_ok, 0, ""),
#endif
//TODO
#if DT_INST_NODE_HAS_PROP(0, target_speed)
	};
	static const struct setup_cmd setup_cmds_target_baudrate[] = {
		SETUP_CMD_NOHANDLE("AT"),
#endif
		/* Set to station mode */
		SETUP_CMD_NOHANDLE("ATPW=1"),
#if defined(CONFIG_WIFI_AMEBA_AT_IP_STATIC)
		/* enable Static IP Config */
		SETUP_CMD("ATPH=2,2", AMEBA_CMD_OK("ATPH"), on_cmd_ok, 0, ""),
		SETUP_CMD(AMEBA_CMD_ATPE(CONFIG_WIFI_AMEBA_AT_IP_ADDRESS,
						  CONFIG_WIFI_AMEBA_AT_IP_GATEWAY,
						  CONFIG_WIFI_AMEBA_AT_IP_MASK),
			AMEBA_CMD_OK("ATPE"), on_cmd_ok, 0, ""),
#else
		/* enable station, DHCP */
		SETUP_CMD("ATPH=2,1", AMEBA_CMD_OK("ATPH"), on_cmd_ok, 0, ""),
#endif
		// enable auto connect
		SETUP_CMD("ATPG=0", AMEBA_CMD_OK("ATPG"), on_cmd_ok, 0, ""),
		SETUP_CMD("ATPK=1", AMEBA_CMD_OK("ATPK"), on_cmd_ok, 0, ""),
		// query wifi info
		SETUP_CMD("ATW?", "ST", on_cmd_wifi_info, 6U, ","),
	};

	dev = CONTAINER_OF(work, struct ameba_data, init_work);
	LOG_DBG("modem_cmd_handler_setup_cmds");
	ret = modem_cmd_handler_setup_cmds(&dev->mctx.iface,
					   &dev->mctx.cmd_handler, setup_cmds,
					   ARRAY_SIZE(setup_cmds),
					   &dev->sem_response,
					   AMEBA_INIT_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Init failed %d", ret);
		return;
	}

#if DT_INST_NODE_HAS_PROP(0, target_speed)
	static const struct uart_config uart_config = {
		.baudrate = DT_INST_PROP(0, target_speed),
		.parity = UART_CFG_PARITY_NONE,
		.stop_bits = UART_CFG_STOP_BITS_1,
		.data_bits = UART_CFG_DATA_BITS_8,
		.flow_ctrl = DT_PROP(AMEBA_BUS, hw_flow_control) ?
			UART_CFG_FLOW_CTRL_RTS_CTS : UART_CFG_FLOW_CTRL_NONE,
	};

	ret = uart_configure(device_get_binding(DT_INST_BUS_LABEL(0)),
			     &uart_config);
	if (ret < 0) {
		LOG_ERR("Baudrate change failed %d", ret);
		return;
	}

	/* arbitrary sleep period to give ESP enough time to reconfigure */
	k_sleep(K_MSEC(100));

	ret = modem_cmd_handler_setup_cmds(&dev->mctx.iface,
				&dev->mctx.cmd_handler,
				setup_cmds_target_baudrate,
				ARRAY_SIZE(setup_cmds_target_baudrate),
				&dev->sem_response,
				AMEBA_INIT_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Init failed %d", ret);
		return;
	}
#endif

	net_if_set_link_addr(dev->net_iface, dev->mac_addr,
			     sizeof(dev->mac_addr), NET_LINK_ETHERNET);

	LOG_DBG("AMEBA Wi-Fi ready");

	net_if_up(dev->net_iface);
}

static void ameba_reset(struct ameba_data *dev)
{
	LOG_DBG("Reseting device");

	if (net_if_is_up(dev->net_iface)) {
		net_if_down(dev->net_iface);
	}

#if DT_INST_NODE_HAS_PROP(0, power_gpios)
	LOG_DBG("Toggling Power Ping");
	modem_pin_write(&dev->mctx, AMEBA_POWER, 0);
	k_sleep(K_MSEC(100));
	modem_pin_write(&dev->mctx, AMEBA_POWER, 1);
#elif DT_INST_NODE_HAS_PROP(0, reset_gpios)
	modem_pin_write(&dev->mctx, AMEBA_RESET, 1);
	k_sleep(K_MSEC(100));
	modem_pin_write(&dev->mctx, AMEBA_RESET, 0);
// #endif
#else
	int ret;
	int retries = 3;

	LOG_DBG("Calling Software Reset");
	while (retries--) {
		LOG_DBG("reset retry");
		ret = modem_cmd_send(&dev->mctx.iface, &dev->mctx.cmd_handler,
				     NULL, 0, "ATSR", &dev->sem_if_ready,
				     K_MSEC(CONFIG_WIFI_AMEBA_AT_RESET_TIMEOUT));
		if (ret == 0 || ret != -ETIMEDOUT) {
			break;
		}
	}

	if (ret < 0) {
		LOG_ERR("Failed to reset device: %d", ret);
		return;
	}
#endif
}

static void ameba_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct ameba_data *data = dev->data;

	net_if_flag_set(iface, NET_IF_NO_AUTO_START);
	data->net_iface = iface;
	ameba_offload_init(iface);
	ameba_reset(data);
	LOG_DBG("Done with iface init");
}

static const struct net_wifi_mgmt_offload ameba_api = {
	.iface_api.init = ameba_iface_init,
	.scan		= ameba_mgmt_scan,
	.connect	= ameba_mgmt_connect,
	.disconnect	= ameba_mgmt_disconnect,
	.ap_enable	= ameba_mgmt_ap_enable,
	.ap_disable	= ameba_mgmt_ap_disable,
};

static int ameba_init(const struct device *dev)
{
	struct ameba_data *data = dev->data;
	int ret = 0;

	k_sem_init(&data->sem_tx_ready, 0, 1);
	k_sem_init(&data->sem_response, 0, 1);
	k_sem_init(&data->sem_if_ready, 0, 1);

	k_work_init(&data->init_work, ameba_init_work);
	k_work_init(&data->scan_work, ameba_mgmt_scan_work);
	k_work_init(&data->connect_work, ameba_mgmt_connect_work);
	k_work_init(&data->mode_switch_work, ameba_mode_switch_work);
	k_work_init(&data->clean_work, ameba_socket_clean_work);

	k_mutex_init(&data->directed_lock);

	ameba_socket_init(data);

	/* initialize the work queue */
	k_work_queue_start(&data->workq, ameba_workq_stack,
			   K_KERNEL_STACK_SIZEOF(ameba_workq_stack),
			   K_PRIO_COOP(CONFIG_WIFI_AMEBA_AT_WORKQ_THREAD_PRIORITY),
			   NULL);
	k_thread_name_set(&data->workq.thread, "ameba_workq");

	/* cmd handler */
	data->cmd_handler_data.cmds[CMD_RESP] = response_cmds_common;
	data->cmd_handler_data.cmds_len[CMD_RESP] = ARRAY_SIZE(response_cmds_common);
	data->cmd_handler_data.cmds[CMD_UNSOL] = unsol_cmds;
	data->cmd_handler_data.cmds_len[CMD_UNSOL] = ARRAY_SIZE(unsol_cmds);
	data->cmd_handler_data.match_buf = &data->cmd_match_buf[0];
	data->cmd_handler_data.match_buf_len = sizeof(data->cmd_match_buf);
	data->cmd_handler_data.buf_pool = &mdm_recv_pool;
	data->cmd_handler_data.alloc_timeout = K_NO_WAIT;
	data->cmd_handler_data.eol = "\r\n";
	ret = modem_cmd_handler_init(&data->mctx.cmd_handler,
				       &data->cmd_handler_data);
	if (ret < 0) {
		goto error;
	}

	/* modem interface */
	data->uart = DEVICE_DT_GET(DT_INST_BUS(0));
	data->iface_data.hw_flow_control = DT_PROP(AMEBA_BUS, hw_flow_control);
	data->iface_data.rx_rb_buf = &data->iface_rb_buf[0];
	data->iface_data.rx_rb_buf_len = sizeof(data->iface_rb_buf);
	ret = modem_iface_uart_init(&data->mctx.iface, &data->iface_data, data->uart);
	if (ret < 0) {
		LOG_ERR("Ameba uart failed");
		goto error;
	}

	/* pin setup */
	data->mctx.pins = modem_pins;
	data->mctx.pins_len = ARRAY_SIZE(modem_pins);

	data->mctx.driver_data = data;

	ret = modem_context_register(&data->mctx);
	if (ret < 0) {
		LOG_ERR("Error registering modem context: %d", ret);
		goto error;
	}

	ameba_register_socket_offload(data);

	/* start RX thread */
	k_thread_create(&ameba_rx_thread, ameba_rx_stack,
			K_KERNEL_STACK_SIZEOF(ameba_rx_stack),
			(k_thread_entry_t)ameba_rx,
			data, NULL, NULL,
			K_PRIO_COOP(CONFIG_WIFI_AMEBA_AT_RX_THREAD_PRIORITY), 0,
			K_NO_WAIT);
	k_thread_name_set(&ameba_rx_thread, "ameba_rx");

	LOG_INF("Ameba wifi initialized");
error:
	return ret;
}

#ifdef CONFIG_PM_DEVICE
static int ameba_pm_turn_off(struct ameba_data *data )
{
	int ret;
	LOG_DBG("PM_DEVICE_ACTION_TURN_OFF");
	if(data->flags)
	{
		LOG_WRN("Shutdown on a bad state (0x%x)", data->flags);
	}
	ret = 0;
	while(!net_if_is_up(data->net_iface) && ret < 10)
	{
		k_sleep(K_SECONDS(1));
		ret++;
	}
	uart_irq_rx_disable(data->uart);
	uart_irq_tx_disable(data->uart);
	// uart doesn't have a shutdown mode only suspend
	ret = pm_device_action_run(data->uart, PM_DEVICE_ACTION_SUSPEND);
	if (ret)
	{
		LOG_ERR("Can't suspend device: %d", ret);
		return ret;
	}

#if DT_INST_NODE_HAS_PROP(0, power_gpios)
	// shutdown the power
	modem_pin_write(&data->mctx, AMEBA_POWER, 0);
#endif

	ret = net_if_down(data->net_iface);
	if(ret)
	{
		LOG_ERR("Failed to take down net interface");
		return ret;
	}

	return 0;
}
static int ameba_pm_turn_on(struct ameba_data *data )
{
	int ret = 0;
	LOG_DBG("PM_DEVICE_ACTION_TURN_ON");
	uart_irq_rx_enable(data->uart);
	ret = pm_device_action_run(data->uart, PM_DEVICE_ACTION_RESUME);
	if (ret)
	{
		LOG_ERR("Can't resume device: %d", ret);
		return ret;
	}

#if DT_INST_NODE_HAS_PROP(0, power_gpios)
	// shutdown the power
	modem_pin_write(&data->mctx, AMEBA_POWER, 1);
#endif

	return 0;
}

static int ameba_pm_action(const struct device *dev,
			       enum pm_device_action action)
{
	struct ameba_data *data = dev->data;
	int ret;

	switch (action) {
	case PM_DEVICE_ACTION_TURN_OFF:
		/* device must be uninitialized */

		ret = ameba_pm_turn_off(data);
		break;
	case PM_DEVICE_ACTION_TURN_ON:
		/* device must be uninitialized */
		ret = ameba_pm_turn_on(data);
		
		break;
	default:
		return -ENOTSUP;
	}

	return ret;
}
#endif /* CONFIG_PM_DEVICE */

PM_DEVICE_DT_INST_DEFINE(0, ameba_pm_action);

NET_DEVICE_DT_INST_OFFLOAD_DEFINE(0, ameba_init, PM_DEVICE_DT_INST_GET(0),
				  &ameba_driver_data, NULL,
				  CONFIG_WIFI_INIT_PRIORITY, &ameba_api,
				  AMEBA_MTU);
