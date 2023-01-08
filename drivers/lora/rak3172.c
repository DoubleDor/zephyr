/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * WARNING: This driver is a WIP
 */
#define DT_DRV_COMPAT rak_rak3172
#include <logging/log.h>
LOG_MODULE_REGISTER(rak3172, CONFIG_LORA_LOG_LEVEL);

#include <pm/pm.h>
#include <pm/device.h>

#include <drivers/gpio.h>
#include <drivers/lora.h>
#include <drivers/uart.h>
#include <drivers/hwinfo.h>
#include <zephyr.h>
#include <lorawan_module.h>
#include <string.h>
#include "rak3172.h"

#include "modem_context.h"
#include "modem_cmd_handler.h"
#include "modem_iface_uart.h"

static const struct device *lora_uart_dev = DEVICE_DT_GET(DT_INST_BUS(0));

typedef struct
{
	struct k_mutex lock;
	/* modem context */
	struct modem_context mctx;

	/* modem interface */
	struct modem_iface_uart_data iface_data;
	uint8_t iface_rb_buf[CONFIG_RAK_MDM_RING_BUF_SIZE];

	/* modem cmds */
	struct modem_cmd_handler_data cmd_handler_data;
	uint8_t cmd_match_buf[CONFIG_RAK_MDM_RX_BUF_SIZE];

	struct k_sem sem_response;
	struct k_sem sem_tx;

	char dev_eui[CONFIG_RAK_DEV_EUI_LEN+1];
	char app_eui[CONFIG_RAK_APP_EUI_LEN+1];
	char app_key[CONFIG_RAK_APP_KEY_LEN+1];

	enum mlorawan_message_type msg_type;
}rak_data_t;

rak_data_t driver_data = {
	.msg_type = LORAWAN_MSG_UNCONFIRMED
};
/* RX thread structures */
K_KERNEL_STACK_DEFINE(modem_rx_stack, CONFIG_RAK_RX_STACK_SIZE);
struct k_thread modem_rx_thread;


NET_BUF_POOL_DEFINE(mdm_recv_pool, 
	CONFIG_RAK_MDM_RX_BUF_COUNT,
	CONFIG_RAK_MDM_RX_BUF_SIZE,
	0,
	NULL);

enum mdm_control_pins {
	MDM_RESET = 0,
#if DT_INST_NODE_HAS_PROP(0, mdm_power_gpios)
	MDM_POWER,
#endif

};

static struct modem_pin modem_pins[] = {
	/* MDM_RESET */
	MODEM_PIN(DT_INST_GPIO_LABEL(0, mdm_reset_gpios),
		  DT_INST_GPIO_PIN(0, mdm_reset_gpios),
		  DT_INST_GPIO_FLAGS(0, mdm_reset_gpios) | GPIO_OUTPUT),
#if DT_INST_NODE_HAS_PROP(0, mdm_power_gpios)
	MODEM_PIN(DT_INST_GPIO_LABEL(0, mdm_power_gpios),
		  DT_INST_GPIO_PIN(0, mdm_power_gpios),
		  DT_INST_GPIO_FLAGS(0, mdm_power_gpios) | GPIO_OUTPUT)
#endif
};

static int rak3172_lora_config(const struct device *dev,
	struct lora_modem_config *config)
{
	LOG_DBG("Lora Config:");
	LOG_DBG("Freq: %d", config->frequency);
	switch(config->bandwidth)
	{
		case BW_125_KHZ:
		LOG_DBG("BW_125_KHZ");
		break;
		case BW_250_KHZ:
		LOG_DBG("BW_250_KHZ");
		break;
		case BW_500_KHZ:
		LOG_DBG("BW_500_KHZ");
		break;
	}
	LOG_DBG("Data Rate: %d", config->datarate);
	switch(config->coding_rate)
	{
		case CR_4_5:
		LOG_DBG("CR_4_5");
		break;
		case CR_4_6:
		LOG_DBG("CR_4_6");
		break;
		case CR_4_7:
		LOG_DBG("CR_4_7");
		break;
		case CR_4_8:
		LOG_DBG("CR_4_8");
		break;
	}
	LOG_DBG("Preamble Len: %d", config->preamble_len);
	LOG_DBG("tx_power: %d", config->tx_power);
	LOG_DBG("tx: %d", config->tx);

	// ret = pm_device_action_run(lora_uart_dev, PM_DEVICE_ACTION_RESUME);
	// if (ret)
	// {
	// 	LOG_ERR("Can't resume device: %d", ret);
	// 	return ret;
	// }
	// modem_pin_write(&data->mctx, MDM_POWER, 0);
	// k_sleep(K_MSEC(1));
	// modem_pin_write(&data->mctx, MDM_POWER, 1);

	return 0;
}

static int rak3172_lora_send(const struct device *dev, uint8_t *data,
	uint32_t data_len)
{
	LOG_DBG("Send data with len %d", data_len);
	return 0;
}

int rak3172_lora_send_async(const struct device *dev, uint8_t *data,
	uint32_t data_len, struct k_poll_signal *async)
{
	LOG_DBG("IN: %s\n", __FUNCTION__);
	return 0;
}

static int rak3172_lora_recv(const struct device *dev, uint8_t *data, uint8_t size,
	k_timeout_t timeout, int16_t *rssi, int8_t *snr)
{
	LOG_DBG("IN: %s\n", __FUNCTION__);
	return 0;
}

static int rak3172_lora_recv_async(const struct device *dev, lora_recv_cb cb)
{
	LOG_DBG("IN: %s\n", __FUNCTION__);
	return 0;
}

static int rak3172_lora_test_cw(const struct device *dev, uint32_t frequency,
	int8_t tx_power,
	uint16_t duration)
{
	LOG_DBG("IN: %s\n", __FUNCTION__);
	return 0;
}

static const struct lora_driver_api rak3172_lora_api = {
	.config = rak3172_lora_config,
	.send = rak3172_lora_send,
	.send_async = rak3172_lora_send_async,
	.recv = rak3172_lora_recv,
	.recv_async = rak3172_lora_recv_async,
	.test_cw = rak3172_lora_test_cw,
};

static void lora_uart_enable()
{
	int ret = pm_device_action_run(lora_uart_dev, PM_DEVICE_ACTION_RESUME);
	if (ret)
	{
		LOG_ERR("Failed to resume lora uart: %d", ret);
	}
}

static void lora_uart_disable()
{
	int ret = pm_device_action_run(lora_uart_dev, PM_DEVICE_ACTION_SUSPEND);
	if (ret)
	{
		LOG_ERR("Failed to suspend lora uart: %d", ret);
	}
}

static void lora_rx(rak_data_t *data)
{
	while (true) {
		/* wait for incoming data */
		k_sem_take(&data->iface_data.rx_sem, K_FOREVER);

		data->mctx.cmd_handler.process(&data->mctx.cmd_handler, 
			&data->mctx.iface);

		/* give up time if we have a solid stream of data */
		k_yield();
	}
}

MODEM_CMD_DEFINE(on_cmd_ready)
{
	rak_data_t *dev_data = CONTAINER_OF(data, rak_data_t, cmd_handler_data);
	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&dev_data->sem_response);
	return 0;
}


MODEM_CMD_DEFINE(on_cmd_ok)
{
	rak_data_t *dev_data = CONTAINER_OF(data, rak_data_t,
		cmd_handler_data);

	k_sem_give(&dev_data->sem_response);

	// TODO: this is just a place holder for the driver for power saving
	// ret = pm_device_action_run(lora_uart_dev, PM_DEVICE_ACTION_SUSPEND);
	// if (ret)
	// {
	// 	LOG_ERR("Can't suspend device: %d", ret);
	// 	return ret;
	// }
	return 0;
}
MODEM_CMD_DEFINE(on_cmd_app_eui)
{
	rak_data_t *dev_data = CONTAINER_OF(data, rak_data_t,
		cmd_handler_data);

	memset(dev_data->app_eui, 0, CONFIG_RAK_APP_EUI_LEN);
	if(strlen(argv[0]) <= CONFIG_RAK_APP_EUI_LEN)
		strcpy(dev_data->app_eui, argv[0]);
	return 0;
}

MODEM_CMD_DEFINE(on_cmd_dev_eui)
{
	rak_data_t *dev_data = CONTAINER_OF(data, rak_data_t,
		cmd_handler_data);

	memset(dev_data->dev_eui, 0, CONFIG_RAK_DEV_EUI_LEN);
	if(strlen(argv[0]) <= CONFIG_RAK_DEV_EUI_LEN)
		strcpy(dev_data->dev_eui, argv[0]);
	LOG_DBG("DEV EUI %s", dev_data->dev_eui);
	return 0;
}

MODEM_CMD_DEFINE(on_cmd_joined)
{
	rak_data_t *dev_data = CONTAINER_OF(data, rak_data_t,
		cmd_handler_data);

	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&dev_data->sem_tx);
	return 0;
}

MODEM_CMD_DEFINE(on_cmd_join_failed)
{
	rak_data_t *dev_data = CONTAINER_OF(data, rak_data_t,
		cmd_handler_data);

	modem_cmd_handler_set_error(data, -1);
	k_sem_give(&dev_data->sem_tx);

	return 0;
}

MODEM_CMD_DEFINE(on_cmd_true)
{
	modem_cmd_handler_set_error(data, 1);
	return 0;
}

MODEM_CMD_DEFINE(on_cmd_false)
{
	modem_cmd_handler_set_error(data, 0);
	return 0;
}

MODEM_CMD_DEFINE(on_cmd_conf_query)
{
	rak_data_t *dev_data = CONTAINER_OF(data, rak_data_t,
		cmd_handler_data);
	if(strcmp("1", argv[0]) == 0) {
		dev_data->msg_type = LORAWAN_MSG_CONFIRMED;
	} else
	{
		dev_data->msg_type = LORAWAN_MSG_UNCONFIRMED;
	}
	return 0;
}

MODEM_CMD_DEFINE(on_cmd_send_confirmation)
{
	rak_data_t *dev_data = CONTAINER_OF(data, rak_data_t,
		cmd_handler_data);
	if(strcmp("OK", argv[0]) == 0)
		modem_cmd_handler_set_error(data, 0);
	else if(strcmp("FAILED", argv[0]) == 0)
		modem_cmd_handler_set_error(data, -1);
	else
		modem_cmd_handler_set_error(data, -2);

	k_sem_give(&dev_data->sem_tx);
	return 0;
}

MODEM_CMD_DEFINE(on_cmd_app_key)
{
	rak_data_t *dev_data = CONTAINER_OF(data, rak_data_t,
		cmd_handler_data);

	memset(dev_data->app_key, 0, CONFIG_RAK_APP_KEY_LEN);
	if(strlen(argv[0]) <= CONFIG_RAK_APP_KEY_LEN)
		strcpy(dev_data->app_key, argv[0]);
	LOG_DBG("App Key %s", dev_data->app_key);

	for(int i = 0; i < argc; i++)
		LOG_DBG("%d: %s", i, argv[i]);
	return 0;
}
static const struct modem_cmd response_cmds_common[] = {
	MODEM_CMD("OK", on_cmd_ok, 0U, ""), 
};

static const struct modem_cmd unsol_cmds[] = {
	MODEM_CMD("Current Work Mode: ", on_cmd_ready, 0U, "")
	
};

static int configure_hw_info(rak_data_t *data)
{
	int ret;
	char cmd[sizeof("AT+APPKEY=AC1F09FFFE0776C1AC1F09FFF9153172")];
	size_t hw_id_length;
	uint8_t hw_id[8];
	hw_id_length = hwinfo_get_device_id(hw_id, sizeof(hw_id));
	if (hw_id_length != 8)
	{
		LOG_ERR("HW ID expects size 8 got size %d", hw_id_length);
		return -1;
	}
	snprintk(cmd, sizeof(cmd), "AT+DEVEUI=%02x%02x%02x%02x%02x%02x%02x%02x",
		hw_id[7],
		hw_id[6],
		hw_id[5],
		hw_id[4],
		hw_id[3],
		hw_id[2],
		hw_id[1],
		hw_id[0]
	);

	ret = modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
		NULL, 0, cmd, &data->sem_response,
		MDM_CMD_TIMEOUT);

	if(ret)
		return ret;

	snprintk(cmd, sizeof(cmd), "AT+APPKEY=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		hw_id[7],
		hw_id[6],
		hw_id[5],
		hw_id[4],
		hw_id[3],
		hw_id[2],
		hw_id[1],
		hw_id[0],
		hw_id[7],
		hw_id[6],
		hw_id[5],
		hw_id[4],
		hw_id[3],
		hw_id[2],
		hw_id[1],
		hw_id[0]
	);
	ret = modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
		NULL, 0, cmd, &data->sem_response,
		MDM_CMD_TIMEOUT);

	if(ret)
		return ret;
	return 0;
}


static int rak_at_init(rak_data_t *data)
{
	static const struct setup_cmd setup_cmds[] = {
		SETUP_CMD_NOHANDLE("AT"),
#if CONFIG_LORA_LOG_LEVEL_DBG
		SETUP_CMD_NOHANDLE("ATE"),
#endif
		SETUP_CMD_NOHANDLE("AT+NWM=1"), // Network Mode Lora
		SETUP_CMD_NOHANDLE("AT+BAND=5"), // Lora Region US
//TODO: 
		SETUP_CMD_NOHANDLE("AT+NJM=1"), // NWJM OTAA
		SETUP_CMD_NOHANDLE("AT+CLASS=A"), // Dev Class A
		SETUP_CMD_NOHANDLE("AT+TXP=?"),
		SETUP_CMD_NOHANDLE("AT+JN1DL=?"),
		SETUP_CMD_NOHANDLE("AT+JN2DL=?"),
		SETUP_CMD_NOHANDLE("AT+RX1DL=5000"),
		SETUP_CMD_NOHANDLE("AT+RX2DL=8000"),
		SETUP_CMD_NOHANDLE("AT+MASK=0002"),
		// SETUP_CMD_NOHANDLE("AT+ADR=0"),
		SETUP_CMD_NOHANDLE("AT+DR=0"),
		SETUP_CMD_NOHANDLE("AT+RETY=?"),
		SETUP_CMD_NOHANDLE("AT+APPEUI="CONFIG_RAK_APP_EUI), // Get App EUI
		SETUP_CMD("AT+CFM=?", "",
			  on_cmd_conf_query, 1U, ""), // Get Dev EUI
		SETUP_CMD("AT+DEVEUI=?", "",
			  on_cmd_dev_eui, 1U, ""), // Get Dev EUI
		SETUP_CMD("AT+APPEUI=?", "",
			  on_cmd_app_eui, 1U, ""), // Get App EUI
		SETUP_CMD("AT+APPKEY=?", "",
			  on_cmd_app_key, 1U, ""), // Get APP Key
		SETUP_CMD_NOHANDLE("AT+VER=?"),
	};
	LOG_DBG("Lora Init");
	
	return modem_cmd_handler_setup_cmds(&data->mctx.iface,
		&data->mctx.cmd_handler, setup_cmds,
		ARRAY_SIZE(setup_cmds),
		&data->sem_response,
		MDM_CMD_TIMEOUT);
}

#if 0
static int set_dev_class(rak_data_t *data, enum mlorawan_class dev_class)
{
	char cmd[sizeof("AT+CLASS=?")];
	switch (dev_class)
	{
	case LORAWAN_CLASS_A:
		snprintk(cmd, sizeof(cmd), "AT+CLASS=A");
		break;
	case LORAWAN_CLASS_B:
		snprintk(cmd, sizeof(cmd), "AT+CLASS=B");
		break;
	case LORAWAN_CLASS_C:
		snprintk(cmd, sizeof(cmd), "AT+CLASS=C");
		break;
	
	default:
		break;
	}
	return  modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
			NULL, 0U, cmd, &data->sem_response,
			MDM_CMD_TIMEOUT);
}


static int set_join_mode(rak_data_t *data, enum mlorawan_act_type mode)
{
	char cmd[sizeof("AT+NJM=?")];

	snprintk(cmd, sizeof(cmd), "AT+NJM=%d", mode);

	return  modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
			NULL, 0U, cmd, &data->sem_response,
			MDM_CMD_TIMEOUT);
}
#endif

static int start_join(rak_data_t *data)
{
	int ret = 0;
	char cmd[sizeof("AT+JOIN=1:0:10:8")];
	struct modem_cmd join_cmd[] = { 
		MODEM_CMD("+EVT:JOINED", on_cmd_joined, 0U, ""),
		MODEM_CMD("+EVT:JOIN FAILED", on_cmd_join_failed, 0U, ""),
	};

	struct modem_cmd status_cmd[] = { 
		MODEM_CMD("1", on_cmd_true, 0, ""),
		MODEM_CMD("0", on_cmd_false, 0, ""),
	};
	snprintk(cmd, sizeof(cmd), "AT+NJS=?");
	ret = modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
		status_cmd, ARRAY_SIZE(status_cmd), cmd, &data->sem_response,
		MDM_CMD_TIMEOUT);

	if(ret)
		return 0;



	snprintk(cmd, sizeof(cmd), "AT+JOIN=1:0:10:4");

	return modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
			join_cmd, ARRAY_SIZE(join_cmd), cmd, &data->sem_tx,
			MDM_JOIN_TIMEOUT);
}

int set_message_type(rak_data_t *data, enum mlorawan_message_type type)
{
	char cmd[sizeof("AT+CFM=?")];
	snprintk(cmd, sizeof(cmd), "AT+CFM=%d", type);
	return modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
		NULL, 0, cmd, &data->sem_response,
		MDM_CMD_TIMEOUT);
}

int send_data(rak_data_t *dev_data, uint8_t port, uint8_t *data, uint8_t len)
{
	struct modem_cmd_handler_data *handler_data = (struct modem_cmd_handler_data *)dev_data->mctx.cmd_handler.cmd_handler_data;
	char buf[sizeof("AT+SEND=???:")];
	int ret = 0;

	snprintk(buf, sizeof(buf), "AT+SEND=%d:", port);
	k_sem_reset(&dev_data->sem_response);
	k_sem_reset(&dev_data->sem_tx);

	dev_data->mctx.iface.write(&dev_data->mctx.iface, buf, strlen(buf));

	for(int i = 0; i < len; i++)
	{
		snprintk(buf, sizeof(buf), "%02x:", data[i]);
		dev_data->mctx.iface.write(&dev_data->mctx.iface, buf, 2);
	}
	if(dev_data->msg_type == LORAWAN_MSG_CONFIRMED)
	{
		const struct modem_cmd cmds[] = {
			MODEM_CMD("+EVT:SEND CONFIRMED ", on_cmd_send_confirmation, 1U, "")
		};
		ret = modem_cmd_handler_update_cmds(&dev_data->cmd_handler_data,
				cmds,
				ARRAY_SIZE(cmds),
				true);
		if(ret)
			return ret;
	}
	dev_data->mctx.iface.write(&dev_data->mctx.iface, 
		handler_data->eol, 
		handler_data->eol_len);

	if(k_sem_take(&dev_data->sem_response, MDM_CMD_TIMEOUT))
	{
		LOG_ERR("Modem command time out");
		return -3;
	}

	if(dev_data->msg_type == LORAWAN_MSG_CONFIRMED)
	{

		if(k_sem_take(&dev_data->sem_tx, MDM_SEND_TIMEOUT))
		{
			LOG_ERR("Modem send time out");
			ret = -3;
		}else
		{
			ret = modem_cmd_handler_get_error(&dev_data->cmd_handler_data);
			(void)modem_cmd_handler_update_cmds(&dev_data->cmd_handler_data,
						NULL, 0U, false);
		}
	}

	return ret;
}

int mlorawan_send(const struct device *dev, uint8_t port, uint8_t *data, uint8_t len, enum mlorawan_message_type type)
{
	rak_data_t *dev_data = dev->data;
	int ret = 0;
	if (k_mutex_lock(&dev_data->lock, K_SECONDS(10)))
		return -EBUSY;

	lora_uart_enable();
	if(dev_data->msg_type != type)
	{
		ret = set_message_type(dev_data, type);
		if(ret)
		{
			k_mutex_unlock(&dev_data->lock);
			LOG_ERR("Lora set message type fail");
			return ret;
		}
		dev_data->msg_type = type;
	}

	ret = send_data(dev_data, port, data, len);
	lora_uart_disable();
	k_mutex_unlock(&dev_data->lock);

	return ret;
	
}

int mlorawan_join(const struct device *dev, const struct mlorawan_join_config *config)
{
	rak_data_t *data = dev->data;
	int ret;
	if (k_mutex_lock(&data->lock, K_SECONDS(10)))
		return -EBUSY;

	lora_uart_enable();
#if 0   // TODO: ignore configs for now and hardcode them in setup
	ret = set_dev_class(data, config->dev_class);
	if(ret)
		goto clean_up;
	ret = set_join_mode(data, config->mode);
	if(ret)
		goto clean_up;
#endif
	ret = start_join(data);
	lora_uart_disable();
	k_mutex_unlock(&data->lock);

	return ret;
}

static int rak3172_lora_init(const struct device *dev)
{
	rak_data_t *data = dev->data;
	int ret = 0;

	k_mutex_init(&data->lock);
	k_sem_init(&data->sem_response, 0, 1);
	k_sem_init(&data->sem_tx, 0, 1);

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
		LOG_ERR("FAILED CMD HANDLER INIT\n");
		return ret;
	}

	/* modem interface */
	data->iface_data.hw_flow_control = DT_PROP(DT_INST_BUS(0), hw_flow_control);
	data->iface_data.rx_rb_buf = &data->iface_rb_buf[0];
	data->iface_data.rx_rb_buf_len = sizeof(data->iface_rb_buf);
	ret = modem_iface_uart_init(&data->mctx.iface, &data->iface_data,
		lora_uart_dev);
	if (ret < 0) {
		LOG_ERR("modem iface init failed with %d\n", ret);
		return ret;
	}

	/* pin setup */
	data->mctx.pins = modem_pins;
	data->mctx.pins_len = ARRAY_SIZE(modem_pins);
	data->mctx.driver_data = data;
	ret = modem_context_register(&data->mctx);
	if (ret < 0) {
		LOG_ERR("Error registering modem context: %d", ret);
		goto clean_uart_init;
	}

	/* start RX thread */
	k_thread_create(&modem_rx_thread, modem_rx_stack,
			K_KERNEL_STACK_SIZEOF(modem_rx_stack),
			(k_thread_entry_t)lora_rx,
			data, NULL, NULL,
			K_PRIO_COOP(CONFIG_RAK_RX_THREAD_PRIORITY), 0,
			K_NO_WAIT);
	k_thread_name_set(&modem_rx_thread, "rak_rx");

#if DT_INST_NODE_HAS_PROP(0, mdm_power_gpios)
	modem_pin_write(&data->mctx, MDM_POWER, 1);
	k_sleep(K_MSEC(500));
#endif

	// Lock here, and unlock after intiailized
	modem_pin_write(&data->mctx, MDM_RESET, 0);
	k_sleep(K_MSEC(1));
	modem_pin_write(&data->mctx, MDM_RESET, 1);

	if(k_sem_take(&data->sem_response, K_SECONDS(5)))
	{
		ret = -ETIMEDOUT;
		goto clean_uart_init;
	}
	
	k_sleep(K_SECONDS(1));

	ret = configure_hw_info(data);
	if(ret)
		goto clean_uart_init;

	ret = rak_at_init(data);

clean_uart_init:
	lora_uart_disable();

	return ret;
}

DEVICE_DT_INST_DEFINE(0, &rak3172_lora_init, NULL, &driver_data,
	NULL, POST_KERNEL, CONFIG_LORA_INIT_PRIORITY,
	&rak3172_lora_api);
