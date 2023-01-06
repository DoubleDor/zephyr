# zephyr
Open Source Drivers and Libraries for Dor's Hardware Product

## LORA Drivers
The lora drivers were designed specifically to work with the [helium](https://www.helium.com/) network. 

The unit tests can be referenced as usage as well as the sample code below:

```c
#include <drivers/lora.h>
#include <lorawan_module.h>

void main(void)
{
	const struct device *lora_module = device_get_binding(DEFAULT_RADIO);
	struct mlorawan_join_config lorawan_join_config;
	uint8_t test_data[5] = {0xbb, 0xbb, 0xcc, 0xdd, 0xee};

	lorawan_join_config.mode = LORAWAN_ACT_OTAA;
	lorawan_join_config.dev_class = LORAWAN_CLASS_A;

	mlorawan_join(lora_module, &lorawan_join_config);

	mlorawan_send(lora_module, 1, test_data, 5, 1);

}

```
