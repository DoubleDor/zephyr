#include <ztest.h>
#include <logging/log.h>
#include <zephyr/device.h>
#include <drivers/lora.h>
#include <lorawan_module.h>

LOG_MODULE_REGISTER(lora_test);

#define DEFAULT_RADIO_NODE DT_ALIAS(lora0)
BUILD_ASSERT(DT_NODE_HAS_STATUS(DEFAULT_RADIO_NODE, okay),
	     "No default LoRa radio specified in DT");
#define DEFAULT_RADIO DT_LABEL(DEFAULT_RADIO_NODE)


struct dor_lora_tests_fixture {
	bool net_joined;
	const struct device *lora_module;
};

static struct dor_lora_tests_fixture test_fixture;

#define JOIN_TIMEOUT_SEC	(120)

static void *dor_lora_tests_setup(void)
{
	int retries = 0;
	struct mlorawan_join_config lorawan_join_config;
	lorawan_join_config.mode = LORAWAN_ACT_OTAA;
	lorawan_join_config.dev_class = LORAWAN_CLASS_A;

	test_fixture.lora_module = device_get_binding(DEFAULT_RADIO);
	if(!test_fixture.lora_module )
		goto exit;
	while(retries < 5 && (mlorawan_join(test_fixture.lora_module, &lorawan_join_config)))
	{
		retries++;
	}
	if(retries < 5)
		test_fixture.net_joined = true;

exit:
	return &test_fixture;
}

ZTEST_SUITE(dor_lora_tests, NULL, dor_lora_tests_setup, NULL, NULL, NULL);

ZTEST_F(dor_lora_tests, test_simple_send)
{
	int ret;
	int fail_count = 0;
	uint8_t test_data[5] = {0xbb, 0xbb, 0xcc, 0xdd, 0xee};
	zassert_true(test_fixture.lora_module, "No lora module found");
	zassert_true(test_fixture.net_joined, "Failed to join network");
	for(int i = 0; i < 20; i++)
	{
		ret = mlorawan_send(test_fixture.lora_module, 1, test_data, 5, 1);
		if(ret)
			fail_count++;
	}
	zassert_true(fail_count <= 15, "Failed to send %d times", fail_count);

}
