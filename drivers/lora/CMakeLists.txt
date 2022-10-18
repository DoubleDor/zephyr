# SPDX-License-Identifier: Apache-2.0

zephyr_library_include_directories(
    ${ZEPHYR_BASE}/drivers/modem
  )
zephyr_include_directories(./include)
zephyr_library_sources_ifdef(CONFIG_LORA_RAK3172 rak3172.c)
