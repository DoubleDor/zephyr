# SPDX-License-Identifier: Apache-2.0

zephyr_library_include_directories(
  ${ZEPHYR_BASE}/drivers/modem
)
zephyr_library_sources(
  ameba.c
  ameba_socket.c
  ameba_offload.c
)

