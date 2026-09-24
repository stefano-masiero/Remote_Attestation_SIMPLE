// main.c — STM32 prover entry point (CubeMX-generated with custom attestation
// logic)
//
// This file is maintained by CubeMX (USER CODE BEGIN/END markers) and contains:
//   - HAL / peripheral init (clock, GPIO, UART, HASH, ICACHE, FLASH, GTZC).
//   - MPU_Config: 7 regions that enforce the privilege boundary (report §2.7).
//   - State-map / parser / config-shadow initialization.
//   - app_config_privileged_flash_region: marks the FLASH_PRIV sectors as
//   privileged
//     via the STM32 block-based attributes (flash write protection).
//   - app_enter_unprivileged_mode: drops Thread mode to unprivileged after
//   init.
//   - The main loop: polls UART byte-by-byte, feeds the protocol parser,
//   dispatches
//     complete frames through the SVC privilege transition.
//   - SVC dispatch path: copies the request into the privileged mailbox, calls
//     attestation_process_request() in Handler mode, copies the result back,
//     and wipes the mailbox (see report §2.5 / §3.2 and Figure 6).
//
// LED feedback:
//   - 1.5 s solid green on attestation success.
//   - 6 rapid blinks on failure. Disabled when ATTESTATION_BENCHMARK=1 to avoid
//     adding ~1 s of dead time to the timing measurements.
/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file           : main.c
 * @brief          : Main program body
 ******************************************************************************
 * @attention
 *
 * Copyright (c) 2026 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "attestation.h"
#include "crypto.h"
#include "privileged_sections.h"
#include "protocol.h"
#include "state_map.h"
#include <string.h>
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

#define APP_LED_OK_ON_MS 1500u
#define APP_LED_FAIL_BLINKS 6u
#define APP_LED_FAIL_ON_MS 100u
#define APP_LED_FAIL_OFF_MS 100u

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

COM_InitTypeDef BspCOMInit;

HASH_HandleTypeDef hhash;

UART_HandleTypeDef huart1;

/* USER CODE BEGIN PV */
extern uint8_t __attest_flash_start__[];
extern uint8_t __attest_flash_end__[];
extern uint8_t __flash_priv_start__[];
extern uint8_t __flash_priv_end__[];
extern uint8_t __app_ram_start__[];
extern uint8_t __app_ram_end__[];
extern uint8_t __attest_state_start__[];
extern uint8_t __attest_mailbox_end__[];

static protocol_parser_t g_protocol_parser;

// The SVC dispatch uses a two-buffer scheme:
//   g_attest_svc_stage   — unprivileged, visible to the main loop (application
//   RAM). g_attest_svc_mailbox — privileged, accessible only in Handler mode
//   (ATTEST_PRIV_DATA
//                          in the .attest_mailbox section inside RAM_PRIV).
// The stage is copied into the mailbox on SVC entry and the result is copied
// back; the mailbox is wiped after every transaction
// (app_secure_mailbox_clear).
typedef struct {
  protocol_attest_req_t req;
  protocol_attest_resp_t resp;
  bool include_local_vs;
  attestation_status_t status;
} attest_svc_mailbox_t;

typedef struct {
  protocol_attest_req_t req;
  protocol_attest_resp_t resp;
  bool include_local_vs;
  attestation_status_t status;
} attest_svc_stage_t;

static volatile attest_svc_stage_t g_attest_svc_stage;
static volatile attest_svc_mailbox_t g_attest_svc_mailbox ATTEST_PRIV_DATA;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MPU_Config(void);
static void MX_GPIO_Init(void);
static void MX_ICACHE_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_FLASH_Init(void);
static void MX_HASH_Init(void);
static void MX_GTZC_Init(void);
/* USER CODE BEGIN PFP */
static HAL_StatusTypeDef app_uart_send_frame(const protocol_frame_t *frame);
static void app_send_placeholder_response(uint32_t counter, uint8_t profile_id,
                                          uint8_t result_code);
static void app_send_attestation_response(const protocol_attest_resp_t *resp,
                                          bool include_local_vs);
static void app_handle_frame(const protocol_frame_t *frame);
static attestation_status_t
app_attestation_via_svc(const protocol_attest_req_t *req,
                        protocol_attest_resp_t *resp, bool *include_local_vs);
static void app_enter_unprivileged_mode(void);
static HAL_StatusTypeDef app_config_privileged_flash_region(void);
static bool app_range_within_app_ram(const void *ptr, size_t len);
ATTEST_PRIV_CODE static void app_secure_mailbox_clear(void);
ATTEST_PRIV_CODE void app_attestation_svc_dispatch(void);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

// ---- LED feedback (disabled during benchmark runs) ----

#if (ATTESTATION_BENCHMARK != 1u)
static void app_led_attestation_ok(void) {
  BSP_LED_On(LED_GREEN);
  HAL_Delay(APP_LED_OK_ON_MS);
  BSP_LED_Off(LED_GREEN);
}

static void app_led_attestation_failed(void) {
  uint32_t i;

  for (i = 0u; i < APP_LED_FAIL_BLINKS; ++i) {
    BSP_LED_On(LED_GREEN);
    HAL_Delay(APP_LED_FAIL_ON_MS);
    BSP_LED_Off(LED_GREEN);
    HAL_Delay(APP_LED_FAIL_OFF_MS);
  }
}
#endif

// ---- UART TX ----

static HAL_StatusTypeDef app_uart_send_frame(const protocol_frame_t *frame) {
  /* Serialize and transmit a protocol frame over UART1 toward the ESP32
   * gateway. */
  uint8_t tx_buf[PROTOCOL_MAX_FRAME_SIZE];
  size_t tx_len = 0u;
  protocol_status_t pstatus;

  pstatus = protocol_build_frame(frame, tx_buf, sizeof(tx_buf), &tx_len);
  if (pstatus != PROTOCOL_STATUS_OK) {
    return HAL_ERROR;
  }

  return HAL_UART_Transmit(&huart1, tx_buf, (uint16_t)tx_len, HAL_MAX_DELAY);
}

static void app_send_placeholder_response(uint32_t counter, uint8_t profile_id,
                                          uint8_t result_code) {
  /* Send a minimal error response (no MAC, no local_vs) for pre-attestation
   * failures. */
  protocol_attest_resp_t resp;
  protocol_frame_t frame;

  memset(&resp, 0, sizeof(resp));
  resp.counter = counter;
  resp.profile_id = profile_id;
  resp.result = result_code;
  resp.flags = PROTOCOL_RESP_FLAG_NONE;

  if (protocol_build_attest_resp_frame(&resp, false, &frame) ==
      PROTOCOL_STATUS_OK) {
    (void)app_uart_send_frame(&frame);
  }
}

static void app_send_attestation_response(const protocol_attest_resp_t *resp,
                                          bool include_local_vs) {
  /* Send the full attestation response (with MAC, optionally with local_vs /
   * timing). */
  protocol_frame_t frame;

  if (resp == NULL) {
    return;
  }

  if (protocol_build_attest_resp_frame(resp, include_local_vs, &frame) ==
      PROTOCOL_STATUS_OK) {
    (void)app_uart_send_frame(&frame);
  }
}

// ---- Frame dispatch ----

static void app_handle_frame(const protocol_frame_t *frame) {
  /* Route a received frame: parse the request, cross the privilege boundary via
   * SVC, and send the response. Non-attestation message types get a placeholder
   * error. */
  protocol_attest_req_t req;
  protocol_attest_resp_t resp;
  protocol_status_t pstatus;
  attestation_status_t astatus;
  bool include_local_vs = false;

  if (frame == NULL) {
    return;
  }

  if (frame->msg_type != PROTOCOL_MSG_ATTEST_REQ) {
    app_send_placeholder_response(0u, 0u, PROTOCOL_RESULT_UNSUPPORTED);
    return;
  }

  pstatus = protocol_parse_attest_req(frame, &req);
  if (pstatus != PROTOCOL_STATUS_OK) {
    app_send_placeholder_response(0u, 0u, PROTOCOL_RESULT_BAD_REQUEST);
    return;
  }

  astatus = app_attestation_via_svc(&req, &resp, &include_local_vs);
  if (astatus != ATTESTATION_STATUS_OK) {
#if (ATTESTATION_BENCHMARK != 1u)
    app_led_attestation_failed();
#endif
    app_send_placeholder_response(req.counter, req.profile_id,
                                  PROTOCOL_RESULT_INTERNAL_ERROR);
    return;
  }

#if (ATTESTATION_BENCHMARK != 1u)
  if (resp.result == PROTOCOL_RESULT_SUCCESS) {
    app_led_attestation_ok();
  } else {
    app_led_attestation_failed();
  }
#endif
  app_send_attestation_response(&resp, include_local_vs);
}

// ---- SVC privilege transition ----

static attestation_status_t
app_attestation_via_svc(const protocol_attest_req_t *req,
                        protocol_attest_resp_t *resp, bool *include_local_vs) {
  /* Copy the request into the unprivileged stage buffer, issue `svc 0` to cross
   * into Handler mode, then retrieve the response. The actual attestation runs
   * inside app_attestation_svc_dispatch() in privileged context. */
  if ((req == NULL) || (resp == NULL) || (include_local_vs == NULL)) {
    return ATTESTATION_STATUS_INVALID_ARG;
  }

  memcpy((void *)&g_attest_svc_stage.req, req, sizeof(*req));
  memset((void *)&g_attest_svc_stage.resp, 0, sizeof(g_attest_svc_stage.resp));
  g_attest_svc_stage.include_local_vs = false;
  g_attest_svc_stage.status = ATTESTATION_STATUS_INVALID_ARG;

  __DMB();
  __asm volatile("svc 0" ::: "memory");
  __DMB();

  memcpy(resp, (const void *)&g_attest_svc_stage.resp, sizeof(*resp));
  *include_local_vs = g_attest_svc_stage.include_local_vs;
  return g_attest_svc_stage.status;
}

ATTEST_PRIV_CODE void app_attestation_svc_dispatch(void) {
  /* Called from SVC_Handler (Handler mode, privileged). Snapshots the
   * unprivileged stage into the privileged mailbox, runs the attestation
   * engine, copies the result back, and wipes the mailbox so key material never
   * lingers. */
  if (!app_range_within_app_ram((const void *)&g_attest_svc_stage,
                                sizeof(g_attest_svc_stage))) {
    app_secure_mailbox_clear();
    return;
  }

  memcpy((void *)&g_attest_svc_mailbox.req,
         (const void *)&g_attest_svc_stage.req,
         sizeof(g_attest_svc_mailbox.req));
  memset((void *)&g_attest_svc_mailbox.resp, 0,
         sizeof(g_attest_svc_mailbox.resp));
  g_attest_svc_mailbox.include_local_vs = false;
  g_attest_svc_mailbox.status = ATTESTATION_STATUS_INVALID_ARG;

  g_attest_svc_mailbox.status = attestation_process_request(
      (const protocol_attest_req_t *)&g_attest_svc_mailbox.req,
      (protocol_attest_resp_t *)&g_attest_svc_mailbox.resp,
      (bool *)&g_attest_svc_mailbox.include_local_vs);

  memcpy((void *)&g_attest_svc_stage.resp,
         (const void *)&g_attest_svc_mailbox.resp,
         sizeof(g_attest_svc_stage.resp));
  g_attest_svc_stage.include_local_vs = g_attest_svc_mailbox.include_local_vs;
  g_attest_svc_stage.status = g_attest_svc_mailbox.status;

  app_secure_mailbox_clear();
}

ATTEST_PRIV_CODE static void app_secure_mailbox_clear(void) {
  /* Volatile-zeroize the privileged mailbox after every transaction so keys,
   * nonces and intermediate digests do not persist in RAM_PRIV. */
  crypto_secure_zero((void *)&g_attest_svc_mailbox,
                     sizeof(g_attest_svc_mailbox));
}

static bool app_range_within_app_ram(const void *ptr, size_t len) {
  /* Validate that a pointer+length range lies entirely inside the unprivileged
   * application RAM window (RAM, not RAM_PRIV). Used as a sanity check before
   * the SVC dispatch copies from the stage buffer. */
  uintptr_t start_addr;
  uintptr_t end_addr;
  uintptr_t ram_start;
  uintptr_t ram_end;

  if ((ptr == NULL) || (len == 0u)) {
    return false;
  }

  start_addr = (uintptr_t)ptr;
  end_addr = start_addr + len;
  ram_start = (uintptr_t)__app_ram_start__;
  ram_end = (uintptr_t)__app_ram_end__;

  if ((end_addr < start_addr) || (start_addr < ram_start) ||
      (end_addr > ram_end)) {
    return false;
  }

  return true;
}

static HAL_StatusTypeDef app_config_privileged_flash_region(void) {
  /* Mark the FLASH_PRIV sectors as privileged using the STM32 flash block-based
   * attributes. This prevents unprivileged code from reading or executing the
   * attestation routines and keys even if the MPU were somehow bypassed. */
  FLASH_BBAttributesTypeDef bb_attr = {0};
  uintptr_t start_addr = (uintptr_t)__flash_priv_start__;
  uintptr_t end_addr = (uintptr_t)__flash_priv_end__;
  uintptr_t const flash_base = 0x08000000u;
  uintptr_t const flash_size = 0x00020000u;
  uintptr_t const bank_size = 0x00010000u;
  uintptr_t const sector_size = 0x00002000u;
  uintptr_t bank_offset;
  uintptr_t end_inclusive;
  uint32_t bank_index;
  uint32_t first_sector;
  uint32_t last_sector;
  uint32_t sector;

  if ((end_addr <= start_addr) || (start_addr < flash_base) ||
      (end_addr > (flash_base + flash_size))) {
    return HAL_ERROR;
  }

  end_inclusive = end_addr - 1u;
  bank_index = (uint32_t)((start_addr - flash_base) / bank_size);
  if (bank_index != (uint32_t)((end_inclusive - flash_base) / bank_size)) {
    return HAL_ERROR;
  }

  bank_offset = (uintptr_t)bank_index * bank_size;
  first_sector =
      (uint32_t)((start_addr - flash_base - bank_offset) / sector_size);
  last_sector =
      (uint32_t)((end_inclusive - flash_base - bank_offset) / sector_size);

  bb_attr.Bank = (bank_index == 0u) ? FLASH_BANK_1 : FLASH_BANK_2;
  bb_attr.BBAttributesType = FLASH_BB_PRIV;

  for (sector = first_sector; sector <= last_sector; ++sector) {
    bb_attr.BBAttributes_array[0] |= (1u << sector);
  }

  if (HAL_FLASH_Unlock() != HAL_OK) {
    return HAL_ERROR;
  }

  if (HAL_FLASHEx_ConfigBBAttributes(&bb_attr) != HAL_OK) {
    (void)HAL_FLASH_Lock();
    return HAL_ERROR;
  }

  if (HAL_FLASH_Lock() != HAL_OK) {
    return HAL_ERROR;
  }

  return HAL_OK;
}

static void app_enter_unprivileged_mode(void) {
  /* Drop Thread mode to unprivileged. From this point on, only `svc 0` can
   * re-enter privileged code. The MPU remains enabled and enforces the region
   * restrictions. */
  __set_CONTROL(__get_CONTROL() | CONTROL_nPRIV_Msk);
  __DSB();
  __ISB();
}

/* USER CODE END 0 */

/**
 * @brief  The application entry point.
 * @retval int
 */
int main(void) {
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* MPU Configuration--------------------------------------------------------*/
  MPU_Config();

  /* Reset of all peripherals, Initializes the Flash interface and the Systick.
   */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();
  attestation_benchmark_init();
  /* GTZC initialisation */
  MX_GTZC_Init();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_ICACHE_Init();
  MX_USART1_UART_Init();
  MX_FLASH_Init();
  MX_HASH_Init();
  /* USER CODE BEGIN 2 */

  // Initialize the three protected-RAM structures and the protocol parser.
  state_map_attest_state_init();
  state_map_config_shadow_init();
  state_map_secure_runtime_init();
  protocol_parser_init(&g_protocol_parser);
  state_map_attest_state_set_protocol_flags(STATE_MAP_PROTOFLAG_UART_READY |
                                            STATE_MAP_PROTOFLAG_PARSER_READY);
  state_map_attest_state_set_lifecycle(STATE_MAP_LIFECYCLE_READY);
  state_map_config_shadow_refresh_from_hw();

  // Lock down the privileged flash sectors via block-based attributes.
  if (app_config_privileged_flash_region() != HAL_OK) {
    Error_Handler();
  }
  /* USER CODE END 2 */

  /* Initialize led */
  BSP_LED_Init(LED_GREEN);

  /* Initialize USER push-button, will be used to trigger an interrupt each time
   * it's pressed.*/
  BSP_PB_Init(BUTTON_USER, BUTTON_MODE_EXTI);

  /* Initialize COM1 port (115200, 8 bits (7-bit data + 1 stop bit), no parity
   */
  BspCOMInit.BaudRate = 115200;
  BspCOMInit.WordLength = COM_WORDLENGTH_8B;
  BspCOMInit.StopBits = COM_STOPBITS_1;
  BspCOMInit.Parity = COM_PARITY_NONE;
  BspCOMInit.HwFlowCtl = COM_HWCONTROL_NONE;
  if (BSP_COM_Init(COM1, &BspCOMInit) != BSP_ERROR_NONE) {
    Error_Handler();
  }

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */

  // Drop to unprivileged mode — all subsequent code runs with MPU restrictions.
  // The only way back to privileged is `svc 0`.
  app_enter_unprivileged_mode();
  while (1) {

    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */

    // Poll UART for one byte at a time, feed into the protocol parser.
    // When a complete CRC-valid frame arrives, dispatch it.
    uint8_t rx_byte;
    protocol_frame_t frame;
    protocol_parse_status_t parse_status;

    if (HAL_UART_Receive(&huart1, &rx_byte, 1u, 10u) == HAL_OK) {
      parse_status =
          protocol_parser_consume_byte(&g_protocol_parser, rx_byte, &frame);

      if (parse_status == PROTOCOL_PARSE_FRAME_READY) {
        app_handle_frame(&frame);
      } else if (parse_status == PROTOCOL_PARSE_ERROR) {
        protocol_parser_reset(&g_protocol_parser);
      }
    }
  }
  /* USER CODE END 3 */
}

/**
 * @brief System Clock Configuration
 * @retval None
 */
void SystemClock_Config(void) {
  /* Configure HSE + PLL1 → 250 MHz SYSCLK, no bus dividers. */
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
   */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE0);

  while (!__HAL_PWR_GET_FLAG(PWR_FLAG_VOSRDY)) {
  }

  /** Initializes the RCC Oscillators according to the specified parameters
   * in the RCC_OscInitTypeDef structure.
   */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLL1_SOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 12;
  RCC_OscInitStruct.PLL.PLLN = 250;
  RCC_OscInitStruct.PLL.PLLP = 2;
  RCC_OscInitStruct.PLL.PLLQ = 2;
  RCC_OscInitStruct.PLL.PLLR = 2;
  RCC_OscInitStruct.PLL.PLLRGE = RCC_PLL1_VCIRANGE_1;
  RCC_OscInitStruct.PLL.PLLVCOSEL = RCC_PLL1_VCORANGE_WIDE;
  RCC_OscInitStruct.PLL.PLLFRACN = 0;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
   */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK |
                                RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2 |
                                RCC_CLOCKTYPE_PCLK3;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB3CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK) {
    Error_Handler();
  }

  /** Configure the programming delay
   */
  __HAL_FLASH_SET_PROGRAM_DELAY(FLASH_PROGRAMMING_DELAY_2);
}

/**
 * @brief FLASH Initialization Function
 * @param None
 * @retval None
 */
static void MX_FLASH_Init(void) {

  /* USER CODE BEGIN FLASH_Init 0 */

  /* USER CODE END FLASH_Init 0 */

  /* USER CODE BEGIN FLASH_Init 1 */

  /* USER CODE END FLASH_Init 1 */
  if (HAL_FLASH_Unlock() != HAL_OK) {
    Error_Handler();
  }
  if (HAL_FLASH_Lock() != HAL_OK) {
    Error_Handler();
  }
  /* USER CODE BEGIN FLASH_Init 2 */

  /* USER CODE END FLASH_Init 2 */
}

/**
 * @brief GTZC Initialization Function
 * @param None
 * @retval None
 */
static void MX_GTZC_Init(void) {
  /* Configure GTZC: mark HASH peripheral and the SRAM2 first block as
   * privileged. SRAM2 block 0 contains the RAM_PRIV overlay (.attest_state,
   * .attest_cfg, .attest_secure, .attest_mailbox). The USER CODE section
   * overrides the CubeMX defaults to put the correct privilege mask on SRAM1
   * (unprivileged) and SRAM2 (block 0 privileged). */

  /* USER CODE BEGIN GTZC_Init 0 */

  /* USER CODE END GTZC_Init 0 */

  MPCBB_ConfigTypeDef MPCBB_Area_Desc = {0};

  /* USER CODE BEGIN GTZC_Init 1 */

  /* USER CODE END GTZC_Init 1 */
  if (HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_HASH,
                                           GTZC_TZSC_PERIPH_PRIV) != HAL_OK) {
    Error_Handler();
  }
  MPCBB_Area_Desc.AttributeConfig.MPCBB_PrivConfig_array[0] = 0x00000001;
  if (HAL_GTZC_MPCBB_ConfigMem(SRAM1_BASE, &MPCBB_Area_Desc) != HAL_OK) {
    Error_Handler();
  }
  MPCBB_Area_Desc.AttributeConfig.MPCBB_PrivConfig_array[0] = 0x00000000;
  if (HAL_GTZC_MPCBB_ConfigMem(SRAM2_BASE, &MPCBB_Area_Desc) != HAL_OK) {
    Error_Handler();
  }
  /* USER CODE BEGIN GTZC_Init 2 */
  // Override CubeMX defaults: SRAM1 all-unprivileged, SRAM2 block 0 privileged.
  memset(&MPCBB_Area_Desc, 0, sizeof(MPCBB_Area_Desc));
  if (HAL_GTZC_MPCBB_ConfigMem(SRAM1_BASE, &MPCBB_Area_Desc) != HAL_OK) {
    Error_Handler();
  }

  memset(&MPCBB_Area_Desc, 0, sizeof(MPCBB_Area_Desc));
  MPCBB_Area_Desc.AttributeConfig.MPCBB_PrivConfig_array[0] = 0x00000001u;
  if (HAL_GTZC_MPCBB_ConfigMem(SRAM2_BASE, &MPCBB_Area_Desc) != HAL_OK) {
    Error_Handler();
  }
  /* USER CODE END GTZC_Init 2 */
}

/**
 * @brief HASH Initialization Function
 * @param None
 * @retval None
 */
static void MX_HASH_Init(void) {

  /* USER CODE BEGIN HASH_Init 0 */

  /* USER CODE END HASH_Init 0 */

  /* USER CODE BEGIN HASH_Init 1 */

  /* USER CODE END HASH_Init 1 */
  hhash.Instance = HASH;
  hhash.Init.DataType = HASH_BYTE_SWAP;
  hhash.Init.Algorithm = HASH_ALGOSELECTION_SHA256;
  if (HAL_HASH_Init(&hhash) != HAL_OK) {
    Error_Handler();
  }
  /* USER CODE BEGIN HASH_Init 2 */

  /* USER CODE END HASH_Init 2 */
}

/**
 * @brief ICACHE Initialization Function
 * @param None
 * @retval None
 */
static void MX_ICACHE_Init(void) {

  /* USER CODE BEGIN ICACHE_Init 0 */

  /* USER CODE END ICACHE_Init 0 */

  /* USER CODE BEGIN ICACHE_Init 1 */

  /* USER CODE END ICACHE_Init 1 */

  /** Enable instruction cache in 1-way (direct mapped cache)
   */
  if (HAL_ICACHE_ConfigAssociativityMode(ICACHE_1WAY) != HAL_OK) {
    Error_Handler();
  }
  if (HAL_ICACHE_Enable() != HAL_OK) {
    Error_Handler();
  }
  /* USER CODE BEGIN ICACHE_Init 2 */

  /* USER CODE END ICACHE_Init 2 */
}

/**
 * @brief USART1 Initialization Function
 * @param None
 * @retval None
 */
static void MX_USART1_UART_Init(void) {

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart1.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart1) != HAL_OK) {
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart1, UART_TXFIFO_THRESHOLD_1_8) !=
      HAL_OK) {
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart1, UART_RXFIFO_THRESHOLD_1_8) !=
      HAL_OK) {
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart1) != HAL_OK) {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */
}

/**
 * @brief GPIO Initialization Function
 * @param None
 * @retval None
 */
static void MX_GPIO_Init(void) {
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/* MPU Configuration */

void MPU_Config(void) {
  /* Configure MPU regions for the attestation privilege boundary (report §2.7).
   *
   * Region 0: main attested flash — all-RO, exec-enabled (application code).
   * Region 1: application RAM    — all-RW, exec-disabled (stack, heap, .data,
   * .bss). Region 2: peripherals        — all-RW, exec-disabled,
   * outer-shareable (APB/AHB). Region 6: privileged flash   — priv-RO,
   * exec-enabled (attestation code + keys). Region 7: privileged RAM     —
   * priv-RW, exec-disabled (.attest_state .. .attest_mailbox).
   *
   * With MPU_PRIVILEGED_DEFAULT the background map covers Handler-mode accesses
   * to regions not explicitly listed; the nPRIV bit set by
   * app_enter_unprivileged_mode() means Thread mode sees only the explicitly
   * configured regions. */
  MPU_Region_InitTypeDef MPU_InitStruct = {0};
  MPU_Attributes_InitTypeDef MPU_AttributesInit = {0};

  HAL_MPU_Disable();

  MPU_AttributesInit.Number = MPU_ATTRIBUTES_NUMBER0;
  MPU_AttributesInit.Attributes = INNER_OUTER(MPU_NOT_CACHEABLE);
  HAL_MPU_ConfigMemoryAttributes(&MPU_AttributesInit);

  MPU_AttributesInit.Number = MPU_ATTRIBUTES_NUMBER1;
  MPU_AttributesInit.Attributes = MPU_DEVICE_nGnRnE;
  HAL_MPU_ConfigMemoryAttributes(&MPU_AttributesInit);

  // Region 0: main attested flash (all-RO, exec)
  MPU_InitStruct.Enable = MPU_REGION_ENABLE;
  MPU_InitStruct.Number = MPU_REGION_NUMBER0;
  MPU_InitStruct.BaseAddress = (uint32_t)__attest_flash_start__;
  MPU_InitStruct.LimitAddress = (uint32_t)__attest_flash_end__ - 1u;
  MPU_InitStruct.AttributesIndex = MPU_ATTRIBUTES_NUMBER0;
  MPU_InitStruct.AccessPermission = MPU_REGION_ALL_RO;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_ENABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_NOT_SHAREABLE;
  HAL_MPU_ConfigRegion(&MPU_InitStruct);

  // Region 1: application RAM (all-RW, no exec)
  MPU_InitStruct.Number = MPU_REGION_NUMBER1;
  MPU_InitStruct.BaseAddress = (uint32_t)__app_ram_start__;
  MPU_InitStruct.LimitAddress = (uint32_t)__app_ram_end__ - 1u;
  MPU_InitStruct.AttributesIndex = MPU_ATTRIBUTES_NUMBER0;
  MPU_InitStruct.AccessPermission = MPU_REGION_ALL_RW;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_NOT_SHAREABLE;
  HAL_MPU_ConfigRegion(&MPU_InitStruct);

  // Region 2: peripherals (device memory, all-RW, no exec)
  MPU_InitStruct.Number = MPU_REGION_NUMBER2;
  MPU_InitStruct.BaseAddress = 0x40000000u;
  MPU_InitStruct.LimitAddress = 0x5FFFFFFFu;
  MPU_InitStruct.AttributesIndex = MPU_ATTRIBUTES_NUMBER1;
  MPU_InitStruct.AccessPermission = MPU_REGION_ALL_RW;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_OUTER_SHAREABLE;
  HAL_MPU_ConfigRegion(&MPU_InitStruct);

  // Region 6: privileged flash — attestation code + keys (priv-only RO, exec)
  MPU_InitStruct.Number = MPU_REGION_NUMBER6;
  MPU_InitStruct.BaseAddress = (uint32_t)__flash_priv_start__;
  MPU_InitStruct.LimitAddress = (uint32_t)__flash_priv_end__ - 1u;
  MPU_InitStruct.AttributesIndex = MPU_ATTRIBUTES_NUMBER0;
  MPU_InitStruct.AccessPermission = MPU_REGION_PRIV_RO;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_ENABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_NOT_SHAREABLE;
  HAL_MPU_ConfigRegion(&MPU_InitStruct);

  // Region 7: privileged RAM — .attest_state through .attest_mailbox (priv-only
  // RW, no exec)
  MPU_InitStruct.Number = MPU_REGION_NUMBER7;
  MPU_InitStruct.BaseAddress = (uint32_t)__attest_state_start__;
  MPU_InitStruct.LimitAddress = (uint32_t)__attest_mailbox_end__ - 1u;
  MPU_InitStruct.AttributesIndex = MPU_ATTRIBUTES_NUMBER0;
  MPU_InitStruct.AccessPermission = MPU_REGION_PRIV_RW;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_NOT_SHAREABLE;
  HAL_MPU_ConfigRegion(&MPU_InitStruct);

  // Enable MPU with privileged-default background map + fault handlers.
  HAL_MPU_Enable(MPU_PRIVILEGED_DEFAULT);
  SCB->SHCSR |= (SCB_SHCSR_MEMFAULTENA_Msk | SCB_SHCSR_BUSFAULTENA_Msk |
                 SCB_SHCSR_USGFAULTENA_Msk);
}

/**
 * @brief  This function is executed in case of error occurrence.
 * @retval None
 */
void Error_Handler(void) {
  /* USER CODE BEGIN Error_Handler_Debug */
  __disable_irq();
  while (1) {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
 * @brief  Reports the name of the source file and the source line number
 *         where the assert_param error has occurred.
 * @param  file: pointer to the source file name
 * @param  line: assert_param error line source number
 * @retval None
 */
void assert_failed(uint8_t *file, uint32_t line) {
  /* USER CODE BEGIN 6 */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
