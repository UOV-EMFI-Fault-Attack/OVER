// SPDX-License-Identifier: Apache-2.0 or CC0-1.0
#include "api.h"
#include "randombytes.h"
#include "hal.h"
#include "sk.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#include "../../common/hal/stm32f4-hal.h"
#include "../../common/simpleserial/simpleserial.h"

#define setup_trigger() inline_gpio_mode_setup(GPIOA, GPIO_MODE_OUTPUT, GPIO_PUPD_PULLDOWN, GPIO12)
#define set_trigger() inline_gpio_set(GPIOA, GPIO12)
#define clear_trigger() inline_gpio_clear(GPIOA, GPIO12)

#define NOP  __asm__ volatile ("nop");
#define NOP10   NOP   NOP   NOP   NOP   NOP   NOP   NOP   NOP   NOP   NOP
#define NOP100  NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10


#define MLEN 256

// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)


// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_PUBLICKEYBYTES NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_BYTES          NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_ALGNAME        NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_sign_keypair NAMESPACE(crypto_sign_keypair)
#define MUPQ_crypto_sign NAMESPACE(crypto_sign)
#define MUPQ_crypto_sign_open NAMESPACE(crypto_sign_open)
#define MUPQ_crypto_sign_signature NAMESPACE(crypto_sign_signature)
#define MUPQ_crypto_sign_verify NAMESPACE(crypto_sign_verify)

const uint8_t canary[8] = {
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
};

/* allocate a bit more for all keys and messages and
 * make sure it is not touched by the implementations.
 */
static void write_canary(uint8_t *d) {
  for (size_t i = 0; i < 8; i++) {
    d[i] = canary[i];
  }
}

static int check_canary(const uint8_t *d) {
  for (size_t i = 0; i < 8; i++) {
    if (d[i] != canary[i]) {
      return -1;
    }
  }
  return 0;
}

unsigned char *sk;
unsigned char sm[MLEN + MUPQ_CRYPTO_BYTES];
unsigned char m[MLEN];
size_t smlen;
size_t mlen;

static int profile_memcpy(void)
{
  send_reset_sequence();
  char uart_ret;

  #define BUFFER_SIZE 68
  #define SRC_BUFFER_INIT_BYTE 0xCC
  #define TARGET_BUFFER_INIT_BYTE 0xEE

  // Arrays holding initalization data for buffers
  #ifdef SRC_BUFFER_INIT_SEQUENCE
  const char src_init[BUFFER_SIZE] = SRC_BUFFER_INIT_SEQUENCE;
  #endif
  #ifdef TARGET_BUFFER_INIT_SEQUENCE
  const char target_init[BUFFER_SIZE] = TARGET_BUFFER_INIT_SEQUENCE;
  #endif

  char src[BUFFER_SIZE];
  char target[BUFFER_SIZE];

  while (1)
  {
    uint8_t cmd;
    size_t dummy_len;
    int res = readpacket(&cmd, NULL, &dummy_len); // Read start signal
    if (res == 0 && cmd == 's')
    {
      send_ack(cmd); // Acknowledge start signal

      // Initalize src buffer
      #ifdef SRC_BUFFER_INIT_SEQUENCE
      memcpy(src, src_init, BUFFER_SIZE);
      #else
      memset(src, SRC_BUFFER_INIT_BYTE, sizeof(src)); // Initialize source buffer
      #endif

      // Initalize target buffer
      #ifdef TARGET_BUFFER_INIT_SEQUENCE
      memcpy(target, target_init, BUFFER_SIZE);
      #else
      memset(target, TARGET_BUFFER_INIT_BYTE, sizeof(target)); // Initialize target buffer
      #endif
      set_trigger();
      NOP100; // ~13.5 us sleep with 100 NOPs
      memcpy(target, src, sizeof(src)); // Attacked code
      clear_trigger();

      if (memcmp(src, target, sizeof(src)) != 0) {
        sendpacket('q', target, sizeof(target)); // Fault packet
      } else {
        sendpacket('e', NULL, 0); // End signal
      }
    }
  }
}


static int profile_unrolled_loop(void)
{
  #define ADD_COMMAND "add r0, r0, #1;"

  #define o ADD_COMMAND
  #define t o o o o o o o o o o
  #define h t t t t t t t t t t
  #define d h h h h h h h h h h
  #define x d d d d d d d d d d

  #define ADD_10    t
  #define ADD_100   h
  #define ADD_1000  d
  #define ADD_10000 x
  // Dispatch is needed to treat ADD_##N as macro and keep expanding
  #define NESTED_LOOP_MACRO_DISPATCH(N) ADD_##N
  #define NESTED_LOOP_MACRO(N) NESTED_LOOP_MACRO_DISPATCH(N)
  #define NUM_EXECUTIONS 100 // Can only be 10, 100 or 1000, 10000 without modification to above defines
  // TODO: measure length of 100 executions

  send_reset_sequence();

  char uart_ret;
  while (1)
  {
    uint8_t cmd;
    size_t dummy_len;
    int res = readpacket(&cmd, NULL, &dummy_len); // Read start signal
    if (res == 0 && cmd == 's')
    {
      send_ack(cmd); // Acknowledge start signal

      volatile unsigned int counter = 0;

      set_trigger(); // Raise trigger

      asm volatile (
        "mov r0, #0;" // Set r0 to 0
        NESTED_LOOP_MACRO(NUM_EXECUTIONS) // Unrolled loop
        "mov %[counter], r0;" // Set counter variable to r0

        : [counter] "=r" (counter) // Refer to variable counter from c code as counter in assembly code
        :
        : "r0"
      );

      clear_trigger(); // Lower trigger

      if (counter != NUM_EXECUTIONS){
          sendpacket('f', (const uint8_t *)&counter, sizeof(counter)); // Fault packet
      }
      else {
          sendpacket('e', NULL, 0); // End signal
      }
    }
  }
}


static int test_sign(void)
{
  // Set sm to all zeros for attack profiling
  #ifndef ATTACK
  memset(sm, 0, sizeof(sm));
  #endif

  #if defined(PROFILE_ATTACK_COMPLETE) || defined(ATTACK)
  set_trigger();
  #endif

  MUPQ_crypto_sign(sm, &smlen, m, MLEN, sk);

  #if defined(PROFILE_ATTACK_COMPLETE) || defined(ATTACK)
  clear_trigger();
  #endif

  // Send `sm` to host (split up in 190 byte chunks)
  for (size_t i = 0; i < smlen; i+=190)
  {
    size_t remaining_len;
    if ((i + 190) < smlen)
    {
      remaining_len = 190;
    }
    else {
      remaining_len = smlen -i;
    }

    sendpacket('d', sm + i, remaining_len); // Send data packet
    if (wait_ack('d') != 0) return -1; // Wait for acknowledge
  }

  send_ack('e'); // Indicates end of data packets

  return 0;
}

int main(void)
{
  hal_setup(CLOCK_FAST);
  // init_uart(); # Not needed because hal_setup() is used
  setup_trigger();

  /* -------------------------------------------------------------------------- */
  /*                          // Profile unrolled loop                          */
  /* -------------------------------------------------------------------------- */
  #ifdef PROFILE_COUNTER
  profile_unrolled_loop();
  #endif

  /* -------------------------------------------------------------------------- */
  /*                              // Profile memcpy                             */
  /* -------------------------------------------------------------------------- */
  #ifdef PROFILE_MEMCPY
  profile_memcpy();
  #endif

  /* -------------------------------------------------------------------------- */
  /*                    // Normal operation (UOV calculation)                   */
  /* -------------------------------------------------------------------------- */
  #if defined(PROFILE_ATTACK_MEMCPY) || defined(PROFILE_ATTACK_COMPLETE) || defined(ATTACK)
  sk = sk_comp;
  memset(m, 0, MLEN);
  send_reset_sequence();
  while (1)
  {
    uint8_t cmd;
    uint8_t* data;
    size_t data_len;

    int res = readpacket(&cmd, &data, &data_len); // Read start signal
    if (res == 0 && cmd == 's')
    {
      // Allow setting the message from the host PC
      // Currently not implemented in chipshouter-profiler
      if (data_len == MLEN)
      {
        memcpy(m, data, MLEN);
      }

      send_ack(cmd); // Acknowledge start signal
      test_sign();
    }
  }
  #endif

  return 0;
}
