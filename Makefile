
# Top level Makefile for building the pqov library and executables

shared_libs:
	$(MAKE) -C pqov shared_libs EXTRA_CFLAGS="-DUSE_SALT_FROM_SIG -DSKIP_MEMCPY"


clean:
	$(MAKE) -C pqov clean
	rm -rf build



# ---------------------------------------------------------------------------- #
#                                Target firmware                               #
# ---------------------------------------------------------------------------- #

OUTPUT_DIR := pqm4/bin
PQM4_HEX := ${OUTPUT_DIR}/crypto_sign_ov-Ip-pkc-skc_m4fspeed_test.hex

target-profile-counter:
	rm -f $(PQM4_HEX)
	$(MAKE) -B -C pqm4 \
		IMPLEMENTATION_PATH=crypto_sign/ov-Ip-pkc-skc/m4fspeed \
		PLATFORM=cw308t-stm32f415 \
		MUPQ_ITERATIONS=1 \
		DEBUG=1 \
		LTO= \
		AIO=1 \
		EXTRA_CFLAGS=-DPROFILE_COUNTER \
		bin/crypto_sign_ov-Ip-pkc-skc_m4fspeed_test.hex
	mv $(PQM4_HEX) $(OUTPUT_DIR)/crypto_sign_$@.hex

target-profile-memcpy:
	rm -f $(PQM4_HEX)
	$(MAKE) -B -C pqm4 \
		IMPLEMENTATION_PATH=crypto_sign/ov-Ip-pkc-skc/m4fspeed \
		PLATFORM=cw308t-stm32f415 \
		MUPQ_ITERATIONS=1 \
		DEBUG=1 \
		LTO= \
		AIO=1 \
		EXTRA_CFLAGS=-DPROFILE_MEMCPY \
		bin/crypto_sign_ov-Ip-pkc-skc_m4fspeed_test.hex
	mv $(PQM4_HEX) $(OUTPUT_DIR)/crypto_sign_$@.hex

target-profile-attack-memcpy:
	rm -f $(PQM4_HEX)
	$(MAKE) -B -C pqm4 \
		IMPLEMENTATION_PATH=crypto_sign/ov-Ip-pkc-skc/m4fspeed \
		PLATFORM=cw308t-stm32f415 \
		MUPQ_ITERATIONS=1 \
		DEBUG=1 \
		LTO= \
		AIO=1 \
		EXTRA_CFLAGS=-DPROFILE_ATTACK_MEMCPY\
		bin/crypto_sign_ov-Ip-pkc-skc_m4fspeed_test.hex
	mv $(PQM4_HEX) $(OUTPUT_DIR)/crypto_sign_$@.hex

target-profile-attack-complete:
	rm -f $(PQM4_HEX)
	$(MAKE) -B -C pqm4 \
		IMPLEMENTATION_PATH=crypto_sign/ov-Ip-pkc-skc/m4fspeed \
		PLATFORM=cw308t-stm32f415 \
		MUPQ_ITERATIONS=1 \
		DEBUG=1 \
		LTO= \
		AIO=1 \
		EXTRA_CFLAGS=-DPROFILE_ATTACK_COMPLETE \
		bin/crypto_sign_ov-Ip-pkc-skc_m4fspeed_test.hex
	mv $(PQM4_HEX) $(OUTPUT_DIR)/crypto_sign_$@.hex

target-attack:
	rm -f $(PQM4_HEX)
	$(MAKE) -B -C pqm4 \
		IMPLEMENTATION_PATH=crypto_sign/ov-Ip-pkc-skc/m4fspeed \
		PLATFORM=cw308t-stm32f415 \
		MUPQ_ITERATIONS=1 \
		DEBUG=1 \
		LTO= \
		AIO=1 \
		EXTRA_CFLAGS=-DATTACK \
		bin/crypto_sign_ov-Ip-pkc-skc_m4fspeed_test.hex
	mv $(PQM4_HEX) $(OUTPUT_DIR)/crypto_sign_$@.hex
