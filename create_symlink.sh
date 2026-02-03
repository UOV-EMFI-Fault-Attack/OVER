#!/bin/bash

# Function to create or update a symlink safely and idempotently
create_symlink() {
    local target_file="$1"
    local symlink_location="$2"

    # Check that the target file exists
    if [[ ! -e "$target_file" ]]; then
        echo "Error: target file does not exist: $target_file"
        return 1
    fi

    # Compute relative path for the symlink target
    local relative_target
    relative_target="$(realpath --relative-to="$(dirname "$symlink_location")" "$target_file")"

    # If a symlink already exists
    if [[ -L "$symlink_location" ]]; then
        local existing_target
        existing_target="$(readlink "$symlink_location")"

        if [[ "$existing_target" == "$relative_target" ]]; then
            echo "Symlink already correct: $symlink_location -> $existing_target"
            return 0
        else
            echo "Updating symlink: $symlink_location (was pointing to $existing_target)"
            ln -sf "$relative_target" "$symlink_location"
            return 0
        fi
    fi

    # If a regular file or directory exists at the symlink path (not a symlink)
    if [[ -e "$symlink_location" ]]; then
        echo "Replacing existing file with symlink: $symlink_location"
        rm -rf "$symlink_location"
    fi

    # Create new symlink
    ln -s "$relative_target" "$symlink_location"
    echo "Symlink created: $symlink_location -> $relative_target"
}

# Create symlinks for the pqov_additional_files
create_symlink pqov_additional_files/genearate_sk_pk-test.c pqov/unit_tests/genearate_sk_pk-test.c
create_symlink pqov_additional_files/key-test.c pqov/unit_tests/key-test.c
create_symlink pqov_additional_files/validation_functions-test.c pqov/unit_tests/validation_functions-test.c
create_symlink pqov_additional_files/Makefile pqov/Makefile
create_symlink pqov_additional_files/ov.c pqov/src/ov.c


# Create Symlinks for pqm4
create_symlink pqm4_additional_files/test.c pqm4/mupq/crypto_sign/test.c
create_symlink pqm4_additional_files/sign.c pqm4/crypto_sign/ov-Ip-pkc-skc/m4fspeed/sign.c
create_symlink pqm4_additional_files/ov.c pqm4/crypto_sign/ov-Ip-pkc-skc/m4fspeed/ov.c

create_symlink pqm4_additional_files/hal pqm4/common/hal # HAL for trigger output
create_symlink pqm4_additional_files/hal-opencm3.c pqm4/common/hal-opencm3.c # HAL for everything else (UART etc.)
create_symlink pqm4_additional_files/simpleserial pqm4/common/simpleserial # simpleserial communication
create_symlink pqm4_additional_files/crypto.mk pqm4/mk/crypto.mk # Makefile update to include above files in build

# Create symlinks for generated files for sk and pk
create_symlink keys/sk.h pqm4/mupq/crypto_sign/sk.h
create_symlink keys/pk.h pqm4/mupq/crypto_sign/pk.h
create_symlink keys/pk.h pqov/unit_tests/pk.h
create_symlink keys/sk.h pqov/unit_tests/sk.h