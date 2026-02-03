import os
import sys
import ctypes

from chipshouter_profiler.config_classes import GlitchConfig, TargetConfig, SimpleSerialPacket
from chipshouter_profiler.profile_target import CSProfiler

from chipshouter_profiler.simpleserial.simpleserial import TargetSerial
from verification_utils import verify_signature, calculate_oil


def attack_data_handler(profilerSelf, packetSelf, data=None):
    profilerSelf.target_serial.send_ack('d')

    # Receive all chunks of `sm` and join them back together
    while True:
        try:
            cmd, raw_data = profilerSelf.target_serial.read_packet()
        except Exception as e:
            result_category, extradata = profilerSelf.crashHandler()
            return result_category, extradata
        else: # if no exception was raised
            if cmd == profilerSelf.target_serial.type_convert_cmd('d'):
                profilerSelf.target_serial.send_ack(cmd)
                data = data + raw_data # Append to data (type = bytes)
            elif cmd == profilerSelf.target_serial.type_convert_cmd('e'):
                break
            else:
                print(f"ERROR: unexpected packet with command: {cmd}")

    # Parse msg and sig from `sm`
    fields = [
            ("msg", ctypes.c_uint8 * 256), # 256 bytes message
            ("sig", ctypes.c_uint8 * 128), # 128 bytes signature
        ]
    parsed_data = TargetSerial.parse_packet_data_struct(data, fields)

    # print(f"MSG (len={len(parsed_data['msg'])}): {parsed_data['msg']}")
    # print(f"SIG (len={len(parsed_data['sig'])}): {parsed_data['sig'].hex()}")

    result = verify_signature(parsed_data['msg'], parsed_data['sig'])
    if result == 0: # Signature is correct (no fault occurred)
        return "nofaults", parsed_data
    else: # Signature is incorrect (fault occurred)
        profilerSelf.reset_target()
        parsed_data["expected_oil"] = calculate_oil(parsed_data["msg"], parsed_data["sig"])
        parsed_data["actual_oil"] = parsed_data["sig"][:112]
        if parsed_data["expected_oil"] == parsed_data["actual_oil"]: # Signature includes correct oil
            return "detected_oil", parsed_data
        else: # Signature does not include correct oil
            return "faulted_sig", parsed_data

def counter_fault_handler(profilerSelf, packetSelf, data=None):
    profilerSelf.reset_target() # TODO when resetting fails, will faults or bricked be written??

    fields = [
            ("counter", ctypes.c_uint32), # unsigned int counter
        ]

    if data:
        parsed_data = TargetSerial.parse_packet_data_struct(data, fields)
        return "faults", parsed_data
    else:
        return "faults", None


def memcpy_fault_handler(profilerSelf, packetSelf, data=None):
    profilerSelf.reset_target() # TODO when resetting fails, will faults or bricked be written??

    fields = [
            ("target_buffer", ctypes.c_uint8 * 68), # 68 bytes memcpy target buffer
        ]

    parsed_data = TargetSerial.parse_packet_data_struct(data, fields)

    return "faults", parsed_data

def get_raster_positions(origin, dim_x, dim_y, stepsize_x, stepsize_y):
    """
    Rasterize a rectangle of dimensions (dim_x, dim_y) with stepsizes (stepsize_x, stepsize_y).
    Starting at origin, returned positions are absolute. Z axis stays fixed at value from origin.

    Returns:
        List: List of positions [x, y, z]
    """

    # Generate coordinate lists for x and y
    x_coords = [origin[0] + x * stepsize_x for x in range(int(dim_x / stepsize_x) + 1)]
    y_coords = [origin[1] + y * stepsize_y for y in range(int(dim_y / stepsize_y) + 1)]

    # Create grid positions
    positions = [
        [x, y, origin[2]]  # Constant z-value
        for x in x_coords
        for y in y_coords
    ]

    return positions

def main():
    # ---------------------------------------------------------------------------- #
    #                             Commandline Arguments                            #
    # ---------------------------------------------------------------------------- #
    build = False
    flash = False
    home = False
    mode = "profile-attack-complete"
    if len(sys.argv) > 1:
        # Build firmware (based on target_config)
        if "--build" in sys.argv or "-b" in sys.argv:
            build = True
        # Flash chipwhisperer on commandline argument
        if "--flash" in sys.argv or "-f" in sys.argv:
            flash = True
        # Home xyz table on commandline argument
        if "--home" in sys.argv or "-h" in sys.argv:
            home = True

        if "--profile-counter" in sys.argv:
            mode = "profile-counter"
        if "--profile-memcpy" in sys.argv:
            mode = "profile-memcpy"
        if "--profile-attack-memcpy" in sys.argv:
            mode = "profile-attack-memcpy"
        if "--profile-attack-complete" in sys.argv:
            mode = "profile-attack-complete"
    # ---------------------------------------------------------------------------- #
    #                             Target Configuration                             #
    # ---------------------------------------------------------------------------- #
    current_dir = os.path.dirname(os.path.abspath(__file__))
    target_config = TargetConfig(
        firmware_build_dir = os.path.join(current_dir),
        firmware_build_command = ["make", f"target-{mode}"], # [] to prevent auto building
        firmware_path = os.path.join(current_dir, f"pqm4/bin/crypto_sign_target-{mode}.hex")
    )

    # ---------------------------------------------------------------------------- #
    #                            Positions Configuration                           #
    # ---------------------------------------------------------------------------- #
    positions = []
    if mode == "profile-counter":
        origin = [25.075, 2.331, 15.59] # x,y,z orgin
        dim_x = 6
        dim_y = 6
        stepsize_x = 1
        stepsize_y = 1
        positions = get_raster_positions(origin, dim_x, dim_y, stepsize_x, stepsize_y)

    elif mode == "profile-memcpy" or "profile-attack-memcpy" or "profile-attack-complete":
        positions = [[25.075, 3.331, 15.59]] # alternative Z=15.48 (slightly higher for less crashes)

    # ---------------------------------------------------------------------------- #
    #                             Glitch Configurations                            #
    # ---------------------------------------------------------------------------- #
    glitch_configs = []

    if mode == "profile-counter":
        # One position found for instruction skipping) -> [[25.075, 3.331, 15.59]]
        # Vary offset in range of one target clock cycle (7.37 MHz -> 135.7ns per cylce)
        for offset in range(1000, 1140, 10):
            for voltage in [400, 350, 300]:
                for pulse_width in [45, 50, 55, 60, 70]:
                    glitch_configs.extend([
                        GlitchConfig(
                            probe = "4mm CW",
                            voltage = voltage,
                            pulse_width = pulse_width,
                            pulse_spacing = 50,
                            pulse_repeats = 0,
                            pulse_offset = offset,
                            num_executions = 5,
                            dead_timeout = 1000,
                        ),
                    ])

    elif mode == "profile-memcpy":
        for offset in range(14900, 22500, 10):
            glitch_configs.extend([
                GlitchConfig(
                    probe = "4mm CW",
                    voltage = 300,
                    pulse_width = 70,
                    pulse_spacing = 50,
                    pulse_repeats = 0,
                    pulse_offset = offset,
                    num_executions = 5,
                    dead_timeout = 1000,
                ),
            ])

    elif mode == "profile-attack-memcpy":
        for offset in range(14900, 16400, 10):
            glitch_configs.extend([
                GlitchConfig(
                    probe = "4mm CW",
                    voltage = 300,
                    pulse_width = 70,
                    pulse_spacing = 50,
                    pulse_repeats = 0,
                    pulse_offset = offset,
                    num_executions = 5,
                    dead_timeout = 1000,
                ),
            ])

    elif mode == "profile-attack-complete":
        # -------------------------- First chip (STM32F415) -------------------------- #
        # for offset in range(358984345, 358985345, 10):
        for offset in [358985195]:
        # for offset in [358984420]:
            glitch_configs.extend([
                GlitchConfig(
                    probe = "4mm CW",
                    voltage = 300,
                    pulse_width = 70,
                    pulse_spacing = 50,
                    pulse_repeats = 0,
                    pulse_offset = offset,
                    num_executions = 500,
                    dead_timeout = 1000,
                ),
            ])
            
            
            
        # ----------------------------- Transfer step 1: ----------------------------- #
        # positions = [[25.075, 3.331, 15.59]]
        # for offset in range(358984400, 358984500, 10):
        #     glitch_configs.extend([
        #         GlitchConfig(
        #             probe = "4mm CW",
        #             voltage = 300,
        #             pulse_width = 70,
        #             pulse_spacing = 50,
        #             pulse_repeats = 0,
        #             pulse_offset = offset,
        #             num_executions = 100,
        #             dead_timeout = 1000,
        #         ),
        #     ])

         # ------------------------------ Transfer step 2 ----------------------------- #
        # origin = [24.575, 2.831, 15.59] # x,y,z orgin
        # dim_x = 1
        # dim_y = 1
        # stepsize_x = 0.5
        # stepsize_y = 0.5
        # positions = get_raster_positions(origin, dim_x, dim_y, stepsize_x, stepsize_y)

        # for offset in range(358984400, 358984500, 10):
        #     glitch_configs.extend([
        #         GlitchConfig(
        #             probe = "4mm CW",
        #             voltage = 300,
        #             pulse_width = 70,
        #             pulse_spacing = 50,
        #             pulse_repeats = 0,
        #             pulse_offset = offset,
        #             num_executions = 20,
        #             dead_timeout = 1000,
        #         ),
        #     ])

        # ---------------------------- Transfer Validation --------------------------- #
        # positions = [[24.575, 3.831, 15.59]]
        # for offset in range(358984430, 358984450, 10):
        #     glitch_configs.extend([
        #         GlitchConfig(
        #             probe = "4mm CW",
        #             voltage = 300,
        #             pulse_width = 70,
        #             pulse_spacing = 50,
        #             pulse_repeats = 0,
        #             pulse_offset = offset,
        #             num_executions = 20,
        #             dead_timeout = 1000,
        #         ),
        #     ])

    # ---------------------------------------------------------------------------- #
    #                        Create and configure CSProfiler                       #
    # ---------------------------------------------------------------------------- #
    profiler = CSProfiler(target_config, positions, glitch_configs)
    # Profile-counter fault signal. Contains the faulted counter value. Sent only when target detects that counter is not as expected.
    profiler.addSimpleSerialCommand(SimpleSerialPacket("f", "Fault signal from target with buffer content (fault)", counter_fault_handler), overwrite=True)
    # Profile-memcpy fault signal. Contains the faulted memcpy buffer (68 bytes). Sent only when target detects that buffer is not as expected.
    profiler.addSimpleSerialCommand(SimpleSerialPacket("q", "Fault signal from target with buffer content (fault)", memcpy_fault_handler), overwrite=True)
    # Attack data signal. Contains sm (signature and message). Sent after every signature generation
    profiler.addSimpleSerialCommand(SimpleSerialPacket("d", "Data from target (signature and message), split up in 190 byte chunks", attack_data_handler), overwrite=True)

    profiler.addResultType("faulted_sig", "Faulted Signature")
    profiler.addResultType("detected_oil", "Detected valid OIL")

    # ---------------------------------------------------------------------------- #
    #                            Run CSProfiler Campaign                           #
    # ---------------------------------------------------------------------------- #
    profiler.run_campaign(build, flash, home)

if __name__ == "__main__":
    main()