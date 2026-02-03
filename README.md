# Oil, Vinegar, and Sparks: Key Recovery from UOV via Single Electromagnetic Fault Injection

This repository contains auxiliary material for the paper: ["Oil, Vinegar, and Sparks: Key Recovery from UOV via Single Electromagnetic Fault Injection"](https://eprint.iacr.org/2026/154).


Authors:
- Fabio Campos, Darmstadt University of Applied Sciences, Germany
- Daniel Hahn, RheinMain University of Applied Sciences Wiesbaden, Germany
- Daniel Könnecke, RheinMain University of Applied Sciences Wiesbaden, Germany
- Marc Stöttinger, RheinMain University of Applied Sciences Wiesbaden, Germany




## Overview
This repository contains the code to perform a single-fault attack on the pqm4 UOV-Ip implementation.

Using electromagnetic fault injection we skip a single branch instruction, preventing a memcpy operation from executing. Consequently, the oil and vinegar components are not mixed as intended, which can lead to leakage of an oil vector into the generated signature. This oil vector can subsequently be used to recover the private key.


For a detailed description of the profiling and attack phases, please read the [paper](https://eprint.iacr.org/2026/154).



### Test Setup
Our test setup uses the following hardware:
- ChipWhisperer STM32F405 / STM32F415 target
- CW308 UFO base board
- ChipWhisperer-Lite (CW1173) for target flashing and resetting
- ChipSHOUTER (NAE-CW520)
- Raspberry Pi Pico (RP2040) as [Pulse Generator](https://github.com/danielh186/Pico-Pulse-Generator)
- XYZ stage from Thorlabs linear actuators and KDC101 controllers

### Scripts

- **`create_symlink.sh`**: Symlink files from `pqov_additional_files` and `pqm4_additional_files` into `pqov` and `pqm4` submodules.
- **`profile_target.py`**: Profiling script to determine the individual fault injection parameters for the target hardware.
- **`attack_target.py`**: Run fault injection attack on unmodified pqm4 reference implementation. Calculates oil vector candidates and prints them to stdout.
- **`simulate_attack_target.py`**: Simulate successful fault injections on x86 to generate oil vectors. Prints oil vectors to stdout.
- **`reconciliation.py`**: Kipnis-Shamir and reconciliation step for private key recovery from single oil vector.
- **`verifiaction_utils.py`**: Utilities used by profile_target and attack_target scipts for verification of signatures and oil candidates.

### Results
The test results referenced in the paper can be found as json files in the `results/` directory.
The `plot-paper-figures.ipynb` jupyter notebook contains the scripts to generate the illustrations inside the paper.


## Script Usage
### Setup
```bash
# Initialize submodules
git submodule update --init --recursive

# Modify some files in submodules via symlinking
./create_symlink.sh

# Initialize venv and install requirements
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

# Build shared libs required for usage of pqov functions in python scripts
make shared_libs 
```

### Profiling
```
python3 profile_target.py -h -f -b --profile-counter
python3 profile_target.py -h -f -b --profile-memcpy
python3 profile_target.py -h -f -b --profile-attack-memcpy
python3 profile_target.py -h -f -b --profile-attack-complete

# -h: home xyz stage
# -b: build target firmware
# -f: flash target
```
- Stores results as json in `results/` directory

### Attack
```
python3 attack_target.py -h -f -b
```
- Prints oil vector candidates as hexdump on stdout.

### Simulate Attack
```
python3 simulate_attack_target.py
```
- Prints oil vectors as hexdump on stdout.

### Kipnis-Shamir and reconciliation step
```
sage -python attack_UOV.py --pk keys/pk.h --oil <OIL_VECTOR_AS_HEX_VALUES>
```
- Requires **python** >= 3.8.x, **sagemath** >= 9.0, and **numpy** >= 1.17.4.
- Recovers second oil vector by Kipnis Shamir and performs reconciliation step

# LICENSES
Code in this repository **that does not indicate otherwise** is placed under the terms of the license specified in `LICENSE.txt`.
