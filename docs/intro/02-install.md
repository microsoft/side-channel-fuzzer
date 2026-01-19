# Installation

**Warning**:
Revizor runs randomly-generated code in kernel space.
This means that a misconfiguration (or a bug) can crash the system and potentially lead to data loss.
Make sure you're not running Revizor on a production machine, and that you have a backup of your data.

### 1. Requirements

**Hardware**: x86-64 or ARM64 CPU. Specifically:

* All Intel and AMD x86-64 CPUs are supported.
* Some ARM CPUs are also supported, namely Microsoft Cobalt and Raspberry Pi. Other ARM CPUs may work, but are not officially supported.

**No virtualization**:
You will need a bare-metal OS installation.
Testing from inside a VM is not supported.

**OS**: The target machine has to be running Linux v4.15 or later.

### 2. Python Package

The preferred installation method is using `pip` within a virtual environment.
The python version must be 3.9 or later.

```bash
sudo apt install python3.9 python3.9-venv
/usr/bin/python3.9 -m pip install virtualenv
/usr/bin/python3.9 -m virtualenv ~/venv-revizor
source ~/venv-revizor/bin/activate
pip install revizor-fuzzer
```

### 3. Executor

In addition to the Python package, you will need to build and install the executor, which is a kernel module.

```bash
# building a kernel module require kernel headers
sudo apt-get install linux-headers-$(uname -r) linux-headers-generic

# get the source code
git clone https://github.com/microsoft/side-channel-fuzzer.git

# build executor
cd side-channel-fuzzer/rvzr/executor_km
make uninstall  # the command will give an error message, but it's ok!
make clean
make
make install
```

### 4. (Optional) DynamoRIO Backend

If you want to use the DynamoRIO-based model, it has to be installed separately:

```bash
# install dependencies
sudo apt-get install cmake g++ g++-multilib doxygen git zlib1g-dev libunwind-dev libsnappy-dev liblz4-dev

# install DynamoRIO and the model
make -C rvzr/model_dynamorio

# check installation
~/.local/dynamorio/drrun -c ~/.local/dynamorio/libdr_model.so --list-tracers -- ls
# expected output:
#   ct
#   ...
#   /dev/null
```

### 5. Download ISA spec

```bash
rvzr download_spec -a x86-64 --extensions ALL_SUPPORTED --outfile base.json

# Alternatively, use the following command to include system instructions;
# however, mind that testing these instructions may crash the system if misconfigured!
# rvzr download_spec -a x86-64 --extensions ALL_AND_UNSAFE --outfile base.json
```

### 6. Test the Installation

To make sure that the installation was successful, run the following command:

```bash
./tests/quick-test.sh

# The expected output is:
Detection: OK
Filtering: OK
```

If you see any other output, check if the previous steps were executed correctly.
If you still have issues, please [open an issue](https://github.com/microsoft/side-channel-fuzzer/issues).


### 7. (Optional) System Configuration

External processes can interfere with Revizor's measurements.
To minimize this interference, we recommend the following system configuration:

* Disable Hyperthreading (BIOS option);
* Disable Turbo Boost (BIOS option);
* Boot the kernel on a single core (add `-maxcpus=1` to [Linux boot parameters]((https://wiki.ubuntu.com/Kernel/KernelBootParameters))).

If you skip these steps, Revizor may produce false positives, especially if you use a low value for [`executor_sample_sizes`](../ref/config.md#executor-configuration) for measurements.
However, a large sample size (> 300-400) usually mitigates this issue.
