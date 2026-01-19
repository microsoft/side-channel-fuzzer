# Install

See https://microsoft.github.io/side-channel-fuzzer/quick-start/ or `README.md` in the project root.

# Using the executor

Use the Revizor CLI (`revizor.py`).
This executor is not meant to be used standalone.

On your own peril, you could try using it directly, through the `/sys/rvzr_executor/` pseudo file system.
You can find an example of how to use it in `rvzr/tests/x86_tests/kernel_module.bats`.
But I promise you, there will come a point when your machine will crash or hang.
Better not.
