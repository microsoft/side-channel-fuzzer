"""
File: Module responsible for generation of secret (private) inputs for the target binary.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Final

import os

if TYPE_CHECKING:
    from .config import Config

CONF_SIZE: Final[int] = 0x10  # Size of the config data in bytes


class SecGen:
    """
    Class responsible for generating secret (private) inputs for the target binary.
    """

    def __init__(self, config: Config) -> None:
        self._config = config

    def _generate_from_reference(self, wd: str, reference_input: str, num_sec_inputs: int) -> int:
        """
        Given a reference input, generate mode inputs that will contain the same public data,
        but the secret (private) data will be randomly generated
        (though the size of the secret data will be the same).

        The input file contains three sections: config data, public data, and private data.
        * The config data is always 16 bytes long, and it should be copied from the reference input.
          The first byte of the config data is a ratio of public to private data, and it thus
          determines the layout of the remaining data.
          E.g., if the value of the first config byte is 1 and the file size is 1040 bytes, then
          data_size = 1040 - 16 = 1024 bytes, which is split into public and private data
          priv_size = (1 / 256) * 1024 = 4 bytes, and
          pub_size = (255 / 256) * 1024 = 1020 bytes.
        * The private data has size priv_size. This is the region that will be randomized.
        * The public data has size pub_size. This region will be copied from the
          reference input.
        :param reference_input: Path to the reference input file
        :param num_sec_inputs: Number of secret (private) inputs to generate
        :return: 0 if successful, 1 if the reference input is invalid or an error occurs
        """
        # Read the reference input to determine the sizes of public and private data
        with open(reference_input, 'rb') as f:
            ref_data = f.read()

        if len(ref_data) < CONF_SIZE + 2:  # Public and private data must be present
            return 1

        data_size = len(ref_data) - CONF_SIZE
        priv_size = (ref_data[0] * data_size) // 256
        pub_size = data_size - priv_size
        if len(ref_data) < (CONF_SIZE + pub_size):
            return 1

        # Copy the reference input to the working directory
        new_ref_name = os.path.join(wd, "000.bin")
        with open(new_ref_name, 'wb') as dest_file:
            dest_file.write(ref_data)

        # Generate the secret inputs
        config_data = ref_data[:CONF_SIZE]
        pub_data = ref_data[CONF_SIZE + priv_size:CONF_SIZE + priv_size + pub_size]
        for i in range(1, num_sec_inputs):
            priv_data = os.urandom(priv_size)
            dest_path = os.path.join(wd, f"{i:03}.bin")
            with open(dest_path, 'wb') as dest_file:
                dest_file.write(config_data + pub_data + priv_data)

        return 0

    def generate(self, num_sec_inputs: int) -> int:
        """
        Generate public-equivalent inputs for each reference input generated on Stage 1 by AFL++.
        The inputs will contain the same public data, but the secret (private) data will be
        randomly generated (though the size of the secret data will be the same).
        The inputs will be stored in the stage 2 working directory.
        :param num_sec_inputs: Number of secret (private) inputs to generate for each reference
        :return: 0 if successful, 1 if an error occurs
        :raises FileNotFoundError: If the AFL++ working directory does not exist
        :raises OSError: If there is an error creating directories or files
        """

        afl_dir = self._config.stage1_wd + "/default/queue/"
        ref_inputs = [f for f in os.listdir(afl_dir) if os.path.isfile(os.path.join(afl_dir, f))]
        for ref_input in ref_inputs:
            # Create a directory for each reference input
            ref_input_path = os.path.join(afl_dir, ref_input)
            dest_dir = os.path.join(self._config.stage2_wd, ref_input)
            os.makedirs(dest_dir, exist_ok=True)

            # Try generating more public-equivalent inputs from the reference input
            if self._generate_from_reference(dest_dir, ref_input_path, num_sec_inputs) == 0:
                continue

            # If we failed, remove the directory
            os.rmdir(dest_dir)

        return 0
