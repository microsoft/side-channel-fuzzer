"""
File: Module responsible for generation of secret (private) inputs for the target binary.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List

import os
import subprocess

if TYPE_CHECKING:
    from .config import Config


class SecGen:
    """
    Class responsible for generating secret (private) inputs for the target binary.
    """

    def __init__(self, config: Config) -> None:
        self._config = config

    def generate(self, _: List[str], num_sec_inputs: int) -> int:
        """
        Generate secret (private) inputs for the target binary invoked with the given command.

        :param cmd: Command to run the target binary, with placeholders for public (@@)
                    and private (@#) inputs
        :param num_sec_inputs: Number of secret (private) inputs to generate for each public input
        :return: 0 if successful, 1 if error occurs
        """
        # Iterate previously-generated public inputs
        # and generate num_sec_inputs private inputs for each
        pub_dir = self._config.stage1_wd + "/default/queue/"
        pub_inputs = [f for f in os.listdir(pub_dir) if os.path.isfile(os.path.join(pub_dir, f))]
        for pub_input in pub_inputs:
            # Create a directory for each public input
            pub_input_path = os.path.join(pub_dir, pub_input)
            dest_dir = os.path.join(self._config.stage2_wd, pub_input)
            os.makedirs(dest_dir, exist_ok=True)

            # Copy the public input to the destination directory
            subprocess.check_call(['cp', pub_input_path, dest_dir + "/public"])

            # Generate private inputs
            for i in range(num_sec_inputs):
                priv_input_path = os.path.join(dest_dir, f"private_{i}")
                if generate_one_secret(priv_input_path, self._config.secret_size_bytes) != 0:
                    return 1
        return 0


def generate_one_secret(dest: str, size: int) -> int:
    """
    Generate a single secret (private) input for the target binary
    invoked with the given command.

    :param dest: Destination path for the generated private input
    :param size: Size of the private input in bytes
    :return: 0 if successful, 1 if error occurs
    """
    subprocess.check_call(
        ['dd', 'if=/dev/urandom', f'of={dest}', 'bs=1', f'count={size}'],
        stderr=subprocess.DEVNULL,
    )
    return 0
