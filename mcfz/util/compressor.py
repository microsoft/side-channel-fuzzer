"""
File: Utility module responsible for compressing and decompressing trace files.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import Literal, get_args, cast, assert_never
from subprocess import run

from ..config import Config

_Tool = Literal["gzip", "bzip2", "none"]


class Compressor:
    """
    A simple utility class to encapsulate compression and decompression commands
    based on the specified tool in the configuration.
    """

    def __init__(self, config: Config) -> None:
        tool = config.compression_tool
        assert tool in get_args(_Tool), f"Unsupported compression tool: {tool}"
        self._tool: _Tool = cast(_Tool, tool)

        self._compress_cmd = self._build_compress_cmd()
        self._decompress_cmd = self._build_decompress_cmd()

    def _build_compress_cmd(self) -> str:
        if self._tool == "gzip":
            return "gzip -9 {file}"
        if self._tool == "bzip2":
            return "bzip2 -z -9 {file}"
        if self._tool == "none":
            return ""
        assert_never(self._tool)

    def _build_decompress_cmd(self) -> str:
        if self._tool == "gzip":
            return "gzip -d {file}.gz"
        if self._tool == "bzip2":
            return "bzip2 -d {file}.bz2"
        if self._tool == "none":
            return ""
        assert_never(self._tool)

    def compress(self, file_path: str) -> None:
        if self._tool == "none":
            return
        cmd = self._compress_cmd.format(file=file_path)
        run(cmd, shell=True, check=True)

    def decompress(self, file_path: str) -> None:
        if self._tool == "none":
            return
        cmd = self._decompress_cmd.format(file=file_path)
        run(cmd, shell=True, check=True)

    def decompress_universal(self, file_path: str, keep: bool = False) -> None:
        """
        Decompress a file regardless of its compression type based on its extension.
        Supported extensions: .gz (gzip), .bz2 (bzip2)
        """
        keep_flag = "-k" if keep else ""

        if file_path.endswith(".gz"):
            cmd = f"gzip {keep_flag} -d {file_path}"
            run(cmd, shell=True, check=True)
        elif file_path.endswith(".bz2"):
            cmd = f"bzip2 {keep_flag} -d {file_path}"
            run(cmd, shell=True, check=True)
        else:
            # No known compression extension; assume uncompressed
            return
