///
/// File: A buffer that gets automatically spilled to a file when it becomes too big
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "dr_api.h"
#include "dr_tools.h"

#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>

const size_t DEFAULT_FILE_BUFFER_SIZE = 8 * 1024 * 1024; // 8 MB


/// @brief A buffer backed by a file: once the buffer reaches a given threshold, it gets
/// automatically spilled into the backing file. Entries can only be appended to the buffer.
/// @tparam T All entries pushed to the buffer have this type.
/// @tparam BufSize Threshold for the buffer (the actual size might be slightly smaller due to
///         imperfect alignment with respect to sizeof(T)).
template <typename T, unsigned BufSize = DEFAULT_FILE_BUFFER_SIZE> class FileBackedBuf
{
  private:
    static constexpr const unsigned max_elems = BufSize / sizeof(T);
    unsigned n_elems = 0;
    std::array<T, max_elems> buf;
    std::ofstream stream;
    std::string filename;

    const bool print;

  public:
    FileBackedBuf(bool print) : print(print) {}
    ~FileBackedBuf()
    {
        if (stream.is_open())
            stream.close();
    }
    FileBackedBuf(const FileBackedBuf &) = delete;
    FileBackedBuf(FileBackedBuf &&) = delete;
    FileBackedBuf &operator=(const FileBackedBuf &other) = delete;
    FileBackedBuf &operator=(FileBackedBuf &&other) = delete;

    /// @brief Open the backing ostream and print the header
    /// @param filename Path of backing file
    void open(const std::string &filename_)
    {
        if (stream.is_open())
            return;

        // Open the backing stream
        filename = filename_;
        stream.open(filename_, std::ios::binary | std::ios::out);

        // Write header so that the parser knows which type of trace we are generating
        char marker = T::marker;
        stream.write(&marker, 1);

        // pad the header to 8 bytes for readability
        const char padding[7] = {0, 0, 0, 0, 0, 0, 0}; // NOLINT
        stream.write(padding, 7);                      // NOLINT
    }

    /// @brief Flush the current buffer contents into the backing file
    /// TODO: this could be made asynchronous
    void flush()
    {
        uint32_t n_bytes = n_elems * sizeof(T);
        stream.write(reinterpret_cast<const char *>(buf.data()), n_bytes);
        n_elems = 0;
    }

    /// @brief Append an element to the buffer
    /// @param elem The element to add
    void push_back(const T &elem)
    {
        buf[n_elems] = elem;
        n_elems++;

        if (print) {
            const std::string entry_str;
            std::stringstream entry_stream(entry_str);
            elem.dump(entry_stream);
            dr_printf("%s", entry_stream.str().c_str());
        }

        if (n_elems == max_elems)
            flush();
    }

    /// @brief Close the backing ostream
    void clear()
    {
        if (not stream.is_open())
            return;

        flush();
        stream.close();
    }

    /// @brief Get the name of the backing file
    const std::string &get_filename() const { return filename; }
};
