#pragma once
#include <hdfs.h>
#include <string>
#include <stdexcept>
#include <cstring>
#include <bits/stdc++.h>

class HDFSWriter {
    hdfsFS fs;
    hdfsFile file;
    static constexpr size_t BUF_SIZE = 256 * 1024; // 256 KB buffer
    std::vector<char> buf;
    size_t bufPos = 0;

public:
    HDFSWriter(const std::string& path) {
        struct hdfsBuilder* builder = hdfsNewBuilder();
        hdfsBuilderSetNameNode(builder, "default");
        fs = hdfsBuilderConnect(builder);
        file = hdfsOpenFile(fs, path.c_str(), O_WRONLY | O_CREAT, 0, 0, 0);
        buf.resize(BUF_SIZE);
    }

    void write(const void* data, size_t len) {
        const char* src = reinterpret_cast<const char*>(data);
        while (len > 0) {
            size_t space = BUF_SIZE - bufPos;
            size_t chunk = std::min(len, space);
            memcpy(buf.data() + bufPos, src, chunk);
            bufPos += chunk;
            src += chunk;
            len -= chunk;
            if (bufPos == BUF_SIZE) {
                flushBuf();
            }
        }
    }

    template<typename T>
    void write(const T& val) {
        write(&val, sizeof(val));
    }

    void flushBuf() {
        if (bufPos == 0) {
            return;
        }
        hdfsWrite(fs, file, buf.data(), bufPos);
        bufPos = 0;
    }

    void flush() {
        flushBuf();
        hdfsFlush(fs, file);
    }

    ~HDFSWriter() {
        flushBuf();
        hdfsFlush(fs, file);
        hdfsCloseFile(fs, file);
        hdfsDisconnect(fs);
    }
};

class HDFSReader {
    hdfsFS fs;
    hdfsFile file;
    static constexpr size_t BUF_SIZE = 256 * 1024; // 256 KB buffer
    std::vector<char> buf;
    size_t bufPos = 0, bufLen = 0;

public:
    HDFSReader(const std::string& path) {
        struct hdfsBuilder* builder = hdfsNewBuilder();
        hdfsBuilderSetNameNode(builder, "default");
        fs = hdfsBuilderConnect(builder);
        file = hdfsOpenFile(fs, path.c_str(), O_RDONLY, 0, 0, 0);
        buf.resize(BUF_SIZE);
    }

    void read(void* out, size_t len) {
        char* dst = reinterpret_cast<char*>(out);
        while (len > 0) {
            if (bufPos == bufLen) {
                fillBuf();
            }
            size_t avail = bufLen - bufPos;
            size_t chunk = std::min(len, avail);
            memcpy(dst, buf.data() + bufPos, chunk);
            bufPos += chunk;
            dst += chunk;
            len -= chunk;
        }
    }

    template<typename T>
    void read(T& val) { 
        read(&val, sizeof(val)); 
    }

    bool eof() { 
        if (bufPos < bufLen) {
            return false;
        }
        fillBuf();
        return bufLen == 0;
    }

private:
    void fillBuf() {
        tSize n = hdfsRead(fs, file, buf.data(), BUF_SIZE);
        bufPos = 0;
        bufLen = (n > 0) ? n : 0;
    }

public:
    ~HDFSReader() {
        hdfsCloseFile(fs, file);
        hdfsDisconnect(fs);
    }
};