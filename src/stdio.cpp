// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/stdio.hpp>

#include "catalog_internal.hpp"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility>

#if defined(__unix__) || defined(__APPLE__)
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

namespace passmcp {

struct StdioTransport::Impl {
    virtual ~Impl() = default;
    virtual std::string send(const std::string& raw_json) = 0;
    virtual void close() = 0;
};

namespace {

bool expects_reply(const std::string& raw_json) {
    try {
        JsonValue parsed = JsonValue::parse(raw_json);
        return !parsed.is_object() || parsed.contains("id");
    } catch (const std::exception&) {
        return true;
    }
}

void validate_single_line(const std::string& raw_json) {
    if (raw_json.find('\n') != std::string::npos || raw_json.find('\r') != std::string::npos) {
        throw std::invalid_argument("Stdio JSON-RPC frame must be a single line");
    }
}

class InMemoryStdioImpl final : public StdioTransport::Impl {
public:
    explicit InMemoryStdioImpl(const McpServer& srv) : server_(&srv) {}

    std::string send(const std::string& raw_json) override {
        if (closed_) throw std::runtime_error("StdioTransport is closed");
        validate_single_line(raw_json);
        std::istringstream in(raw_json + "\n");
        std::ostringstream out;
        serve_stdio(*server_, in, out);
        if (!expects_reply(raw_json)) return "";
        std::string line = out.str();
        if (!line.empty() && line.back() == '\n') line.pop_back();
        return line;
    }

    void close() override { closed_ = true; }

private:
    const McpServer* server_;
    bool closed_ = false;
};

class StreamPairStdioImpl final : public StdioTransport::Impl {
public:
    StreamPairStdioImpl(std::istream& in, std::ostream& out) : in_(&in), out_(&out) {}

    std::string send(const std::string& raw_json) override {
        if (closed_) throw std::runtime_error("StdioTransport is closed");
        validate_single_line(raw_json);
        (*out_) << raw_json << '\n';
        out_->flush();
        if (!expects_reply(raw_json)) return "";
        std::string line;
        if (!std::getline(*in_, line)) {
            throw std::runtime_error("Unexpected EOF on stdio stream transport");
        }
        if (!line.empty() && line.back() == '\r') line.pop_back();
        return line;
    }

    void close() override { closed_ = true; }

private:
    std::istream* in_;
    std::ostream* out_;
    bool closed_ = false;
};

#if defined(__unix__) || defined(__APPLE__)
void write_all_fd(int fd, const char* data, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        ssize_t n = ::write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("Failed writing to child stdio pipe");
        }
        off += static_cast<std::size_t>(n);
    }
}

[[noreturn]] void exec_child(int stdin_r, int stdin_w, int stdout_r, int stdout_w,
                             const std::vector<std::string>& command) {
    (void)::dup2(stdin_r, STDIN_FILENO);
    (void)::dup2(stdout_w, STDOUT_FILENO);
    int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        (void)::dup2(devnull, STDERR_FILENO);
        ::close(devnull);
    }
    ::close(stdin_r);
    ::close(stdin_w);
    ::close(stdout_r);
    ::close(stdout_w);
    std::vector<std::string> copy = command;
    std::vector<char*> argv;
    argv.reserve(copy.size() + 1);
    for (auto& arg : copy) argv.push_back(arg.data());
    argv.push_back(nullptr);
    ::execvp(argv[0], argv.data());
    _exit(127);
}

class ChildProcessStdioImpl final : public StdioTransport::Impl {
public:
    ChildProcessStdioImpl(pid_t pid, int write_fd, int read_fd)
        : pid_(pid), write_fd_(write_fd), read_fd_(read_fd) {}

    ~ChildProcessStdioImpl() override { close(); }

    std::string send(const std::string& raw_json) override {
        if (closed_) throw std::runtime_error("StdioTransport is closed");
        validate_single_line(raw_json);
        std::string frame = raw_json + "\n";
        write_all_fd(write_fd_, frame.data(), frame.size());
        if (!expects_reply(raw_json)) return "";
        return read_line();
    }

    void close() override {
        if (closed_) return;
        closed_ = true;
        if (write_fd_ >= 0) {
            ::close(write_fd_);
            write_fd_ = -1;
        }
        if (read_fd_ >= 0) {
            ::close(read_fd_);
            read_fd_ = -1;
        }
        reap_child();
    }

private:
    std::string read_line() {
        for (;;) {
            auto nl = buf_.find('\n');
            if (nl != std::string::npos) {
                std::string line = buf_.substr(0, nl);
                buf_.erase(0, nl + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                return line;
            }
            char chunk[4096];
            ssize_t n = ::read(read_fd_, chunk, sizeof(chunk));
            if (n < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("Failed reading from child stdio pipe");
            }
            if (n == 0) throw std::runtime_error("Unexpected EOF from child MCP server");
            buf_.append(chunk, static_cast<std::size_t>(n));
        }
    }

    void reap_child() {
        if (pid_ <= 0) return;
        int status = 0;
        for (int attempt = 0; attempt < 50; ++attempt) {
            pid_t r = ::waitpid(pid_, &status, WNOHANG);
            if (r == pid_ || r < 0) {
                pid_ = -1;
                return;
            }
            struct timespec ts { 0, 10'000'000L };
            ::nanosleep(&ts, nullptr);
        }
        (void)::kill(pid_, SIGKILL);
        (void)::waitpid(pid_, &status, 0);
        pid_ = -1;
    }

    pid_t pid_;
    int write_fd_;
    int read_fd_;
    std::string buf_;
    bool closed_ = false;
};
#endif

} // namespace

void serve_stdio(const McpServer& server, std::istream& in, std::ostream& out) {
    std::string line;
    while (std::getline(in, line)) {
        std::string trimmed = detail::trim_ascii(line);
        if (trimmed.empty()) continue;
        std::string reply = server.handle_json(trimmed);
        if (!reply.empty()) {
            out << reply << '\n';
            out.flush();
        }
    }
}

void serve_stdio(const McpServer& server) {
    std::ios::sync_with_stdio(false);
    serve_stdio(server, std::cin, std::cout);
}

StdioTransport::StdioTransport(std::shared_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}

StdioTransport StdioTransport::in_memory(const McpServer& server) {
    return StdioTransport(std::make_shared<InMemoryStdioImpl>(server));
}

StdioTransport StdioTransport::from_streams(std::istream& server_stdout, std::ostream& server_stdin) {
    return StdioTransport(std::make_shared<StreamPairStdioImpl>(server_stdout, server_stdin));
}

StdioTransport StdioTransport::spawn(const std::vector<std::string>& command) {
    if (command.empty() || command.front().empty()) {
        throw std::invalid_argument("Stdio spawn command must not be empty");
    }
#if defined(__unix__) || defined(__APPLE__)
    int in_pipe[2]{-1, -1};
    int out_pipe[2]{-1, -1};
    if (::pipe(in_pipe) != 0) throw std::runtime_error("pipe() failed for child stdin");
    if (::pipe(out_pipe) != 0) {
        ::close(in_pipe[0]);
        ::close(in_pipe[1]);
        throw std::runtime_error("pipe() failed for child stdout");
    }
    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(in_pipe[0]);
        ::close(in_pipe[1]);
        ::close(out_pipe[0]);
        ::close(out_pipe[1]);
        throw std::runtime_error("fork() failed for child MCP server");
    }
    if (pid == 0) {
        exec_child(in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1], command);
    }
    ::close(in_pipe[0]);
    ::close(out_pipe[1]);
    return StdioTransport(std::make_shared<ChildProcessStdioImpl>(pid, in_pipe[1], out_pipe[0]));
#else
    throw std::runtime_error("StdioTransport::spawn requires POSIX pipe/fork support");
#endif
}

std::string StdioTransport::operator()(const std::string& raw_json) const {
    return impl_->send(raw_json);
}

void StdioTransport::close() const {
    if (impl_) impl_->close();
}

} // namespace passmcp
