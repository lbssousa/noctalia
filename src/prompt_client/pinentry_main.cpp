// noctalia-pinentry: gpg-agent's pinentry-program. Relays the Assuan conversation between the
// agent (stdin/stdout) and the Noctalia shell, which draws the prompt. Without a reachable shell
// (TTY, SSH session, Noctalia not running) it execs $NOCTALIA_PINENTRY_FALLBACK with the same
// arguments, e.g. pinentry-curses.

#include "prompt_client/prompt_client.h"
#include "security/prompt/prompt_socket_path.h"

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

  bool writeAll(int fd, const char* data, std::size_t size) {
    while (size > 0) {
      const auto n = ::write(fd, data, size);
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        return false;
      }
      data += n;
      size -= static_cast<std::size_t>(n);
    }
    return true;
  }

  [[noreturn]] void fallback(char** argv) {
    const char* program = std::getenv("NOCTALIA_PINENTRY_FALLBACK");
    if (program != nullptr && program[0] != '\0') {
      argv[0] = const_cast<char*>(program);
      ::execv(program, argv);
      std::fprintf(stderr, "noctalia-pinentry: cannot run %s: %s\n", program, std::strerror(errno));
    } else {
      std::fprintf(stderr, "noctalia-pinentry: Noctalia is not reachable and no fallback is set\n");
    }
    std::_Exit(1);
  }

} // namespace

int main(int /*argc*/, char** argv) {
  std::signal(SIGPIPE, SIG_IGN);

  const int sock = secret_prompt::connectPromptSocket(secret_prompt::kPinentrySocketKind);
  if (sock < 0) {
    fallback(argv);
  }

  pollfd fds[2] = {
      {.fd = STDIN_FILENO, .events = POLLIN, .revents = 0},
      {.fd = sock, .events = POLLIN, .revents = 0},
  };
  char buf[4096];
  while (true) {
    if (::poll(fds, 2, -1) < 0) {
      if (errno == EINTR) {
        continue;
      }
      return 1;
    }
    if (fds[1].revents != 0) {
      const auto n = ::read(sock, buf, sizeof(buf));
      if (n <= 0) {
        // The shell answered BYE or went away.
        return n == 0 ? 0 : 1;
      }
      if (!writeAll(STDOUT_FILENO, buf, static_cast<std::size_t>(n))) {
        return 1;
      }
    }
    if (fds[0].fd >= 0 && fds[0].revents != 0) {
      const auto n = ::read(STDIN_FILENO, buf, sizeof(buf));
      if (n > 0) {
        if (!writeAll(sock, buf, static_cast<std::size_t>(n))) {
          return 1;
        }
      } else if (n == 0 || errno != EINTR) {
        // No more requests; keep reading until the shell answers what is already queued.
        ::shutdown(sock, SHUT_WR);
        fds[0].fd = -1;
      }
    }
  }
}
