// noctalia-askpass: SSH_ASKPASS for ssh, ssh-add and git. The prompt comes in argv[1] and
// SSH_ASKPASS_PROMPT selects the kind ("confirm", "none" or a secret). Answers are printed on
// stdout; cancelling exits with status 1. Talks to the Noctalia shell with the same Assuan
// commands a pinentry client would.

#include "prompt_client/prompt_client.h"
#include "security/prompt/assuan_session.h"
#include "security/prompt/prompt_socket_path.h"

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

namespace {

  class LineReader {
  public:
    explicit LineReader(int fd) : m_fd(fd) {}
    ~LineReader() { secret_prompt::wipe(m_buffer); }

    bool next(std::string& line) {
      while (true) {
        if (const auto newline = m_buffer.find('\n'); newline != std::string::npos) {
          line.assign(m_buffer, 0, newline);
          ::explicit_bzero(m_buffer.data(), newline + 1);
          m_buffer.erase(0, newline + 1);
          return true;
        }
        char buf[1024];
        const auto n = ::read(m_fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) {
          continue;
        }
        if (n <= 0) {
          return false;
        }
        m_buffer.append(buf, static_cast<std::size_t>(n));
        ::explicit_bzero(buf, sizeof(buf));
      }
    }

  private:
    int m_fd;
    std::string m_buffer;
  };

  bool sendLine(int fd, const std::string& line) {
    const std::string out = line + "\n";
    std::size_t sent = 0;
    while (sent < out.size()) {
      const auto n = ::write(fd, out.data() + sent, out.size() - sent);
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        return false;
      }
      sent += static_cast<std::size_t>(n);
    }
    return true;
  }

  // Reads one reply: data lines are collected into `data`. True on OK, false on ERR or EOF.
  bool readReply(LineReader& reader, std::string& data) {
    std::string line;
    while (reader.next(line)) {
      if (line.starts_with("D ")) {
        std::string decoded = secret_prompt::percentDecode(std::string_view(line).substr(2));
        data += decoded;
        secret_prompt::wipe(decoded);
        secret_prompt::wipe(line);
        continue;
      }
      if (line == "OK" || line.starts_with("OK ")) {
        return true;
      }
      if (line.starts_with("ERR")) {
        return false;
      }
      // "S" status and "#" comment lines carry nothing for us.
    }
    return false;
  }

} // namespace

int main(int argc, char** argv) {
  std::signal(SIGPIPE, SIG_IGN);
  const std::string prompt = argc > 1 ? argv[1] : "";

  const int sock = secret_prompt::connectPromptSocket(secret_prompt::kAskpassSocketKind);
  if (sock < 0) {
    if (const char* program = std::getenv("NOCTALIA_ASKPASS_FALLBACK"); program != nullptr && program[0] != '\0') {
      argv[0] = const_cast<char*>(program);
      ::execv(program, argv);
      std::fprintf(stderr, "noctalia-askpass: cannot run %s: %s\n", program, std::strerror(errno));
      return 1;
    }
    std::fprintf(stderr, "noctalia-askpass: Noctalia is not reachable\n");
    return 1;
  }

  LineReader reader(sock);
  std::string data;
  if (!readReply(reader, data)) {
    std::fprintf(stderr, "noctalia-askpass: unexpected greeting\n");
    return 1;
  }

  const secret_prompt::AskpassPlan plan = secret_prompt::planAskpass(prompt, std::getenv("SSH_ASKPASS_PROMPT"));
  bool ok = true;
  for (const auto& command : plan.commands) {
    data.clear();
    if (!sendLine(sock, command)) {
      return 1;
    }
    ok = readReply(reader, data);
    if (!ok) {
      break;
    }
  }
  sendLine(sock, "BYE");
  ::close(sock);

  if (!ok) {
    secret_prompt::wipe(data);
    return 1;
  }
  if (plan.mode == secret_prompt::AskpassMode::Secret) {
    data += '\n';
    std::fwrite(data.data(), 1, data.size(), stdout);
    std::fflush(stdout);
    secret_prompt::wipe(data);
  }
  return 0;
}
