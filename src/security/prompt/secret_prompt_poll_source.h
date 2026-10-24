#pragma once

#include "app/poll_source.h"
#include "security/prompt/secret_prompt_service.h"

class SecretPromptPollSource final : public PollSource {
public:
  explicit SecretPromptPollSource(SecretPromptService& service) : m_service(service) {}

  [[nodiscard]] int pollTimeoutMs() const override { return m_service.pollTimeoutMs(); }

  void dispatch(const std::vector<pollfd>& fds, std::size_t startIdx) override { m_service.dispatch(fds, startIdx); }

protected:
  void doAddPollFds(std::vector<pollfd>& fds) override { m_service.addPollFds(fds); }

private:
  SecretPromptService& m_service;
};
