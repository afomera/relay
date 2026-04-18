class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.3"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.3/relay-v0.0.3-aarch64-apple-darwin.tar.gz"
  sha256 "5c26d9de5e41e084881bebad764c590d7e5d601603e5fe237de22e1b7ed689a9"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
