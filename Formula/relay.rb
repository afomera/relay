class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.19"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.19/relay-v0.0.19-aarch64-apple-darwin.tar.gz"
  sha256 "e347411b11d1057441c33160da1b9f63fe0734d6808b780d5b133b2c1ccb66e5"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
