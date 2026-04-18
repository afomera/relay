class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.5"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.5/relay-v0.0.5-aarch64-apple-darwin.tar.gz"
  sha256 "49609b7d4174b755addb9cf76aebfe12a993938829f5239d83080cc5b9f4d743"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
