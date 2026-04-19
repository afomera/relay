class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.15"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.15/relay-v0.0.15-aarch64-apple-darwin.tar.gz"
  sha256 "50521ce96efa50873058c7fd97970500b362b3b13d483d8444df66cb7493a2e4"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
