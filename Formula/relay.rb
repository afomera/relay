class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.7"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.7/relay-v0.0.7-aarch64-apple-darwin.tar.gz"
  sha256 "bf15eeb8c2b33553051cf2e5743df228f3f14e6e3902ae480d764a27509f88c1"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
