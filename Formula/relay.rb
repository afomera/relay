class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.13"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.13/relay-v0.0.13-aarch64-apple-darwin.tar.gz"
  sha256 "855cb8f47927b73c88ded3d4bd3d40e8f7f8e488308f162d32e2b58b9ebb062b"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
