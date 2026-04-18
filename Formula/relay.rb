class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.6"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.6/relay-v0.0.6-aarch64-apple-darwin.tar.gz"
  sha256 "1bd7597bc599f588fe9a301481347b518cb2839bc78656be8130287fa473fdf9"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
