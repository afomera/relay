class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.20"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.20/relay-v0.0.20-aarch64-apple-darwin.tar.gz"
  sha256 "847834d6dff9f234aa46331303da8dd80e37880035561d45029017ccc1bb35a0"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
