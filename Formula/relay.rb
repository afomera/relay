class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.11"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.11/relay-v0.0.11-aarch64-apple-darwin.tar.gz"
  sha256 "ec38a263f03b27ec92fd162f0cd4d8522461d97ce6531bf0deaf51267c433b07"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
