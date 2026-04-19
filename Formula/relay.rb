class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.17"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.17/relay-v0.0.17-aarch64-apple-darwin.tar.gz"
  sha256 "a5b78ca8086d4bda4576146e1270ab2411d6127ac7c0b89a26f06c271be992c0"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
