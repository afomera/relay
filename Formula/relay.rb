class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.2"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.2/relay-v0.0.2-aarch64-apple-darwin.tar.gz"
  sha256 "cff7b1e6378282df25fee06eae1ef8d5ac964674cede7208bbbe1661688d0c23"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
