class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.1"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.1/relay-v0.0.1-aarch64-apple-darwin.tar.gz"
  sha256 "be2900673b5661c3d6134b55588e6f7bc3a7b1a4d88b80c79350d66ef66d3609"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
