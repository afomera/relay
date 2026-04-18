class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.8"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.8/relay-v0.0.8-aarch64-apple-darwin.tar.gz"
  sha256 "ddd087707022f2befad8fd7b2793d5a1106ad1ce2e5c189b2fb6f689edafa172"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
