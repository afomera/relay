class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.14"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.14/relay-v0.0.14-aarch64-apple-darwin.tar.gz"
  sha256 "4650229f24d87c0e172b05b07c528eec233ad8bc09d2bc692911e7ea2ceabe4a"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
