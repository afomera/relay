class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.18"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.18/relay-v0.0.18-aarch64-apple-darwin.tar.gz"
  sha256 "b1e3cad64da1cb38b17711eb2c9e7ae9b6df91e3175fd0be55da272a7d10210c"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
