class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.16"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.16/relay-v0.0.16-aarch64-apple-darwin.tar.gz"
  sha256 "622dcff3e668ef6146c63ecc1cc6b04ab177829658e9698ad068e3f29361c317"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
