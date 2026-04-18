class Relay < Formula
  desc "Self-hostable tunneling — open public URLs for local services over QUIC"
  homepage "https://withrelay.dev"
  version "0.0.12"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  url "https://github.com/afomera/relay/releases/download/v0.0.12/relay-v0.0.12-aarch64-apple-darwin.tar.gz"
  sha256 "6ad3cf63101cee5f49b37473fc1443148457bacb0de511952ae7f1dd0856ff52"

  def install
    bin.install "relay"
  end

  test do
    assert_match "relay", shell_output("#{bin}/relay --version")
  end
end
