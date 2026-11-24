class Devtape < Formula
  desc "Reference CLI for the DevTape Protocol (DTP v0.1) — record, scrub, rewind, and inspect terminal & AI-agent sessions"
  homepage "https://sayyidsh.github.io/devtape/"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/sayyidsh/devtape/releases/download/v0.1.0/devtape-aarch64-apple-darwin.tar.gz"
      sha256 "a7b56f8c5cccbb9294c2abcc1f8785ac2a2e27b181741685d739d7b077552319"
    else
      url "https://github.com/sayyidsh/devtape/releases/download/v0.1.0/devtape-x86_64-apple-darwin.tar.gz"
      sha256 "b17cc86958162e243a56d7ce2d535d9af61e1515bbf5a5570fe2e9caf469cf03"
    end
  end

  on_linux do
    url "https://github.com/sayyidsh/devtape/releases/download/v0.1.0/devtape-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "9e6ced23f1cfac4b9e9c8321f729570e3ca4f771668bcf4520b8e5ae06213d4b"
  end

  def install
    bin.install "devtape"
  end

  test do
    system "#{bin}/devtape", "doctor"
  end
end
