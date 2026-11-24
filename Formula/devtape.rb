class Devtape < Formula
  desc "Reference CLI for the DevTape Protocol (DTP v0.1) — record, scrub, rewind, and inspect terminal & AI-agent sessions"
  homepage "https://sayyidsh.github.io/devtape/"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/sayyidsh/devtape/releases/download/v0.1.0/devtape-aarch64-apple-darwin.tar.gz"
      sha256 "6b5f8024a1bf7863718d3679e88c21985cc3cf661a99dc6d055b70bfaeaa80e0"
    else
      url "https://github.com/sayyidsh/devtape/releases/download/v0.1.0/devtape-x86_64-apple-darwin.tar.gz"
      sha256 "2f4bb09168bf15d7bc621d47908f90ae071fb2b23bf8d7728b51b7108df52df8"
    end
  end

  on_linux do
    url "https://github.com/sayyidsh/devtape/releases/download/v0.1.0/devtape-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "4bb7cb3fd4eb02f6f07f34517a74d8e5fc7d93007c079438ab68b32a7f906b98"
  end

  def install
    bin.install "devtape"
  end

  test do
    system "#{bin}/devtape", "doctor"
  end
end
