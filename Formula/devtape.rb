class Devtape < Formula
  desc "Reference CLI for the DevTape Protocol (DTP v0.1) — record, scrub, rewind, and inspect terminal & AI-agent sessions"
  homepage "https://sayyidsh.github.io/devtape/"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/sayyidsh/devtape/releases/download/v0.1.0/devtape"
      sha256 "c80cfe84871710074e6d9b1cc849ed4ff14737cf37e9a2cb67e9ba033fc0ec49"
    else
      url "https://github.com/sayyidsh/devtape/archive/refs/tags/v0.1.0.tar.gz"
      depends_on "rust" => :build
    end
  end

  on_linux do
    url "https://github.com/sayyidsh/devtape/archive/refs/tags/v0.1.0.tar.gz"
    depends_on "rust" => :build
  end

  def install
    if build.with?("rust") || !OS.mac? || !Hardware::CPU.arm?
      system "cargo", "install", *std_cargo_args(path: "crates/devtape-cli")
    else
      bin.install "devtape"
    end
  end

  test do
    system "#{bin}/devtape", "doctor"
  end
end
