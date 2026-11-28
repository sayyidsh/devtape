class Devtape < Formula
  desc "Record, scrub, rewind, and inspect terminal and AI-agent sessions"
  homepage "https://sayyidsh.github.io/devtape/"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/sayyidsh/devtape/releases/download/v0.4.7/devtape-aarch64-apple-darwin.tar.gz"
      sha256 "4519419055bc88a2fdc55606375739c0038ed2f991b77c6e5370fa71e6a156ee"
    end
    on_intel do
      url "https://github.com/sayyidsh/devtape/releases/download/v0.4.7/devtape-x86_64-apple-darwin.tar.gz"
      sha256 "e7694b4da85f610f134031010ede66369bca132fae5b528615bac19459dabb32"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/sayyidsh/devtape/releases/download/v0.4.7/devtape-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "cdd69149b061fa113c6cb984c1bf9062884d99bafb8cabab54cf11fa8400dc9c"
    end
  end

  def install
    bin.install "devtape"
  end

  test do
    system bin/"devtape", "doctor"
  end
end
