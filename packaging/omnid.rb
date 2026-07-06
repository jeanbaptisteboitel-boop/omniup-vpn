# Formule Homebrew de l'agent OmniUp VPN (macOS).
#
#   brew install jeanbaptisteboitel-boop/omniup/omnid
#
# Les champs sha256/url sont mis à jour automatiquement à chaque release
# (voir .github/workflows/release.yml, étape Homebrew).
class Omnid < Formula
  desc "Agent OmniUp VPN — réseau mesh WireGuard auto-hébergé"
  homepage "https://github.com/jeanbaptisteboitel-boop/omniup-vpn"
  version "0.0.0"
  license "MIT"

  on_arm do
    url "https://github.com/jeanbaptisteboitel-boop/omniup-vpn/releases/download/v#{version}/omnid-darwin-arm64"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end
  on_intel do
    url "https://github.com/jeanbaptisteboitel-boop/omniup-vpn/releases/download/v#{version}/omnid-darwin-amd64"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  def install
    bin.install Dir["omnid-darwin-*"].first => "omnid"
  end

  def caveats
    <<~EOS
      omnid nécessite root pour créer l'interface réseau :
        sudo omnid up --server https://vpn.omniup.fr --auth-key omkey-…

      Pour le démarrage automatique, préférez le script d'installation qui
      pose un LaunchDaemon :
        curl -fsSL https://raw.githubusercontent.com/jeanbaptisteboitel-boop/omniup-vpn/main/scripts/install-omnid-macos.sh | sudo sh -s -- --server … --auth-key …
    EOS
  end

  test do
    assert_match "v#{version}", shell_output("#{bin}/omnid version")
  end
end
