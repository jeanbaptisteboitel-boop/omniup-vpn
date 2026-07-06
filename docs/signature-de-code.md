# Signature de code (macOS et Windows)

Les binaires des releases ne sont pas signés pour l'instant : macOS
(Gatekeeper) et Windows (SmartScreen) affichent donc un avertissement à la
première exécution. Ce document décrit quoi acquérir et quoi fournir pour
activer la signature automatique dans le workflow de release.

## macOS — signature + notarisation

Prérequis : un compte [Apple Developer](https://developer.apple.com)
(~99 $/an).

1. **Certificat « Developer ID Application »** — dans le portail
   développeur : Certificates → « Developer ID Application ». L'exporter
   avec sa clé privée au format `.p12` (via le Trousseau d'un Mac, ou
   `rcodesign generate-certificate-signing-request` sans Mac).
2. **Clé d'API App Store Connect** — App Store Connect → Utilisateurs et
   accès → Clés d'API → rôle « Developer ». Récupérer le fichier `.p8`,
   le *Key ID* et l'*Issuer ID*. C'est ce qui permet la notarisation en
   CI sans identifiant Apple.
3. **Secrets GitHub** à créer sur le dépôt (Settings → Secrets → Actions) :
   - `APPLE_P12_BASE64` : le `.p12` encodé en base64
   - `APPLE_P12_PASSWORD` : son mot de passe
   - `APPLE_API_KEY_P8` : contenu du `.p8`
   - `APPLE_API_KEY_ID`, `APPLE_API_ISSUER_ID`

La signature et la notarisation se font avec
[`rcodesign`](https://github.com/indygreg/apple-platform-rs) directement
sur le runner Linux (pas besoin de runner macOS) :

```sh
rcodesign sign --p12-file cert.p12 --p12-password … \
  --code-signature-flags runtime dist/omnid-darwin-arm64
rcodesign notary-submit --api-key-file … --wait dist/omnid-darwin-arm64
```

Une fois les secrets en place, l'étape s'ajoute au job `binaries` de
`.github/workflows/release.yml`, conditionnée à la présence des secrets
(les releases restent possibles sans).

## Windows

Depuis 2023, les certificats de signature Windows exigent un stockage
matériel (token/HSM), ce qui a renchéri l'offre classique. Options par
coût croissant :

| Option | Coût indicatif | Notes |
|---|---|---|
| SignPath.io (open source) | gratuit | Dépôt public requis, candidature auprès de la fondation ; signature intégrée à la CI |
| Certum Open Source | ~70 €/an + lecteur ~40 € | Le classique des développeurs OSS ; signature locale par carte |
| Azure Trusted Signing | ~10 $/mois | Signature via API en CI, validation d'identité Microsoft |
| OV/EV classique (Sectigo…) | 200–500 €/an | EV = réputation SmartScreen immédiate |

Selon l'option retenue, la signature de `omnid-windows-amd64.exe` se fait
soit en CI (SignPath, Azure — secrets d'API), soit localement avant
d'attacher le binaire à la release (Certum — `signtool sign /fd SHA256 …`
sur une machine Windows avec la carte).

## Linux

Pas de mécanisme équivalent : les `SHA256SUMS` publiés avec chaque release
font foi. (Optionnel à terme : signature GPG des sommes et dépôt apt/rpm
signé.)
