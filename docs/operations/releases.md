# Verifying a release

Releases are built by GitHub Actions from a `v*` tag and signed without a
long-lived key (Sigstore keyless signing): the signature proves the files were
produced by this repository's release workflow.

Binaries: `checksums.txt` lists every archive and SBOM; its signature is
`checksums.txt.sigstore.json`.

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/iamsuriyan/doorkeep/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

Container image:

```sh
cosign verify ghcr.io/iamsuriyan/doorkeep:<version> \
  --certificate-identity-regexp '^https://github.com/iamsuriyan/doorkeep/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each archive has an SPDX software bill of materials next to it
(`<archive>.sbom.json`). npm packages are published with provenance
(`npm audit signatures`). Dependencies are kept current by Dependabot
(`.github/dependabot.yml`).
