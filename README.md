# Volatoo release engineering

Release definitions and orchestration for producing verifiable Volatoo images.

## Owns

- versioned release compositions and supported target matrices;
- reproducible raw-disk, ISO, PXE, and cloud-image build orchestration;
- SBOM, checksum, provenance, signature-request, and publication gates;
- release promotion, rollback, retention, and mirror metadata.

Release images, kernels, packages, signatures, and SBOMs are published as
artifacts, never committed to Git. Private signing keys never enter this
repository.

## Migration gate

Release-specific code currently remains in `Volatoo/Volatoo`. Move it here only
after its input/output contract is versioned and the main repository can test
against a pinned releng revision without duplicating build logic.

## Release index v1

The first migrated contract is the signed installer release index. The
network-disabled packager verifies both compressed image round trips, creates
one content-addressed object tree, emits timestamped and channel index paths,
signs the exact index bytes with an operator-supplied OpenBSD signify key and
verifies the result before publication:

```sh
scripts/package-index-docker.sh \
  --build-id 20260815T000000Z \
  --channel v0.1-dev \
  --sequence 1 \
  --published-at 2026-08-15T00:00:00Z \
  --expires-at 2026-08-22T00:00:00Z \
  --openrc-archive /path/openrc.img.zst \
  --openrc-manifest /path/openrc.img.manifest \
  --systemd-archive /path/systemd.img.zst \
  --systemd-manifest /path/systemd.img.manifest \
  --installer /path/volatoo-installer-amd64 \
  --installer-version 0.1.0-dev \
  --signing-key /secure/release.sec \
  --public-key /secure/release.pub \
  out/publication
```

The publication also contains a separately signed live-media-inputs v1
document. It binds the exact static amd64 installer executable and release
public key to content-addressed objects, and binds them to the exact release
index digest, channel, and build ID. Live-root construction and QA can consume
the same immutable inputs without trusting repository paths or accepting a
mix of independently valid documents from different releases.

The wrapper refuses Docker contexts other than `orbstack`. Private key bytes
are mounted read-only into the network-disabled signing container and are
never copied to the publication tree.

## Live-media release signature

After constructing the reproducible ISO, sign a canonical release descriptor
that binds its exact bytes and build manifest back to the signed release index
and live-media inputs:

```sh
scripts/sign-live-media-docker.sh \
  --build-id 20260815T000000Z \
  --channel v0.1-dev \
  --init-system openrc \
  --iso /path/volatoo-live-openrc.iso \
  --manifest /path/volatoo-live-openrc.iso.manifest \
  --publication /path/releng-publication \
  --signing-key /secure/release.sec \
  --public-key /secure/release.pub \
  out/live-media-release
```

The network-disabled signer re-verifies the index and live-input signatures,
their exact binding, the ISO manifest and the complete ISO digest before
emitting signed `live-media.json`. This second-stage signature avoids a
circular dependency: the first-stage publication is embedded in the ISO, then
the final ISO bytes are authenticated for distribution.
