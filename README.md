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
