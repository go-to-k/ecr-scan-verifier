FROM public.ecr.aws/amazonlinux/amazonlinux:2023 AS builder

RUN dnf install -y cpio && dnf clean all

# Notation CLI + AWS Signer plugin (rpm2cpio for cross-arch build)
RUN curl -sLo /tmp/signer.rpm \
    "https://d2hvyiie56hcat.cloudfront.net/linux/arm64/installer/latest/aws-signer-notation-cli_arm64.rpm" \
    && cd / && rpm2cpio /tmp/signer.rpm | cpio -idm

# Cosign for ARM64 (Sigstore)
ARG COSIGN_VERSION=2.4.1
RUN curl -sLo /tmp/cosign \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-arm64" \
    && chmod +x /tmp/cosign

FROM public.ecr.aws/lambda/nodejs:22-arm64

# Notation
COPY --from=builder /usr/bin/notation /var/task/bin/notation
COPY --from=builder /root/.config/notation/plugins /var/task/notation-config/plugins
COPY --from=builder /root/.config/notation/truststore /var/task/notation-config/truststore

# Cosign
COPY --from=builder /tmp/cosign /var/task/bin/cosign

# Lambda handler
COPY dist/index.js ${LAMBDA_TASK_ROOT}/index.js

CMD ["index.handler"]
