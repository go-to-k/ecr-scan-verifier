FROM public.ecr.aws/amazonlinux/amazonlinux:2023 AS builder

# Notation CLI + AWS Signer plugin
RUN curl -sLo /tmp/signer.rpm \
    "https://d2hvyiie56hcat.cloudfront.net/linux/arm64/installer/rpm/latest/aws-signer-notation-cli_arm64.rpm" \
    && rpm -ivh /tmp/signer.rpm && rm /tmp/signer.rpm

# Cosign for ARM64 (Sigstore)
ARG COSIGN_VERSION=3.0.5
RUN curl -sLo /tmp/cosign \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-arm64" \
    && chmod +x /tmp/cosign

FROM public.ecr.aws/lambda/nodejs:24-arm64

# Notation binary
COPY --from=builder /usr/local/bin/notation /var/task/bin/notation

# Notation plugin (must be at plugins/<plugin-name>/<binary>)
COPY --from=builder \
    /opt/com.amazonaws.signer.notation.installer.rpm/notation_libexec/notation-com.amazonaws.signer.notation.plugin \
    /var/task/notation-config/plugins/com.amazonaws.signer.notation.plugin/notation-com.amazonaws.signer.notation.plugin

# Notation trust store (must be at truststore/x509/signingAuthority/<store-name>/<certs>)
# Commercial regions
COPY --from=builder \
    /opt/com.amazonaws.signer.notation.installer.rpm/notation_config/aws-signer-notation-root.crt \
    /var/task/notation-config/truststore/x509/signingAuthority/aws-signer-ts/aws-signer-notation-root.crt
# GovCloud regions
COPY --from=builder \
    /opt/com.amazonaws.signer.notation.installer.rpm/notation_config/aws-us-gov-signer-notation-root.crt \
    /var/task/notation-config/truststore/x509/signingAuthority/aws-us-gov-signer-ts/aws-us-gov-signer-notation-root.crt

# Fix permissions (RPM installs with root-only 700/600 permissions)
# Lambda base image doesn't have 'find', so use chmod -R and then fix executables
RUN chmod -R 755 /var/task/notation-config && \
    chmod 644 /var/task/notation-config/truststore/x509/signingAuthority/aws-signer-ts/*.crt && \
    chmod 644 /var/task/notation-config/truststore/x509/signingAuthority/aws-us-gov-signer-ts/*.crt && \
    chmod +x /var/task/bin/notation && \
    chmod +x /var/task/notation-config/plugins/com.amazonaws.signer.notation.plugin/notation-com.amazonaws.signer.notation.plugin

# Cosign
COPY --from=builder /tmp/cosign /var/task/bin/cosign
RUN chmod +x /var/task/bin/cosign

# Lambda handler
COPY dist/index.js ${LAMBDA_TASK_ROOT}/index.js

CMD ["index.handler"]
