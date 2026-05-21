import { resolve } from 'path';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack } from 'aws-cdk-lib';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { Architecture } from 'aws-cdk-lib/aws-lambda';
import { EcrScanVerifier, ScanConfig } from '../../../src';

/**
 * Integration test for Basic scanning with `Architecture.X86_64` on the verifier Lambda.
 *
 * Mirrors integ.minimal-options.ts but flips the Lambda architecture so that the
 * Dockerfile build args (TARGETARCH=amd64, LAMBDA_ARCH=x86_64), the notation amd64
 * RPM, the cosign amd64 binary, and the `public.ecr.aws/lambda/nodejs:24-x86_64`
 * base image are all exercised end-to-end against real AWS — not just verified
 * via `docker buildx`.
 *
 * The fixture image stays `Platform.LINUX_ARM64` on purpose: the architecture
 * under test here is the verifier Lambda's, not the scanned image's.
 *
 * Prerequisites:
 *   Enhanced scanning (Amazon Inspector) must be DISABLED on the account.
 */

const app = new App();
const stack = new Stack(app, 'X86ArchStack');

const image = new DockerImageAsset(stack, 'DockerImage', {
  directory: resolve(__dirname, '../fixtures/docker-image'),
  platform: Platform.LINUX_ARM64,
});

new EcrScanVerifier(stack, 'Scanner', {
  repository: image.repository,
  imageTag: image.assetHash,
  scanConfig: ScanConfig.basic(),
  architecture: Architecture.X86_64,
});

new IntegTest(app, 'X86ArchTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
