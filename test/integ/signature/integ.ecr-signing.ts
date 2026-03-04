import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { App, Stack } from 'aws-cdk-lib';
import { Repository } from 'aws-cdk-lib/aws-ecr';
import { EcrScanVerifier, ScanConfig, SignatureVerification } from '../../../src';

/**
 * Integration test for ECR managed signing (signing-configuration feature).
 *
 * This test verifies images that have been automatically signed by ECR's
 * managed signing feature using AWS Signer and Notation.
 *
 * Prerequisites:
 *   1. Manually push a signed image with tag 'latest' to the test repository
 *      'ecr-scan-verifier-integ-ecr-signing'
 *      (see test/integ/README.md for full setup and docker push instructions)
 *
 *   2. Image must be signed via ECR managed signing (not manual notation sign)
 *
 *   3. AWS Signer signing profile 'EcrScanVerifierTest' must exist
 *
 * Run:
 *   pnpm integ:signature:update --language javascript --test-regex integ.ecr-signing.js
 *
 * Note: This test requires manual image push because ECR managed signing only
 * works with direct docker push operations, not with ECRDeployment or CDK assets.
 */

const app = new App();
const stack = new Stack(app, 'EcrSigningStack');

// Reference the existing repository (created via CLI with signing-configuration enabled)
const repository = Repository.fromRepositoryName(
  stack,
  'TestRepository',
  'ecr-scan-verifier-integ-ecr-signing',
);

// Use CFn pseudo parameters to build signing profile ARN (avoids hardcoding account ID)
const signingProfileArn = `arn:aws:signer:${stack.region}:${stack.account}:/signing-profiles/EcrScanVerifierTest`;

new EcrScanVerifier(stack, 'Scanner', {
  repository: repository,
  imageTag: 'latest',
  scanConfig: ScanConfig.signatureOnly(),
  signatureVerification: SignatureVerification.notation({
    trustedIdentities: [signingProfileArn],
  }),
});

new IntegTest(app, 'EcrSigningTest', {
  testCases: [stack],
  diffAssets: true,
  stackUpdateWorkflow: false,
});
