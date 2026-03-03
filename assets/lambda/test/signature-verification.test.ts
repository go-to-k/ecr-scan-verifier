import { execFileSync } from 'child_process';
import { mkdirSync, writeFileSync, cpSync } from 'fs';
import {
  ECRClient,
  DescribeImagesCommand,
  GetAuthorizationTokenCommand,
} from '@aws-sdk/client-ecr';
import { mockClient } from 'aws-sdk-client-mock';
import { verifySignature } from '../lib/signature-verification';
import { SignatureVerificationConfig } from '../../../src/custom-resource-props';

jest.mock('child_process', () => ({
  execFileSync: jest.fn(),
}));

jest.mock('fs', () => ({
  mkdirSync: jest.fn(),
  writeFileSync: jest.fn(),
  cpSync: jest.fn(),
}));

const ecrMock = mockClient(ECRClient);

describe('verifySignature', () => {
  const mockDigest = 'sha256:abc123def456';
  const mockAuthToken = Buffer.from('AWS:mock-password').toString('base64');
  const mockEndpoint = 'https://123456789012.dkr.ecr.us-east-1.amazonaws.com';

  beforeEach(() => {
    jest.clearAllMocks();
    ecrMock.reset();
    jest.spyOn(console, 'log').mockImplementation();
    jest.spyOn(console, 'error').mockImplementation();

    process.env.LAMBDA_TASK_ROOT = '/var/task';

    ecrMock.on(DescribeImagesCommand).resolves({
      imageDetails: [{ imageDigest: mockDigest }],
    });

    ecrMock.on(GetAuthorizationTokenCommand).resolves({
      authorizationData: [{
        authorizationToken: mockAuthToken,
        proxyEndpoint: mockEndpoint,
      }],
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
    delete process.env.LAMBDA_TASK_ROOT;
  });

  describe('Docker config', () => {
    test('writes Docker config.json with embedded credentials', async () => {
      (execFileSync as jest.Mock).mockReturnValue(Buffer.from(''));

      const config: SignatureVerificationConfig = {
        type: 'NOTATION',
        trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
        failOnUnsigned: 'true',
      };

      await verifySignature('my-repo', 'v1.0', config);

      expect(mkdirSync).toHaveBeenCalledWith('/tmp/.docker', { recursive: true });
      expect(writeFileSync).toHaveBeenCalledWith(
        '/tmp/.docker/config.json',
        expect.stringContaining('"auths"'),
      );
      // Verify the auth token is base64-encoded username:password
      const configCall = (writeFileSync as jest.Mock).mock.calls.find(
        (call: any[]) => call[0] === '/tmp/.docker/config.json',
      );
      const configJson = JSON.parse(configCall[1]);
      const endpoint = '123456789012.dkr.ecr.us-east-1.amazonaws.com';
      expect(configJson.auths[endpoint].auth).toBe(
        Buffer.from('AWS:mock-password').toString('base64'),
      );
    });
  });

  describe('Notation', () => {
    const notationConfig: SignatureVerificationConfig = {
      type: 'NOTATION',
      trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
      failOnUnsigned: 'true',
    };

    test('verifies signature successfully', async () => {
      (execFileSync as jest.Mock).mockReturnValue(Buffer.from(''));

      const result = await verifySignature('my-repo', 'v1.0', notationConfig);

      expect(result.verified).toBe(true);
      expect(result.message).toContain('succeeded');

      // Only notation verify (no login - credentials via Docker config.json)
      expect(execFileSync).toHaveBeenCalledTimes(1);
      const verifyCall = (execFileSync as jest.Mock).mock.calls[0];
      expect(verifyCall[0]).toContain('notation');
      expect(verifyCall[1]).toContain('verify');
      expect(verifyCall[1][1]).toContain(`@${mockDigest}`);
    });

    test('sets up trust policy with trustedIdentities', async () => {
      (execFileSync as jest.Mock).mockReturnValue(Buffer.from(''));

      await verifySignature('my-repo', 'v1.0', notationConfig);

      // Check that trust policy was written
      expect(writeFileSync).toHaveBeenCalledWith(
        expect.stringContaining('trustpolicy.json'),
        expect.stringContaining('arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'),
      );
    });

    test('copies trust store from bundled assets (plugins stay at NOTATION_LIBEXEC)', async () => {
      (execFileSync as jest.Mock).mockReturnValue(Buffer.from(''));

      await verifySignature('my-repo', 'v1.0', notationConfig);

      // Only trust store is copied to /tmp (plugins accessed via NOTATION_LIBEXEC)
      expect(cpSync).toHaveBeenCalledTimes(1);
      expect(cpSync).toHaveBeenCalledWith(
        expect.stringContaining('notation-config/truststore'),
        expect.stringContaining('/tmp/notation-config/truststore'),
        { recursive: true },
      );
    });

    test('throws error when verification fails and failOnUnsigned is true', async () => {
      (execFileSync as jest.Mock)
        .mockImplementationOnce(() => { throw new Error('signature verification failed'); });

      await expect(verifySignature('my-repo', 'v1.0', notationConfig))
        .rejects.toThrow('Signature verification failed');
    });

    test('returns failed result when failOnUnsigned is false', async () => {
      const config: SignatureVerificationConfig = {
        ...notationConfig,
        failOnUnsigned: 'false',
      };

      (execFileSync as jest.Mock)
        .mockImplementationOnce(() => { throw new Error('signature verification failed'); });

      const result = await verifySignature('my-repo', 'v1.0', config);

      expect(result.verified).toBe(false);
      expect(result.message).toContain('failed');
    });

    test('sets HOME, DOCKER_CONFIG, NOTATION_CONFIG and NOTATION_LIBEXEC environment variables', async () => {
      (execFileSync as jest.Mock).mockReturnValue(Buffer.from(''));

      await verifySignature('my-repo', 'v1.0', notationConfig);

      const verifyCall = (execFileSync as jest.Mock).mock.calls[0];
      const env = verifyCall[2].env;
      expect(env.HOME).toBe('/tmp');
      expect(env.DOCKER_CONFIG).toBe('/tmp/.docker');
      expect(env.NOTATION_CONFIG).toBe('/tmp/notation-config');
      expect(env.NOTATION_LIBEXEC).toBe('/var/task/notation-config');
    });
  });

  describe('Cosign (publicKey)', () => {
    const cosignPublicKeyConfig: SignatureVerificationConfig = {
      type: 'COSIGN',
      publicKey: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
      failOnUnsigned: 'true',
    };

    test('verifies signature successfully', async () => {
      (execFileSync as jest.Mock).mockReturnValue(Buffer.from(''));

      const result = await verifySignature('my-repo', 'v1.0', cosignPublicKeyConfig);

      expect(result.verified).toBe(true);

      // Only cosign verify (no login - credentials via Docker config.json)
      expect(execFileSync).toHaveBeenCalledTimes(1);
      const verifyCall = (execFileSync as jest.Mock).mock.calls[0];
      expect(verifyCall[0]).toContain('cosign');
      expect(verifyCall[1]).toContain('verify');
      expect(verifyCall[1]).toContain('--key');
      expect(verifyCall[1]).toContain('/tmp/cosign.pub');
    });

    test('writes public key to /tmp/cosign.pub', async () => {
      (execFileSync as jest.Mock).mockReturnValue(Buffer.from(''));

      await verifySignature('my-repo', 'v1.0', cosignPublicKeyConfig);

      expect(writeFileSync).toHaveBeenCalledWith(
        '/tmp/cosign.pub',
        '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
      );
    });

    test('sets DOCKER_CONFIG for registry credential access', async () => {
      (execFileSync as jest.Mock).mockReturnValue(Buffer.from(''));

      await verifySignature('my-repo', 'v1.0', cosignPublicKeyConfig);

      const verifyCall = (execFileSync as jest.Mock).mock.calls[0];
      expect(verifyCall[2].env.DOCKER_CONFIG).toBe('/tmp/.docker');
    });

    test('throws error when verification fails and failOnUnsigned is true', async () => {
      (execFileSync as jest.Mock)
        .mockImplementationOnce(() => { throw new Error('no matching signatures'); });

      await expect(verifySignature('my-repo', 'v1.0', cosignPublicKeyConfig))
        .rejects.toThrow('Signature verification failed');
    });

    test('returns failed result when failOnUnsigned is false', async () => {
      const config: SignatureVerificationConfig = {
        ...cosignPublicKeyConfig,
        failOnUnsigned: 'false',
      };

      (execFileSync as jest.Mock)
        .mockImplementationOnce(() => { throw new Error('no matching signatures'); });

      const result = await verifySignature('my-repo', 'v1.0', config);

      expect(result.verified).toBe(false);
    });
  });

  describe('Cosign (KMS)', () => {
    const cosignKmsConfig: SignatureVerificationConfig = {
      type: 'COSIGN',
      kmsKeyArn: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
      failOnUnsigned: 'true',
    };

    test('verifies signature successfully', async () => {
      (execFileSync as jest.Mock).mockReturnValue(Buffer.from(''));

      const result = await verifySignature('my-repo', 'v1.0', cosignKmsConfig);

      expect(result.verified).toBe(true);

      const verifyCall = (execFileSync as jest.Mock).mock.calls[0];
      expect(verifyCall[1]).toContain('--key');
      expect(verifyCall[1]).toContain(
        `awskms:///${cosignKmsConfig.kmsKeyArn}`,
      );
    });

    test('throws error when verification fails and failOnUnsigned is true', async () => {
      (execFileSync as jest.Mock)
        .mockImplementationOnce(() => { throw new Error('no matching signatures'); });

      await expect(verifySignature('my-repo', 'v1.0', cosignKmsConfig))
        .rejects.toThrow('Signature verification failed');
    });

    test('returns failed result when failOnUnsigned is false', async () => {
      const config: SignatureVerificationConfig = {
        ...cosignKmsConfig,
        failOnUnsigned: 'false',
      };

      (execFileSync as jest.Mock)
        .mockImplementationOnce(() => { throw new Error('no matching signatures'); });

      const result = await verifySignature('my-repo', 'v1.0', config);

      expect(result.verified).toBe(false);
    });
  });

  describe('common', () => {
    test('uses digest directly when imageTag starts with sha256:', async () => {
      (execFileSync as jest.Mock).mockReturnValue(Buffer.from(''));

      const config: SignatureVerificationConfig = {
        type: 'NOTATION',
        trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
        failOnUnsigned: 'true',
      };

      await verifySignature('my-repo', 'sha256:directdigest', config);

      // Should NOT call DescribeImages when digest is provided directly
      expect(ecrMock.commandCalls(DescribeImagesCommand)).toHaveLength(0);

      const verifyCall = (execFileSync as jest.Mock).mock.calls[0];
      expect(verifyCall[1][1]).toContain('@sha256:directdigest');
    });

    test('resolves tag to digest via DescribeImages', async () => {
      (execFileSync as jest.Mock).mockReturnValue(Buffer.from(''));

      const config: SignatureVerificationConfig = {
        type: 'NOTATION',
        trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
        failOnUnsigned: 'true',
      };

      await verifySignature('my-repo', 'v1.0', config);

      expect(ecrMock.commandCalls(DescribeImagesCommand)).toHaveLength(1);
      const verifyCall = (execFileSync as jest.Mock).mock.calls[0];
      expect(verifyCall[1][1]).toContain(`@${mockDigest}`);
    });

    test('throws error for unknown verification type', async () => {
      const config: SignatureVerificationConfig = {
        type: 'UNKNOWN',
        failOnUnsigned: 'true',
      };

      await expect(verifySignature('my-repo', 'v1.0', config))
        .rejects.toThrow('Unknown signature verification type: UNKNOWN');
    });

    test('throws error when ECR auth fails', async () => {
      ecrMock.on(GetAuthorizationTokenCommand).rejects(new Error('Auth failed'));

      const config: SignatureVerificationConfig = {
        type: 'NOTATION',
        trustedIdentities: ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile'],
        failOnUnsigned: 'true',
      };

      await expect(verifySignature('my-repo', 'v1.0', config))
        .rejects.toThrow('Signature verification failed');
    });
  });
});
