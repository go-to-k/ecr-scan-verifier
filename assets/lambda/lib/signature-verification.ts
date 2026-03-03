import { execFileSync } from 'child_process';
import { mkdirSync, writeFileSync, cpSync } from 'fs';
import { join } from 'path';
import {
  ECRClient,
  DescribeImagesCommand,
  GetAuthorizationTokenCommand,
} from '@aws-sdk/client-ecr';
import { SignatureVerificationConfig } from '../../../src/custom-resource-props';

const ecrClient = new ECRClient();

export interface SignatureVerificationResult {
  readonly verified: boolean;
  readonly message: string;
}

interface EcrAuthInfo {
  readonly endpoint: string;
  readonly username: string;
  readonly password: string;
}

const getImageDigest = async (
  repositoryName: string,
  imageTag: string,
): Promise<string> => {
  if (imageTag.startsWith('sha256:')) {
    return imageTag;
  }

  const response = await ecrClient.send(
    new DescribeImagesCommand({
      repositoryName,
      imageIds: [{ imageTag }],
    }),
  );

  const digest = response.imageDetails?.[0]?.imageDigest;
  if (!digest) {
    throw new Error(`Failed to resolve digest for ${repositoryName}:${imageTag}`);
  }
  return digest;
};

const getEcrAuthInfo = async (): Promise<EcrAuthInfo> => {
  const response = await ecrClient.send(new GetAuthorizationTokenCommand({}));
  const authData = response.authorizationData?.[0];
  if (!authData?.authorizationToken || !authData?.proxyEndpoint) {
    throw new Error('Failed to get ECR authorization token');
  }

  const decoded = Buffer.from(authData.authorizationToken, 'base64').toString();
  const [username, password] = decoded.split(':');
  // proxyEndpoint is like "https://123456789012.dkr.ecr.us-east-1.amazonaws.com"
  const endpoint = authData.proxyEndpoint.replace(/^https?:\/\//, '');

  return { endpoint, username, password };
};

const getRegistryUri = (repositoryName: string, endpoint: string): string => {
  return `${endpoint}/${repositoryName}`;
};

// --- Notation ---

const setupNotationConfig = (trustedIdentities: string[]): string => {
  const configDir = '/tmp/notation-config';
  mkdirSync(configDir, { recursive: true });

  // Copy trust store from bundled assets (plugins stay at NOTATION_LIBEXEC path, no copy needed)
  const bundledConfigDir = join(process.env.LAMBDA_TASK_ROOT ?? '/var/task', 'notation-config');
  cpSync(join(bundledConfigDir, 'truststore'), join(configDir, 'truststore'), { recursive: true });

  // Generate trust policy
  const trustPolicy = {
    version: '1.0',
    trustPolicies: [
      {
        name: 'aws-signer-tp',
        registryScopes: ['*'],
        signatureVerification: {
          level: 'strict',
        },
        trustStores: ['signingAuthority:aws-signer-ts'],
        trustedIdentities: trustedIdentities,
      },
    ],
  };

  mkdirSync(join(configDir, 'trustpolicy'), { recursive: true });
  writeFileSync(
    join(configDir, 'trustpolicy', 'trustpolicy.json'),
    JSON.stringify(trustPolicy, null, 2),
  );

  return configDir;
};

const notationLogin = (
  endpoint: string,
  username: string,
  password: string,
  notationBin: string,
  env: Record<string, string>,
): void => {
  execFileSync(notationBin, ['login', '--username', username, '--password-stdin', endpoint], {
    input: password,
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
};

const notationVerify = (
  imageRef: string,
  notationBin: string,
  env: Record<string, string>,
): void => {
  execFileSync(notationBin, ['verify', imageRef], {
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 120_000,
  });
};

// --- Cosign ---

const cosignLogin = (
  endpoint: string,
  username: string,
  password: string,
  cosignBin: string,
  env: Record<string, string>,
): void => {
  execFileSync(cosignBin, ['login', '--username', username, '--password-stdin', endpoint], {
    input: password,
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
};

const cosignVerify = (
  imageRef: string,
  keyArgs: string[],
  cosignBin: string,
  env: Record<string, string>,
): void => {
  execFileSync(cosignBin, ['verify', ...keyArgs, imageRef], {
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 120_000,
  });
};

// --- Main ---

export const verifySignature = async (
  repositoryName: string,
  imageTag: string,
  config: SignatureVerificationConfig,
): Promise<SignatureVerificationResult> => {
  const failOnUnsigned = config.failOnUnsigned === 'true';

  try {
    const digest = await getImageDigest(repositoryName, imageTag);
    const auth = await getEcrAuthInfo();
    const imageRef = `${getRegistryUri(repositoryName, auth.endpoint)}@${digest}`;
    const binDir = join(process.env.LAMBDA_TASK_ROOT ?? '/var/task', 'bin');

    console.log(`Verifying signature for ${imageRef} (type: ${config.type})`);

    if (config.type === 'NOTATION') {
      const notationBin = join(binDir, 'notation');
      const configDir = setupNotationConfig(config.trustedIdentities!);
      const env: Record<string, string> = {
        NOTATION_CONFIG: configDir,
        NOTATION_LIBEXEC: join(process.env.LAMBDA_TASK_ROOT ?? '/var/task', 'notation-config'),
        PATH: `${binDir}:${process.env.PATH}`,
      };

      notationLogin(auth.endpoint, auth.username, auth.password, notationBin, env);
      notationVerify(imageRef, notationBin, env);
    } else if (config.type === 'COSIGN') {
      const cosignBin = join(binDir, 'cosign');
      const dockerConfigDir = '/tmp/.docker';
      mkdirSync(dockerConfigDir, { recursive: true });
      const env: Record<string, string> = {
        DOCKER_CONFIG: dockerConfigDir,
        PATH: `${binDir}:${process.env.PATH}`,
      };

      cosignLogin(auth.endpoint, auth.username, auth.password, cosignBin, env);

      let keyArgs: string[];
      if (config.kmsKeyArn) {
        keyArgs = ['--key', `awskms:///${config.kmsKeyArn}`];
      } else if (config.publicKey) {
        const keyPath = '/tmp/cosign.pub';
        writeFileSync(keyPath, config.publicKey);
        keyArgs = ['--key', keyPath];
      } else {
        throw new Error('Cosign verification requires either publicKey or kmsKeyArn');
      }

      cosignVerify(imageRef, keyArgs, cosignBin, env);
    } else {
      throw new Error(`Unknown signature verification type: ${config.type}`);
    }

    console.log(`Signature verification succeeded for ${imageRef}`);
    return { verified: true, message: 'Signature verification succeeded' };
  } catch (error: any) {
    const message = `Signature verification failed: ${error.message || error}`;
    console.error(message);

    if (failOnUnsigned) {
      throw new Error(message);
    }

    return { verified: false, message };
  }
};
