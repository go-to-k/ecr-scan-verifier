import { IGrantable } from 'aws-cdk-lib/aws-iam';
import { IKey } from 'aws-cdk-lib/aws-kms';

/**
 * Options for Notation (AWS Signer) signature verification.
 */
export interface NotationVerificationOptions {
  /**
   * Trusted signing profile ARNs.
   *
   * At least one signing profile ARN must be specified.
   *
   * @example ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile']
   */
  readonly trustedIdentities: string[];

  /**
   * Whether to fail the deployment if the image is unsigned or signature verification fails.
   *
   * @default true
   */
  readonly failOnUnsigned?: boolean;
}

/**
 * Options for Cosign signature verification using a public key.
 */
export interface CosignPublicKeyVerificationOptions {
  /**
   * The PEM-encoded public key content used to verify the image signature.
   *
   * @example '-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----'
   */
  readonly publicKey: string;

  /**
   * Whether to fail the deployment if the image is unsigned or signature verification fails.
   *
   * @default true
   */
  readonly failOnUnsigned?: boolean;

  /**
   * Whether to skip Rekor transparency log verification.
   *
   * When false (default), cosign will verify the signature against the Rekor transparency log,
   * providing additional assurance that the signature was created at a specific time.
   * This requires network access to the Rekor service and TUF metadata initialization.
   *
   * When true, only the cryptographic signature is verified using the public key,
   * skipping Rekor transparency log verification. Use this if:
   * - The image was signed with `cosign sign --tlog-upload=false`
   * - Network access to Rekor is restricted
   * - You prefer faster verification without transparency log overhead
   *
   * @default false - Rekor verification is enabled by default for better security
   */
  readonly ignoreTlog?: boolean;
}

/**
 * Options for Cosign signature verification using an AWS KMS key.
 */
export interface CosignKmsVerificationOptions {
  /**
   * AWS KMS key used to verify the image signature.
   *
   * The Lambda function is automatically granted `kms:GetPublicKey` and `kms:Verify`
   * permissions on this key.
   */
  readonly key: IKey;

  /**
   * Whether to fail the deployment if the image is unsigned or signature verification fails.
   *
   * @default true
   */
  readonly failOnUnsigned?: boolean;

  /**
   * Whether to skip Rekor transparency log verification.
   *
   * When false (default), cosign will verify the signature against the Rekor transparency log,
   * providing additional assurance that the signature was created at a specific time.
   * This requires network access to the Rekor service and TUF metadata initialization.
   *
   * When true, only the cryptographic signature is verified using the KMS key,
   * skipping Rekor transparency log verification. Use this if:
   * - The image was signed with `cosign sign --tlog-upload=false`
   * - Network access to Rekor is restricted
   * - You prefer faster verification without transparency log overhead
   *
   * @default false - Rekor verification is enabled by default for better security
   */
  readonly ignoreTlog?: boolean;
}

/**
 * Output of SignatureVerification.bind().
 */
export interface SignatureVerificationBindOutput {
  /**
   * The verification type.
   */
  readonly type: string;

  /**
   * Trusted signing profile ARNs (Notation only).
   */
  readonly trustedIdentities?: string[];

  /**
   * Public key content (Cosign public key only).
   */
  readonly publicKey?: string;

  /**
   * KMS key ARN (Cosign KMS only).
   */
  readonly kmsKeyArn?: string;

  /**
   * Whether to fail the deployment on unsigned images.
   */
  readonly failOnUnsigned: boolean;

  /**
   * Whether to skip Rekor transparency log verification (Cosign only).
   */
  readonly cosignIgnoreTlog?: boolean;
}

/**
 * Signature verification configuration for container images.
 *
 * Supports Notation (AWS Signer) and Cosign (Sigstore) verification methods.
 * Signature verification is performed before the vulnerability scan during deployment.
 */
export abstract class SignatureVerification {
  /**
   * Verify image signature using Notation (AWS Signer).
   *
   * Requires the image to be signed with AWS Signer.
   * The Lambda function uses the Notation CLI to perform cryptographic verification.
   */
  public static notation(options: NotationVerificationOptions): SignatureVerification {
    return new NotationSignatureVerification(options);
  }

  /**
   * Verify image signature using Cosign with a public key.
   *
   * The public key content is passed to the Lambda function as a Custom Resource property.
   */
  public static cosignPublicKey(
    options: CosignPublicKeyVerificationOptions,
  ): SignatureVerification {
    return new CosignPublicKeySignatureVerification(options);
  }

  /**
   * Verify image signature using Cosign with an AWS KMS key.
   *
   * The Lambda function is automatically granted the required KMS permissions.
   */
  public static cosignKms(options: CosignKmsVerificationOptions): SignatureVerification {
    return new CosignKmsSignatureVerification(options);
  }

  /**
   * Returns the signature verification configuration.
   */
  public abstract bind(grantee: IGrantable): SignatureVerificationBindOutput;
}

class NotationSignatureVerification extends SignatureVerification {
  private readonly trustedIdentities: string[];
  private readonly failOnUnsigned: boolean;

  constructor(options: NotationVerificationOptions) {
    super();

    if (options.trustedIdentities.length === 0) {
      throw new Error('trustedIdentities must contain at least one signing profile ARN.');
    }

    this.trustedIdentities = options.trustedIdentities;
    this.failOnUnsigned = options.failOnUnsigned ?? true;
  }

  public bind(_grantee: IGrantable): SignatureVerificationBindOutput {
    return {
      type: 'NOTATION',
      trustedIdentities: this.trustedIdentities,
      failOnUnsigned: this.failOnUnsigned,
    };
  }
}

class CosignPublicKeySignatureVerification extends SignatureVerification {
  private readonly publicKey: string;
  private readonly failOnUnsigned: boolean;
  private readonly ignoreTlog: boolean;

  constructor(options: CosignPublicKeyVerificationOptions) {
    super();

    this.publicKey = options.publicKey;
    this.failOnUnsigned = options.failOnUnsigned ?? true;
    this.ignoreTlog = options.ignoreTlog ?? false;
  }

  public bind(_grantee: IGrantable): SignatureVerificationBindOutput {
    return {
      type: 'COSIGN',
      publicKey: this.publicKey,
      failOnUnsigned: this.failOnUnsigned,
      cosignIgnoreTlog: this.ignoreTlog,
    };
  }
}

class CosignKmsSignatureVerification extends SignatureVerification {
  private readonly key: IKey;
  private readonly failOnUnsigned: boolean;
  private readonly ignoreTlog: boolean;

  constructor(options: CosignKmsVerificationOptions) {
    super();

    this.key = options.key;
    this.failOnUnsigned = options.failOnUnsigned ?? true;
    this.ignoreTlog = options.ignoreTlog ?? false;
  }

  public bind(grantee: IGrantable): SignatureVerificationBindOutput {
    this.key.grant(grantee, 'kms:DescribeKey', 'kms:GetPublicKey', 'kms:Verify');

    return {
      type: 'COSIGN',
      kmsKeyArn: this.key.keyArn,
      failOnUnsigned: this.failOnUnsigned,
      cosignIgnoreTlog: this.ignoreTlog,
    };
  }
}
