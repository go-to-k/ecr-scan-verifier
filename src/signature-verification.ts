import { IGrantable } from 'aws-cdk-lib/aws-iam';
import { IKey } from 'aws-cdk-lib/aws-kms';

/**
 * Common options for signature verification.
 */
export interface VerificationOptions {
  /**
   * Whether to fail the deployment if the image is unsigned or signature verification fails.
   *
   * @default true
   */
  readonly failOnUnsigned?: boolean;
}

/**
 * Options for Notation (AWS Signer) signature verification.
 */
export interface NotationVerificationOptions extends VerificationOptions {
  /**
   * Trusted signing profile ARNs.
   *
   * At least one signing profile ARN must be specified.
   *
   * @example ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/MyProfile']
   */
  readonly trustedIdentities: string[];
}

/**
 * Options for Cosign signature verification using a public key.
 *
 * **Note on Rekor Transparency Log:**
 * This implementation skips Rekor transparency log verification and verifies only
 * the cryptographic signature using the public key.
 * The Lambda function always uses the `--insecure-ignore-tlog` flag when running cosign verify.
 *
 * @see https://docs.sigstore.dev/cosign/key_management/overview/
 */
export interface CosignPublicKeyVerificationOptions extends VerificationOptions {
  /**
   * The PEM-encoded public key content used to verify the image signature.
   *
   * @example '-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----'
   */
  readonly publicKey: string;
}

/**
 * Options for Cosign signature verification using an AWS KMS key.
 *
 * **Note on Rekor Transparency Log:**
 * This implementation skips Rekor transparency log verification and verifies only
 * the cryptographic signature using the KMS key.
 * The Lambda function always uses the `--insecure-ignore-tlog` flag when running cosign verify.
 *
 * @see https://docs.sigstore.dev/cosign/key_management/overview/
 */
export interface CosignKmsVerificationOptions extends VerificationOptions {
  /**
   * AWS KMS key used to verify the image signature.
   */
  readonly key: IKey;
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
   */
  public static notation(options: NotationVerificationOptions): SignatureVerification {
    return new NotationSignatureVerification(options);
  }

  /**
   * Verify image signature using Cosign with a public key.
   *
   * **Important:** Cosign verification skips Rekor transparency log verification.
   *
   * Sign your images with:
   * ```bash
   * cosign sign --tlog-upload=false --key cosign.pub IMAGE
   * ```
   */
  public static cosignPublicKey(
    options: CosignPublicKeyVerificationOptions,
  ): SignatureVerification {
    return new CosignPublicKeySignatureVerification(options);
  }

  /**
   * Verify image signature using Cosign with an AWS KMS key.
   *
   * **Important:** Cosign verification skips Rekor transparency log verification.
   *
   * Sign your images with:
   * ```bash
   * cosign sign --tlog-upload=false --key awskms:///KMS_KEY_ARN IMAGE
   * ```
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

  constructor(options: CosignPublicKeyVerificationOptions) {
    super();

    this.publicKey = options.publicKey;
    this.failOnUnsigned = options.failOnUnsigned ?? true;
  }

  public bind(_grantee: IGrantable): SignatureVerificationBindOutput {
    return {
      type: 'COSIGN',
      publicKey: this.publicKey,
      failOnUnsigned: this.failOnUnsigned,
    };
  }
}

class CosignKmsSignatureVerification extends SignatureVerification {
  private readonly key: IKey;
  private readonly failOnUnsigned: boolean;

  constructor(options: CosignKmsVerificationOptions) {
    super();

    this.key = options.key;
    this.failOnUnsigned = options.failOnUnsigned ?? true;
  }

  public bind(grantee: IGrantable): SignatureVerificationBindOutput {
    this.key.grant(grantee, 'kms:DescribeKey', 'kms:GetPublicKey', 'kms:Verify');

    return {
      type: 'COSIGN',
      kmsKeyArn: this.key.keyArn,
      failOnUnsigned: this.failOnUnsigned,
    };
  }
}
