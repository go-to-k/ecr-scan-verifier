import { Arn, ArnFormat, Stack } from 'aws-cdk-lib';
import { IGrantable, PolicyStatement, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { SbomFormat } from './types';

/**
 * Output of SbomOutput.bind().
 */
export interface SbomOutputConfig {
  /**
   * The SBOM format.
   */
  readonly format: SbomFormat;

  /**
   * The S3 bucket name for SBOM output.
   */
  readonly bucketName: string;

  /**
   * Optional prefix for S3 objects.
   */
  readonly prefix?: string;

  /**
   * The KMS key ARN for encrypting SBOM output in S3.
   */
  readonly kmsKeyArn: string;
}

/**
 * Properties for SBOM output.
 */
export interface SbomOutputProps {
  /**
   * The S3 bucket to output SBOM.
   *
   * The bucket is used as the destination for Amazon Inspector's
   * CreateSbomExport API and for storing the final SBOM file.
   */
  readonly bucket: IBucket;

  /**
   * Optional prefix for S3 objects.
   *
   * @default - no prefix
   */
  readonly prefix?: string;

  /**
   * The KMS key used to encrypt the SBOM report in S3.
   *
   * Amazon Inspector's CreateSbomExport API requires a customer managed
   * symmetric encryption KMS key. AWS managed keys are not supported.
   *
   * The construct automatically adds the required key policy for
   * the `inspector2.amazonaws.com` service principal.
   */
  readonly encryptionKey: IKey;
}

/**
 * Configuration for SBOM (Software Bill of Materials) output.
 *
 * SBOM export is only available with Enhanced scanning (Amazon Inspector).
 * Uses the Inspector CreateSbomExport API to generate SBOM and uploads it to S3.
 *
 * **Note**: Using with Basic scanning will throw an error.
 */
export abstract class SbomOutput {
  /**
   * Output SBOM in CycloneDX 1.4 JSON format.
   */
  public static cycloneDx14(props: SbomOutputProps): SbomOutput {
    return new SbomOutputImpl(props, SbomFormat.CYCLONEDX_1_4);
  }

  /**
   * Output SBOM in SPDX 2.3 JSON format.
   */
  public static spdx23(props: SbomOutputProps): SbomOutput {
    return new SbomOutputImpl(props, SbomFormat.SPDX_2_3);
  }

  /**
   * Returns the SBOM output configuration.
   */
  public abstract bind(grantee: IGrantable): SbomOutputConfig;
}

class SbomOutputImpl extends SbomOutput {
  private readonly bucket: IBucket;
  private readonly prefix?: string;
  private readonly encryptionKey: IKey;
  private readonly format: SbomFormat;

  constructor(props: SbomOutputProps, format: SbomFormat) {
    super();
    this.bucket = props.bucket;
    this.prefix = props.prefix;
    this.encryptionKey = props.encryptionKey;
    this.format = format;
  }

  public bind(grantee: IGrantable): SbomOutputConfig {
    this.bucket.grantReadWrite(grantee);

    const stack = Stack.of(this.bucket);
    const account = stack.account;
    const reportArn = Arn.format(
      {
        service: 'inspector2',
        resource: 'report',
        resourceName: '*',
        arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
      },
      stack,
    );

    // Inspector2 CreateSbomExport writes SBOM directly to the S3 bucket.
    // The service needs a bucket policy to allow PutObject.
    this.bucket.addToResourcePolicy(
      new PolicyStatement({
        actions: ['s3:PutObject', 's3:AbortMultipartUpload'],
        principals: [new ServicePrincipal('inspector2.amazonaws.com')],
        resources: [this.bucket.arnForObjects('*')],
        conditions: {
          StringEquals: {
            'aws:SourceAccount': account,
          },
          ArnLike: {
            'aws:SourceArn': reportArn,
          },
        },
      }),
    );

    // Inspector2 needs kms:Decrypt and kms:GenerateDataKey* to encrypt the SBOM report.
    this.encryptionKey.addToResourcePolicy(
      new PolicyStatement({
        actions: ['kms:Decrypt', 'kms:GenerateDataKey*'],
        principals: [new ServicePrincipal('inspector2.amazonaws.com')],
        resources: ['*'],
        conditions: {
          StringEquals: {
            'aws:SourceAccount': account,
          },
          ArnLike: {
            'aws:SourceArn': reportArn,
          },
        },
      }),
    );

    // Lambda needs to decrypt the SBOM to download it from S3.
    this.encryptionKey.grantDecrypt(grantee);

    return {
      format: this.format,
      bucketName: this.bucket.bucketName,
      prefix: this.prefix,
      kmsKeyArn: this.encryptionKey.keyArn,
    };
  }
}
