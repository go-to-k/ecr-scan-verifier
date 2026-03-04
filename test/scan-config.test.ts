import { Stack } from 'aws-cdk-lib';
import { Key } from 'aws-cdk-lib/aws-kms';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { SbomOutput } from '../src/sbom-output';
import { ScanConfig } from '../src/scan-config';

describe('ScanConfig', () => {
  describe('basic()', () => {
    test('returns BASIC scan type with default startScan=true', () => {
      const config = ScanConfig.basic();
      expect(config.bind()).toEqual({
        scanType: 'BASIC',
        startScan: true,
      });
    });

    test('accepts startScan option', () => {
      const config = ScanConfig.basic({ startScan: false });
      expect(config.bind()).toEqual({
        scanType: 'BASIC',
        startScan: false,
      });
    });
  });

  describe('enhanced()', () => {
    test('returns ENHANCED scan type with startScan=false', () => {
      const config = ScanConfig.enhanced();
      const output = config.bind();
      expect(output.scanType).toBe('ENHANCED');
      expect(output.startScan).toBe(false);
      expect(output.sbomOutput).toBeUndefined();
    });

    test('accepts sbomOutput option', () => {
      const stack = new Stack();
      const bucket = new Bucket(stack, 'Bucket');
      const key = new Key(stack, 'Key');

      const config = ScanConfig.enhanced({
        sbomOutput: SbomOutput.cycloneDx14({ bucket, encryptionKey: key }),
      });

      const output = config.bind();
      expect(output.scanType).toBe('ENHANCED');
      expect(output.startScan).toBe(false);
      expect(output.sbomOutput).toBeDefined();
    });
  });

  describe('signatureOnly()', () => {
    test('returns SIGNATURE_ONLY scan type', () => {
      const config = ScanConfig.signatureOnly();
      expect(config.bind()).toEqual({
        scanType: 'SIGNATURE_ONLY',
        startScan: false,
      });
    });

    test('accepts options parameter', () => {
      const config = ScanConfig.signatureOnly({});
      expect(config.bind().scanType).toBe('SIGNATURE_ONLY');
    });
  });
});
