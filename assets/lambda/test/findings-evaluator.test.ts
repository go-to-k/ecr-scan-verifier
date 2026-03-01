import { FindingSeverity, ImageScanFinding } from '@aws-sdk/client-ecr';
import { ScanFindings } from '../lib/ecr-scan';
import { evaluateFindings, formatScanSummary } from '../lib/findings-evaluator';

describe('findings-evaluator', () => {
  const createBasicScanFindings = (
    findings: { name: string; severity: string }[],
  ): ScanFindings => ({
    scanType: 'BASIC',
    status: 'COMPLETE',
    basicFindings: findings.map((f) => ({
      name: f.name,
      severity: f.severity as FindingSeverity,
    })) as ImageScanFinding[],
    enhancedFindings: [],
    severityCounts: findings.reduce(
      (acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    ),
    rawResponse: {
      $metadata: {},
      imageScanFindings: {
        findings: findings.map((f) => ({ name: f.name, severity: f.severity as FindingSeverity })) as ImageScanFinding[],
        findingSeverityCounts: findings.reduce(
          (acc, f) => {
            acc[f.severity] = (acc[f.severity] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>,
        ),
      },
    },
  });

  const createEnhancedScanFindings = (
    findings: { vulnId: string; severity: string; findingArn?: string }[],
  ): ScanFindings => ({
    scanType: 'ENHANCED',
    status: 'ACTIVE',
    basicFindings: [],
    enhancedFindings: findings.map((f) => ({
      severity: f.severity,
      findingArn: f.findingArn || `arn:aws:inspector2:us-east-1:123456789012:finding/${f.vulnId}`,
      packageVulnerabilityDetails: {
        vulnerabilityId: f.vulnId,
      },
    })),
    severityCounts: findings.reduce(
      (acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    ),
    rawResponse: {
      $metadata: {},
      imageScanFindings: {
        enhancedFindings: [],
        findingSeverityCounts: {},
      },
    },
  });

  describe('evaluateFindings', () => {
    describe('basic scan', () => {
      test('should detect vulnerabilities matching severity threshold', () => {
        const scanFindings = createBasicScanFindings([
          { name: 'CVE-2023-0001', severity: 'CRITICAL' },
          { name: 'CVE-2023-0002', severity: 'HIGH' },
        ]);

        const result = evaluateFindings(scanFindings, ['CRITICAL'], []);

        expect(result.hasVulnerabilities).toBe(true);
        expect(result.filteredSeverityCounts).toEqual({ CRITICAL: 1, HIGH: 1 });
      });

      test('should not detect vulnerabilities below threshold', () => {
        const scanFindings = createBasicScanFindings([
          { name: 'CVE-2023-0001', severity: 'LOW' },
          { name: 'CVE-2023-0002', severity: 'MEDIUM' },
        ]);

        const result = evaluateFindings(scanFindings, ['CRITICAL', 'HIGH'], []);

        expect(result.hasVulnerabilities).toBe(false);
      });

      test('should ignore findings by CVE ID', () => {
        const scanFindings = createBasicScanFindings([
          { name: 'CVE-2023-0001', severity: 'CRITICAL' },
          { name: 'CVE-2023-0002', severity: 'CRITICAL' },
        ]);

        const result = evaluateFindings(
          scanFindings,
          ['CRITICAL'],
          ['CVE-2023-0001'],
        );

        expect(result.hasVulnerabilities).toBe(true);
        expect(result.filteredSeverityCounts).toEqual({ CRITICAL: 1 });
      });

      test('should ignore all matching findings', () => {
        const scanFindings = createBasicScanFindings([
          { name: 'CVE-2023-0001', severity: 'CRITICAL' },
        ]);

        const result = evaluateFindings(
          scanFindings,
          ['CRITICAL'],
          ['CVE-2023-0001'],
        );

        expect(result.hasVulnerabilities).toBe(false);
        expect(result.filteredSeverityCounts).toEqual({});
      });

      test('should handle empty findings', () => {
        const scanFindings = createBasicScanFindings([]);

        const result = evaluateFindings(scanFindings, ['CRITICAL'], []);

        expect(result.hasVulnerabilities).toBe(false);
        expect(result.summary).toBe('');
      });

      test('should handle UNDEFINED severity', () => {
        const scanFindings = createBasicScanFindings([
          { name: 'CVE-2023-0001', severity: 'UNDEFINED' },
        ]);

        const result = evaluateFindings(scanFindings, ['UNDEFINED'], []);

        expect(result.hasVulnerabilities).toBe(true);
        expect(result.filteredSeverityCounts).toEqual({ UNDEFINED: 1 });
      });
    });

    describe('enhanced scan', () => {
      test('should detect vulnerabilities matching severity threshold', () => {
        const scanFindings = createEnhancedScanFindings([
          { vulnId: 'CVE-2023-0001', severity: 'CRITICAL' },
        ]);

        const result = evaluateFindings(scanFindings, ['CRITICAL'], []);

        expect(result.hasVulnerabilities).toBe(true);
      });

      test('should ignore findings by vulnerability ID', () => {
        const scanFindings = createEnhancedScanFindings([
          { vulnId: 'CVE-2023-0001', severity: 'CRITICAL' },
          { vulnId: 'CVE-2023-0002', severity: 'CRITICAL' },
        ]);

        const result = evaluateFindings(
          scanFindings,
          ['CRITICAL'],
          ['CVE-2023-0001'],
        );

        expect(result.hasVulnerabilities).toBe(true);
        expect(result.filteredSeverityCounts).toEqual({ CRITICAL: 1 });
      });

      test('should ignore findings by finding ARN', () => {
        const scanFindings = createEnhancedScanFindings([
          {
            vulnId: 'CVE-2023-0001',
            severity: 'CRITICAL',
            findingArn: 'arn:aws:inspector2:us-east-1:123456789012:finding/specific-arn',
          },
        ]);

        const result = evaluateFindings(
          scanFindings,
          ['CRITICAL'],
          ['arn:aws:inspector2:us-east-1:123456789012:finding/specific-arn'],
        );

        expect(result.hasVulnerabilities).toBe(false);
      });

      test('should handle multiple severity levels', () => {
        const scanFindings = createEnhancedScanFindings([
          { vulnId: 'CVE-2023-0001', severity: 'CRITICAL' },
          { vulnId: 'CVE-2023-0002', severity: 'HIGH' },
          { vulnId: 'CVE-2023-0003', severity: 'MEDIUM' },
          { vulnId: 'CVE-2023-0004', severity: 'LOW' },
        ]);

        const result = evaluateFindings(
          scanFindings,
          ['CRITICAL', 'HIGH'],
          [],
        );

        expect(result.hasVulnerabilities).toBe(true);
        expect(result.filteredSeverityCounts).toEqual({
          CRITICAL: 1,
          HIGH: 1,
          MEDIUM: 1,
          LOW: 1,
        });
      });
    });
  });

  describe('formatScanSummary', () => {
    test('should format basic scan summary', () => {
      const scanFindings = createBasicScanFindings([
        { name: 'CVE-2023-0001', severity: 'CRITICAL' },
        { name: 'CVE-2023-0002', severity: 'HIGH' },
      ]);
      const evaluation = {
        hasVulnerabilities: true,
        summary: 'CRITICAL: 1, HIGH: 1',
        filteredSeverityCounts: { CRITICAL: 1, HIGH: 1 },
      };

      const result = formatScanSummary(scanFindings, evaluation, 'my-repo', 'v1.0');

      expect(result).toContain('ECR Image Scan Results');
      expect(result).toContain('Repository: my-repo');
      expect(result).toContain('Image: v1.0');
      expect(result).toContain('Scan Type: BASIC');
      expect(result).toContain('CRITICAL: 1, HIGH: 1');
    });

    test('should show no vulnerabilities message', () => {
      const scanFindings = createBasicScanFindings([]);
      const evaluation = {
        hasVulnerabilities: false,
        summary: '',
        filteredSeverityCounts: {},
      };

      const result = formatScanSummary(scanFindings, evaluation, 'my-repo', 'v1.0');

      expect(result).toContain('No vulnerabilities found.');
    });

    test('should format enhanced scan summary', () => {
      const scanFindings = createEnhancedScanFindings([
        { vulnId: 'CVE-2023-0001', severity: 'HIGH' },
      ]);
      const evaluation = {
        hasVulnerabilities: true,
        summary: 'HIGH: 1',
        filteredSeverityCounts: { HIGH: 1 },
      };

      const result = formatScanSummary(scanFindings, evaluation, 'my-repo', 'v1.0');

      expect(result).toContain('Scan Type: ENHANCED');
      expect(result).toContain('HIGH: 1');
    });

    test('should truncate findings list when more than 20', () => {
      const findings = Array.from({ length: 25 }, (_, i) => ({
        name: `CVE-2023-${String(i).padStart(4, '0')}`,
        severity: 'HIGH',
      }));
      const scanFindings = createBasicScanFindings(findings);
      const evaluation = {
        hasVulnerabilities: true,
        summary: 'HIGH: 25',
        filteredSeverityCounts: { HIGH: 25 },
      };

      const result = formatScanSummary(scanFindings, evaluation, 'my-repo', 'v1.0');

      expect(result).toContain('and 5 more');
    });
  });
});
