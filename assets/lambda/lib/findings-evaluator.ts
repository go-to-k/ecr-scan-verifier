import { ScanFindings } from './ecr-scan';

export interface EvaluationResult {
  hasVulnerabilities: boolean;
  summary: string;
  filteredSeverityCounts: Record<string, number>;
}

export const evaluateFindings = (
  scanFindings: ScanFindings,
  severityThresholds: string[],
  ignoreFindings: string[],
): EvaluationResult => {
  const ignoreSet = new Set(ignoreFindings);
  const severitySet = new Set(severityThresholds);

  if (scanFindings.scanType === 'ENHANCED') {
    return evaluateEnhancedFindings(scanFindings, severitySet, ignoreSet);
  }
  return evaluateBasicFindings(scanFindings, severitySet, ignoreSet);
};

const evaluateBasicFindings = (
  scanFindings: ScanFindings,
  severitySet: Set<string>,
  ignoreSet: Set<string>,
): EvaluationResult => {
  const filteredFindings = scanFindings.basicFindings.filter(
    (f) => !ignoreSet.has(f.name || ''),
  );

  const filteredSeverityCounts: Record<string, number> = {};
  let hasVulnerabilities = false;

  for (const finding of filteredFindings) {
    const severity = finding.severity || 'UNDEFINED';
    filteredSeverityCounts[severity] = (filteredSeverityCounts[severity] || 0) + 1;
    if (severitySet.has(severity)) {
      hasVulnerabilities = true;
    }
  }

  const summary = formatSummary(filteredSeverityCounts);
  return { hasVulnerabilities, summary, filteredSeverityCounts };
};

const evaluateEnhancedFindings = (
  scanFindings: ScanFindings,
  severitySet: Set<string>,
  ignoreSet: Set<string>,
): EvaluationResult => {
  const filteredFindings = scanFindings.enhancedFindings.filter((f) => {
    if (ignoreSet.has(f.findingArn || '')) return false;
    const vulnId = f.packageVulnerabilityDetails?.vulnerabilityId;
    if (vulnId && ignoreSet.has(vulnId)) return false;
    return true;
  });

  const filteredSeverityCounts: Record<string, number> = {};
  let hasVulnerabilities = false;

  for (const finding of filteredFindings) {
    const severity = finding.severity || 'UNDEFINED';
    filteredSeverityCounts[severity] = (filteredSeverityCounts[severity] || 0) + 1;
    if (severitySet.has(severity)) {
      hasVulnerabilities = true;
    }
  }

  const summary = formatSummary(filteredSeverityCounts);
  return { hasVulnerabilities, summary, filteredSeverityCounts };
};

const formatSummary = (severityCounts: Record<string, number>): string => {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'UNDEFINED'];
  return order
    .filter((s) => severityCounts[s])
    .map((s) => `${s}: ${severityCounts[s]}`)
    .join(', ');
};

export const formatScanSummary = (
  scanFindings: ScanFindings,
  evaluation: EvaluationResult,
  repositoryName: string,
  imageTag: string,
): string => {
  const lines: string[] = [
    '=== ECR Image Scan Results ===',
    `Repository: ${repositoryName}`,
    `Image: ${imageTag}`,
    `Scan Type: ${scanFindings.scanType}`,
    `Scan Status: ${scanFindings.status}`,
    '',
    '--- Severity Summary ---',
  ];

  if (evaluation.summary) {
    lines.push(evaluation.summary);
  } else {
    lines.push('No vulnerabilities found.');
  }

  lines.push('');

  if (scanFindings.scanType === 'BASIC' || scanFindings.scanType === 'ENHANCED') {
    const findings =
      scanFindings.scanType === 'ENHANCED'
        ? scanFindings.enhancedFindings
        : scanFindings.basicFindings;

    if (findings.length > 0) {
      lines.push(`--- Findings (${findings.length} total) ---`);

      const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'UNDEFINED'];
      for (const severity of severityOrder) {
        const sevFindings =
          scanFindings.scanType === 'ENHANCED'
            ? scanFindings.enhancedFindings.filter((f) => f.severity === severity)
            : scanFindings.basicFindings.filter((f) => f.severity === severity);

        if (sevFindings.length > 0) {
          lines.push(`\n[${severity}] (${sevFindings.length})`);
          for (const f of sevFindings.slice(0, 20)) {
            if (scanFindings.scanType === 'ENHANCED') {
              const ef = f as any;
              const vulnId = ef.packageVulnerabilityDetails?.vulnerabilityId || 'N/A';
              const pkg = ef.packageVulnerabilityDetails?.vulnerablePackages?.[0];
              const pkgInfo = pkg ? `${pkg.name}@${pkg.version}` : 'N/A';
              lines.push(`  ${vulnId} | Package: ${pkgInfo}`);
            } else {
              const bf = f as any;
              lines.push(`  ${bf.name || 'N/A'} | ${bf.description?.substring(0, 100) || 'N/A'}`);
            }
          }
          if (sevFindings.length > 20) {
            lines.push(`  ... and ${sevFindings.length - 20} more`);
          }
        }
      }
    }
  }

  return lines.join('\n');
};
