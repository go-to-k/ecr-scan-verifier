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

  return lines.join('\n');
};
