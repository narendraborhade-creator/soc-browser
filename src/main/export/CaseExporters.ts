import { createHash } from 'crypto';
import { mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import {
  CaseTab,
  EvidenceScreenshot,
  ExportFormat,
  IocRecord,
  NetworkEvent,
  QuarantinedDownload
} from '../../shared/types';
import { defangIndicator } from '../intel/IocExtractor';

export interface CaseExportInput {
  tab: CaseTab;
  events: NetworkEvent[];
  iocs: IocRecord[];
  screenshots: EvidenceScreenshot[];
  downloads: QuarantinedDownload[];
  harJson: string;
}

export function exportCaseBundle(
  input: CaseExportInput,
  format: ExportFormat,
  evidenceRoot: string
): { filePath: string; sha256: string; preview: string } {
  const dir = join(evidenceRoot, input.tab.caseId, 'exports');
  mkdirSync(dir, { recursive: true });

  let content = '';
  let ext = 'json';

  if (format === 'har') {
    content = input.harJson;
    ext = 'har';
  } else if (format === 'splunk') {
    const splunkPayload = {
      time: Math.floor(Date.now() / 1000),
      source: 'soc-browser',
      sourcetype: 'soc_browser:case',
      event: {
        case_id: input.tab.caseId,
        final_url: defangIndicator(input.tab.url),
        proxy_mode: input.tab.proxy.mode,
        ioc_count: input.iocs.length,
        iocs: input.iocs.map((i) => ({
          type: i.type,
          value: i.defanged,
          source: i.source,
          verdict: i.enrichment?.verdict || 'unknown',
          score: i.enrichment?.score || 'N/A'
        })),
        redirects: input.events
          .filter((e) => Boolean(e.redirectFrom))
          .map((e) => ({ from: defangIndicator(e.redirectFrom!), to: defangIndicator(e.url), ts: e.timestamp })),
        screenshots: input.screenshots.map((s) => ({ file: s.filePath, sha256: s.sha256, ts: s.capturedAt })),
        quarantined_downloads: input.downloads.map((d) => ({
          filename: d.filename,
          sha256: d.sha256,
          bytes: d.bytes
        }))
      }
    };
    content = JSON.stringify(splunkPayload, null, 2);
    ext = 'splunk.json';
  } else if (format === 'thehive') {
    const typeMap: Record<IocRecord['type'], string> = {
      ipv4: 'ip',
      domain: 'domain',
      url: 'url',
      md5: 'hash',
      sha1: 'hash',
      sha256: 'hash'
    };

    const theHiveCase = {
      title: `SOC Browser Investigation - ${input.tab.caseId}`,
      description: `Automated case export from SOC Analyst Browser.\nFinal URL: ${defangIndicator(input.tab.url)}`,
      severity: input.iocs.some((i) => i.enrichment?.verdict === 'malicious') ? 3 : 2,
      tlp: 2,
      pap: 2,
      tags: ['soc-browser', `case:${input.tab.caseId}`],
      observables: input.iocs.map((i) => ({
        dataType: typeMap[i.type],
        data: i.value,
        ioc: true,
        tlp: 2,
        message: `Extracted from ${i.source} (${i.enrichment ? `${i.enrichment.provider}: ${i.enrichment.score}` : 'unenriched'})`
      }))
    };
    content = JSON.stringify(theHiveCase, null, 2);
    ext = 'thehive.json';
  } else {
    // Jira Markdown / Wiki summary
    const redirectLines = input.events
      .filter((e) => Boolean(e.redirectFrom))
      .map((e) => `- \`${defangIndicator(e.redirectFrom!)}\` -> \`${defangIndicator(e.url)}\``);

    const iocRows = input.iocs.map(
      (i) =>
        `| ${i.type.toUpperCase()} | \`${i.defanged}\` | ${i.source} | ${i.enrichment ? `${i.enrichment.verdict} (${i.enrichment.score})` : 'Unchecked'} |`
    );

    const shotLines = input.screenshots.map((s) => `- \`${s.filePath}\` (SHA-256: \`${s.sha256}\`)`);

    content = [
      `## SOC Investigation Summary — ${input.tab.caseId}`,
      ``,
      `- **Timestamp:** ${new Date().toISOString()}`,
      `- **Final URL (Defanged):** \`${defangIndicator(input.tab.url)}\``,
      `- **Proxy Mode:** ${input.tab.proxy.mode}${input.tab.proxy.rules ? ` (${input.tab.proxy.rules})` : ''}`,
      ``,
      `### Extracted Indicators (${input.iocs.length})`,
      `| Type | Indicator (Defanged) | Source | Threat Intel |`,
      `| :--- | :--- | :--- | :--- |`,
      ...(iocRows.length ? iocRows : ['| — | No indicators extracted | — | — |']),
      ``,
      `### Redirect Chain`,
      ...(redirectLines.length ? redirectLines : ['- No redirects recorded']),
      ``,
      `### Evidence Artifacts`,
      ...(shotLines.length ? shotLines : ['- No screenshots captured'])
    ].join('\n');
    ext = 'jira.md';
  }

  const filePath = join(dir, `${input.tab.caseId}-${Date.now()}.${ext}`);
  writeFileSync(filePath, content, 'utf-8');
  const sha256 = createHash('sha256').update(content, 'utf-8').digest('hex');

  return {
    filePath,
    sha256,
    preview: content.slice(0, 1200)
  };
}
