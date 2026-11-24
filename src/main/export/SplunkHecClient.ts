import http from 'http';
import https from 'https';
import os from 'os';
import {
  CaseTab,
  EvidenceScreenshot,
  IocRecord,
  NetworkEvent,
  QuarantinedDownload,
  SplunkPushResult
} from '../../shared/types';
import { defangIndicator } from '../intel/IocExtractor';
import { SecretStore } from '../intel/EnrichmentClient';

export interface SplunkPushInput {
  tab: CaseTab;
  events: NetworkEvent[];
  iocs: IocRecord[];
  screenshots: EvidenceScreenshot[];
  downloads: QuarantinedDownload[];
}

export class SplunkHecClient {
  constructor(private readonly secrets: SecretStore) {}

  public async pushCase(input: SplunkPushInput): Promise<SplunkPushResult> {
    const token = this.secrets.getSplunkToken();
    const config = this.secrets.getSplunkConfig();

    if (!token) {
      return {
        ok: false,
        statusCode: 0,
        message: 'Splunk HEC token is not configured. Add it in the Keys tab.'
      };
    }

    let endpoint: URL;
    try {
      endpoint = new URL(config.url);
    } catch {
      return {
        ok: false,
        statusCode: 0,
        message: `Invalid Splunk HEC URL: ${config.url}`
      };
    }

    const body = JSON.stringify({
      time: Math.floor(Date.now() / 1000),
      host: os.hostname(),
      source: 'soc-browser',
      sourcetype: 'soc_browser:case',
      index: config.index || 'soc_browser',
      event: {
        case_id: input.tab.caseId,
        title: input.tab.title,
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
          .map((e) => ({
            from: defangIndicator(e.redirectFrom!),
            to: defangIndicator(e.url),
            ts: e.timestamp
          })),
        screenshots: input.screenshots.map((s) => ({
          file: s.filePath,
          sha256: s.sha256,
          ts: s.capturedAt
        })),
        quarantined_downloads: input.downloads.map((d) => ({
          filename: d.filename,
          sha256: d.sha256,
          bytes: d.bytes
        }))
      }
    });

    return new Promise((resolve) => {
      const isHttps = endpoint.protocol === 'https:';
      const transport = isHttps ? https : http;

      const req = transport.request(
        endpoint,
        {
          method: 'POST',
          headers: {
            Authorization: `Splunk ${token}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body)
          },
          ...(isHttps ? { rejectUnauthorized: !config.allowSelfSignedTls } : {})
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
          res.on('end', () => {
            const raw = Buffer.concat(chunks).toString('utf-8');
            const code = res.statusCode || 0;
            resolve({
              ok: code >= 200 && code < 300,
              statusCode: code,
              message: raw || `HTTP ${code}`
            });
          });
        }
      );

      req.setTimeout(10000, () => {
        req.destroy(new Error('Splunk HEC request timed out after 10s'));
      });

      req.on('error', (err) => {
        resolve({
          ok: false,
          statusCode: 0,
          message: `Splunk HEC connection error: ${err.message}`
        });
      });

      req.write(body);
      req.end();
    });
  }
}
