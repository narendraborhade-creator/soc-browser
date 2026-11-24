import { safeStorage } from 'electron';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname } from 'path';
import {
  ApiKeysState,
  EnrichmentResult,
  IocRecord,
  SaveSecretsPayload,
  SplunkHecConfig
} from '../../shared/types';

interface StoredSecrets {
  virusTotal?: string;
  abuseIpDb?: string;
  splunkToken?: string;
  splunkUrl?: string;
  splunkIndex?: string;
  splunkAllowSelfSignedTls?: boolean;
  vaultMasterKeyHex?: string;
}

export class SecretStore {
  private cache: StoredSecrets = {};

  constructor(private readonly filePath: string) {
    this.load();
  }

  private load(): void {
    if (!existsSync(this.filePath)) return;
    try {
      const raw = readFileSync(this.filePath);
      if (safeStorage.isEncryptionAvailable()) {
        const decrypted = safeStorage.decryptString(raw);
        this.cache = JSON.parse(decrypted);
      } else {
        this.cache = JSON.parse(raw.toString('utf-8'));
      }
    } catch {
      this.cache = {};
    }
  }

  private persist(): void {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const serialized = JSON.stringify(this.cache);
    const payload = safeStorage.isEncryptionAvailable()
      ? safeStorage.encryptString(serialized)
      : Buffer.from(serialized, 'utf-8');
    writeFileSync(this.filePath, payload);
  }

  public save(update: SaveSecretsPayload): ApiKeysState {
    if (update.virusTotal !== undefined) {
      this.cache.virusTotal = update.virusTotal.trim() || undefined;
    }
    if (update.abuseIpDb !== undefined) {
      this.cache.abuseIpDb = update.abuseIpDb.trim() || undefined;
    }
    if (update.splunkToken !== undefined) {
      this.cache.splunkToken = update.splunkToken.trim() || undefined;
    }
    if (update.splunkUrl !== undefined) {
      this.cache.splunkUrl = update.splunkUrl.trim();
    }
    if (update.splunkIndex !== undefined) {
      this.cache.splunkIndex = update.splunkIndex.trim() || 'soc_browser';
    }
    if (update.splunkAllowSelfSignedTls !== undefined) {
      this.cache.splunkAllowSelfSignedTls = update.splunkAllowSelfSignedTls;
    }

    this.persist();
    return this.getState();
  }

  public getOrCreateVaultMasterKey(generateHex: () => string): string {
    if (!this.cache.vaultMasterKeyHex) {
      this.cache.vaultMasterKeyHex = generateHex();
      this.persist();
    }
    return this.cache.vaultMasterKeyHex;
  }

  public getState(): ApiKeysState {
    return {
      hasVirusTotal: Boolean(this.cache.virusTotal),
      hasAbuseIpDb: Boolean(this.cache.abuseIpDb),
      hasSplunkToken: Boolean(this.cache.splunkToken),
      splunkConfig: this.getSplunkConfig()
    };
  }

  public getVirusTotalKey(): string | undefined {
    return this.cache.virusTotal;
  }

  public getAbuseIpDbKey(): string | undefined {
    return this.cache.abuseIpDb;
  }

  public getSplunkToken(): string | undefined {
    return this.cache.splunkToken;
  }

  public getSplunkConfig(): SplunkHecConfig {
    return {
      url: this.cache.splunkUrl || 'https://127.0.0.1:8088/services/collector/event',
      index: this.cache.splunkIndex || 'soc_browser',
      allowSelfSignedTls: this.cache.splunkAllowSelfSignedTls ?? true
    };
  }
}

export class EnrichmentClient {
  constructor(private readonly secrets: SecretStore) {}

  public async enrich(ioc: IocRecord): Promise<EnrichmentResult> {
    if (ioc.type === 'ipv4' && this.secrets.getAbuseIpDbKey()) {
      return this.queryAbuseIpDb(ioc.value, this.secrets.getAbuseIpDbKey()!);
    }

    if (this.secrets.getVirusTotalKey()) {
      return this.queryVirusTotal(ioc, this.secrets.getVirusTotalKey()!);
    }

    return {
      provider: ioc.type === 'ipv4' ? 'abuseipdb' : 'virustotal',
      verdict: 'unknown',
      score: 'N/A',
      summary: 'No API key configured. Add a VirusTotal or AbuseIPDB key in the Keys tab.',
      checkedAt: new Date().toISOString()
    };
  }

  private async queryAbuseIpDb(ip: string, apiKey: string): Promise<EnrichmentResult> {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        headers: {
          Key: apiKey,
          Accept: 'application/json'
        }
      }
    );

    if (!res.ok) {
      return {
        provider: 'abuseipdb',
        verdict: 'unknown',
        score: `HTTP ${res.status}`,
        summary: `AbuseIPDB request failed (${res.status}).`,
        checkedAt: new Date().toISOString()
      };
    }

    const json = (await res.json()) as {
      data?: { abuseConfidenceScore?: number; totalReports?: number; countryCode?: string; isp?: string };
    };
    const score = json.data?.abuseConfidenceScore ?? 0;
    const reports = json.data?.totalReports ?? 0;
    const verdict = score >= 50 ? 'malicious' : score >= 15 ? 'suspicious' : 'clean';

    return {
      provider: 'abuseipdb',
      verdict,
      score: `${score}% confidence`,
      summary: `${reports} reports · ${json.data?.countryCode || '??'} · ${json.data?.isp || 'Unknown ISP'}`,
      checkedAt: new Date().toISOString()
    };
  }

  private async queryVirusTotal(ioc: IocRecord, apiKey: string): Promise<EnrichmentResult> {
    let endpoint = '';
    if (ioc.type === 'ipv4') endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc.value)}`;
    else if (ioc.type === 'domain') endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc.value)}`;
    else if (ioc.type === 'md5' || ioc.type === 'sha1' || ioc.type === 'sha256') {
      endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc.value)}`;
    } else {
      const urlId = Buffer.from(ioc.value).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    }

    const res = await fetch(endpoint, {
      headers: { 'x-apikey': apiKey }
    });

    if (!res.ok) {
      return {
        provider: 'virustotal',
        verdict: 'unknown',
        score: `HTTP ${res.status}`,
        summary: `VirusTotal returned HTTP ${res.status}.`,
        checkedAt: new Date().toISOString()
      };
    }

    const json = (await res.json()) as {
      data?: { attributes?: { last_analysis_stats?: Record<string, number> } };
    };
    const stats = json.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);
    const verdict = malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'clean';

    return {
      provider: 'virustotal',
      verdict,
      score: `${malicious}/${total} detections`,
      summary: `${malicious} malicious, ${suspicious} suspicious across ${total} engines`,
      checkedAt: new Date().toISOString()
    };
  }
}
