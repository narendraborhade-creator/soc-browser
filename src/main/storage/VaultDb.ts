import Database from 'better-sqlite3';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { mkdirSync } from 'fs';
import { dirname } from 'path';
import {
  CaseTab,
  EvidenceScreenshot,
  IocRecord,
  NetworkEvent,
  QuarantinedDownload,
  VaultCaseDetail,
  VaultCaseSummary
} from '../../shared/types';
import { defangIndicator } from '../intel/IocExtractor';
import { SecretStore } from '../intel/EnrichmentClient';

interface EncryptedRow {
  case_id: string;
  saved_at: string;
  ioc_count: number;
  screenshot_count: number;
  download_count: number;
  iv: Buffer;
  auth_tag: Buffer;
  ciphertext: Buffer;
}

/**
 * Local SQLite case history vault with authenticated AES-256-GCM payload encryption.
 * The 256-bit master key is sealed in the OS keychain via Electron safeStorage.
 */
export class VaultDb {
  private db: Database.Database;
  private masterKey: Buffer;

  constructor(dbPath: string, secrets: SecretStore) {
    mkdirSync(dirname(dbPath), { recursive: true });
    const keyHex = secrets.getOrCreateVaultMasterKey(() => randomBytes(32).toString('hex'));
    this.masterKey = Buffer.from(keyHex, 'hex');

    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('secure_delete = ON');

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault_cases (
        case_id TEXT PRIMARY KEY,
        saved_at TEXT NOT NULL,
        ioc_count INTEGER NOT NULL DEFAULT 0,
        screenshot_count INTEGER NOT NULL DEFAULT 0,
        download_count INTEGER NOT NULL DEFAULT 0,
        iv BLOB NOT NULL,
        auth_tag BLOB NOT NULL,
        ciphertext BLOB NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_vault_cases_saved_at ON vault_cases (saved_at DESC);
    `);
  }

  private encryptPayload(obj: unknown): { iv: Buffer; authTag: Buffer; ciphertext: Buffer } {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.masterKey, iv);
    const plaintext = Buffer.from(JSON.stringify(obj), 'utf-8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return { iv, authTag, ciphertext };
  }

  private decryptPayload<T>(row: EncryptedRow): T {
    const decipher = createDecipheriv('aes-256-gcm', this.masterKey, row.iv);
    decipher.setAuthTag(row.auth_tag);
    const decrypted = Buffer.concat([decipher.update(row.ciphertext), decipher.final()]);
    return JSON.parse(decrypted.toString('utf-8')) as T;
  }

  public saveCaseSnapshot(params: {
    tab: CaseTab;
    events: NetworkEvent[];
    iocs: IocRecord[];
    screenshots: EvidenceScreenshot[];
    downloads: QuarantinedDownload[];
    notes?: string;
  }): VaultCaseSummary {
    const savedAt = new Date().toISOString();
    const detail: VaultCaseDetail = {
      caseId: params.tab.caseId,
      title: params.tab.title || params.tab.caseId,
      finalUrlDefanged: defangIndicator(params.tab.url),
      proxyMode: params.tab.proxy.mode,
      iocCount: params.iocs.length,
      screenshotCount: params.screenshots.length,
      downloadCount: params.downloads.length,
      savedAt,
      iocs: params.iocs,
      redirects: params.events
        .filter((e) => Boolean(e.redirectFrom))
        .map((e) => ({
          from: defangIndicator(e.redirectFrom!),
          to: defangIndicator(e.url),
          ts: e.timestamp
        })),
      screenshots: params.screenshots,
      downloads: params.downloads,
      notes: params.notes || ''
    };

    const { iv, authTag, ciphertext } = this.encryptPayload(detail);

    const stmt = this.db.prepare(`
      INSERT INTO vault_cases (
        case_id, saved_at, ioc_count, screenshot_count, download_count, iv, auth_tag, ciphertext
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(case_id) DO UPDATE SET
        saved_at = excluded.saved_at,
        ioc_count = excluded.ioc_count,
        screenshot_count = excluded.screenshot_count,
        download_count = excluded.download_count,
        iv = excluded.iv,
        auth_tag = excluded.auth_tag,
        ciphertext = excluded.ciphertext
    `);

    stmt.run(
      detail.caseId,
      savedAt,
      detail.iocCount,
      detail.screenshotCount,
      detail.downloadCount,
      iv,
      authTag,
      ciphertext
    );

    return {
      caseId: detail.caseId,
      title: detail.title,
      finalUrlDefanged: detail.finalUrlDefanged,
      iocCount: detail.iocCount,
      screenshotCount: detail.screenshotCount,
      downloadCount: detail.downloadCount,
      savedAt
    };
  }

  public listCases(): VaultCaseSummary[] {
    const rows = this.db
      .prepare('SELECT * FROM vault_cases ORDER BY saved_at DESC LIMIT 200')
      .all() as EncryptedRow[];

    const summaries: VaultCaseSummary[] = [];
    for (const row of rows) {
      try {
        const detail = this.decryptPayload<VaultCaseDetail>(row);
        summaries.push({
          caseId: detail.caseId,
          title: detail.title,
          finalUrlDefanged: detail.finalUrlDefanged,
          iocCount: detail.iocCount,
          screenshotCount: detail.screenshotCount,
          downloadCount: detail.downloadCount,
          savedAt: detail.savedAt
        });
      } catch {
        // Skip rows if master key was rotated
      }
    }
    return summaries;
  }

  public getCaseDetail(caseId: string): VaultCaseDetail | null {
    const row = this.db.prepare('SELECT * FROM vault_cases WHERE case_id = ?').get(caseId) as
      | EncryptedRow
      | undefined;
    if (!row) return null;
    try {
      return this.decryptPayload<VaultCaseDetail>(row);
    } catch {
      return null;
    }
  }

  public deleteCase(caseId: string): void {
    this.db.prepare('DELETE FROM vault_cases WHERE case_id = ?').run(caseId);
  }

  public close(): void {
    this.db.close();
  }
}
