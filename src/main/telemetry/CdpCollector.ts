import { WebContents } from 'electron';
import { createHash } from 'crypto';
import { mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { EvidenceScreenshot, NetworkEvent } from '../../shared/types';
import { v4 as uuidv4 } from 'uuid';

interface HarEntry {
  startedDateTime: string;
  time: number;
  request: {
    method: string;
    url: string;
    httpVersion: string;
    headers: Array<{ name: string; value: string }>;
  };
  response: {
    status: number;
    statusText: string;
    httpVersion: string;
    headers: Array<{ name: string; value: string }>;
    content: { size: number; mimeType: string };
  };
  serverIPAddress?: string;
}

export class CdpCollector {
  private events: NetworkEvent[] = [];
  private harEntries = new Map<string, HarEntry>();
  private screenshots: EvidenceScreenshot[] = [];
  private attached = false;

  constructor(
    private readonly caseId: string,
    private readonly wc: WebContents,
    private readonly evidenceRoot: string,
    private readonly onEvent: (ev: NetworkEvent) => void
  ) {}

  public attach(): void {
    if (this.attached || this.wc.isDestroyed()) return;

    try {
      this.wc.debugger.attach('1.3');
      this.attached = true;
    } catch (err) {
      console.error(`[CDP] Failed to attach for case ${this.caseId}:`, err);
      return;
    }

    this.wc.debugger.sendCommand('Network.enable').catch(() => {});
    this.wc.debugger.sendCommand('Security.enable').catch(() => {});
    this.wc.debugger.sendCommand('Page.enable').catch(() => {});

    this.wc.debugger.on('message', (_event, method, params) => {
      if (method === 'Network.requestWillBeSent') {
        const ts = new Date().toISOString();
        const redirectFrom = params.redirectResponse ? params.redirectResponse.url : undefined;

        const netEvent: NetworkEvent = {
          requestId: params.requestId,
          caseId: this.caseId,
          timestamp: ts,
          method: params.request?.method || 'GET',
          url: params.request?.url || '',
          redirectFrom
        };
        this.pushEvent(netEvent);

        const reqHeaders = Object.entries(params.request?.headers || {}).map(([name, value]) => ({
          name,
          value: String(value)
        }));

        this.harEntries.set(params.requestId, {
          startedDateTime: ts,
          time: 0,
          request: {
            method: netEvent.method,
            url: netEvent.url,
            httpVersion: 'HTTP/1.1',
            headers: reqHeaders
          },
          response: {
            status: 0,
            statusText: '',
            httpVersion: 'HTTP/1.1',
            headers: [],
            content: { size: 0, mimeType: '' }
          }
        });
      }

      if (method === 'Network.responseReceived') {
        const res = params.response || {};
        const existing = this.harEntries.get(params.requestId);
        const resHeaders = Object.entries(res.headers || {}).map(([name, value]) => ({
          name,
          value: String(value)
        }));

        if (existing) {
          existing.response = {
            status: res.status || 0,
            statusText: res.statusText || '',
            httpVersion: res.protocol || 'HTTP/1.1',
            headers: resHeaders,
            content: {
              size: res.encodedDataLength || 0,
              mimeType: res.mimeType || ''
            }
          };
          existing.serverIPAddress = res.remoteIPAddress;
        }

        const netEvent: NetworkEvent = {
          requestId: params.requestId,
          caseId: this.caseId,
          timestamp: new Date().toISOString(),
          method: existing?.request.method || 'GET',
          url: res.url || existing?.request.url || '',
          status: res.status,
          mimeType: res.mimeType,
          remoteIPAddress: res.remoteIPAddress,
          protocol: res.protocol,
          securityState: res.securityState
        };
        this.pushEvent(netEvent);
      }
    });
  }

  public detach(): void {
    if (!this.attached || this.wc.isDestroyed()) return;
    try {
      this.wc.debugger.detach();
    } catch {
      // Ignore if already detached
    }
    this.attached = false;
  }

  private pushEvent(ev: NetworkEvent): void {
    this.events.push(ev);
    if (this.events.length > 2000) {
      this.events.shift();
    }
    this.onEvent(ev);
  }

  public getEvents(): NetworkEvent[] {
    return [...this.events];
  }

  public getScreenshots(): EvidenceScreenshot[] {
    return [...this.screenshots];
  }

  public async captureScreenshot(): Promise<EvidenceScreenshot | null> {
    if (this.wc.isDestroyed()) return null;

    let pngBuffer: Buffer;
    try {
      const image = await this.wc.capturePage();
      pngBuffer = image.toPNG();
      if (!pngBuffer || pngBuffer.length === 0) throw new Error('Empty capturePage buffer');
    } catch {
      // Robust fallback to CDP Page.captureScreenshot if OS surface is unavailable
      try {
        const res = (await this.wc.debugger.sendCommand('Page.captureScreenshot', { format: 'png' })) as {
          data: string;
        };
        pngBuffer = Buffer.from(res.data, 'base64');
      } catch (err) {
        console.error(`[CDP] Failed to capture screenshot for case ${this.caseId}:`, err);
        return null;
      }
    }

    const sha256 = createHash('sha256').update(pngBuffer).digest('hex');

    const dir = join(this.evidenceRoot, this.caseId, 'screenshots');
    mkdirSync(dir, { recursive: true });

    const id = uuidv4().slice(0, 8);
    const filePath = join(dir, `capture-${Date.now()}-${id}.png`);
    writeFileSync(filePath, pngBuffer);

    const record: EvidenceScreenshot = {
      id,
      caseId: this.caseId,
      url: this.wc.getURL(),
      filePath,
      sha256,
      capturedAt: new Date().toISOString()
    };
    this.screenshots.push(record);
    return record;
  }

  public buildHarJson(): string {
    const har = {
      log: {
        version: '1.2',
        creator: {
          name: 'SOC Analyst Browser',
          version: '0.1.0'
        },
        entries: Array.from(this.harEntries.values())
      }
    };
    return JSON.stringify(har, null, 2);
  }
}
