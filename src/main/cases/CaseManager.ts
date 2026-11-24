import { BaseWindow, BrowserWindow, session, WebContents, WebContentsView } from 'electron';
import { createHash } from 'crypto';
import { createReadStream, mkdirSync } from 'fs';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  CaseTab,
  EnrichmentResult,
  EvidenceScreenshot,
  ExportFormat,
  IocRecord,
  NetworkEvent,
  ProxyConfig,
  QuarantinedDownload,
  SplunkPushResult,
  VaultCaseDetail,
  VaultCaseSummary
} from '../../shared/types';
import {
  applyBrowserCompatibilityAndHardening,
  applyWebContentsHardening,
  isSafeNavigationUrl,
  normalizeAddressInput
} from '../hardening/BrowserSpoof';
import { CdpCollector } from '../telemetry/CdpCollector';
import { extractIocsFromNetworkEvents, extractIocsFromText } from '../intel/IocExtractor';
import { EnrichmentClient } from '../intel/EnrichmentClient';
import { exportCaseBundle } from '../export/CaseExporters';
import { SplunkHecClient } from '../export/SplunkHecClient';
import { VaultDb } from '../storage/VaultDb';

const TOP_CHROME_HEIGHT = 86;

interface ManagedCaseTab {
  meta: CaseTab;
  partition: string;
  view: WebContentsView;
  collector: CdpCollector;
  iocs: Map<string, IocRecord>;
  downloads: QuarantinedDownload[];
  popups: Set<BrowserWindow>;
}

export class CaseManager {
  private tabs = new Map<string, ManagedCaseTab>();
  private activeTabId: string | null = null;
  private sidePanelWidth = 380;

  constructor(
    private readonly hostWindow: BaseWindow,
    private readonly evidenceRoot: string,
    private readonly enrichment: EnrichmentClient,
    private readonly vault: VaultDb,
    private readonly splunkHec: SplunkHecClient,
    private readonly emitToShell: (channel: string, ...args: unknown[]) => void
  ) {
    this.hostWindow.on('resize', () => this.layoutActiveView());
  }

  public async createCaseTab(initialUrl?: string, proxyOverride?: ProxyConfig, sharedCaseId?: string): Promise<CaseTab> {
    const id = uuidv4().slice(0, 8);
    const caseId = sharedCaseId || `CASE-${id.toUpperCase()}`;
    const partition = `case-${caseId.toLowerCase()}`;
    const ses = session.fromPartition(partition);

    const proxy: ProxyConfig = proxyOverride || {
      mode: 'direct',
      rules: '',
      stripCrossOriginReferer: true
    };

    const meta: CaseTab = {
      id,
      caseId,
      title: 'New Investigation',
      url: normalizeAddressInput(initialUrl || 'https://www.reddit.com'),
      isLoading: true,
      canGoBack: false,
      canGoForward: false,
      proxy,
      createdAt: new Date().toISOString()
    };

    applyBrowserCompatibilityAndHardening(ses, () => this.tabs.get(id)?.meta.proxy || proxy);
    await this.applySessionProxy(ses, proxy);

    ses.removeAllListeners('will-download');
    ses.on('will-download', (_event, item) => {
      const quarantineDir = join(this.evidenceRoot, caseId, 'quarantine');
      mkdirSync(quarantineDir, { recursive: true });
      const safeName = item.getFilename().replace(/[^a-zA-Z0-9._-]/g, '_');
      const savePath = join(quarantineDir, `${Date.now()}-${safeName}.quarantine`);
      item.setSavePath(savePath);

      item.once('done', (_e, state) => {
        if (state !== 'completed') return;
        const hash = createHash('sha256');
        const stream = createReadStream(savePath);
        stream.on('data', (chunk) => hash.update(chunk));
        stream.on('end', () => {
          const record: QuarantinedDownload = {
            id: uuidv4().slice(0, 8),
            caseId,
            filename: item.getFilename(),
            url: item.getURL(),
            savedPath: savePath,
            sha256: hash.digest('hex'),
            bytes: item.getTotalBytes(),
            capturedAt: new Date().toISOString()
          };
          const managed = this.tabs.get(id);
          if (managed) {
            managed.downloads.push(record);
            this.emitToShell('soc:download-quarantined', record);
          }
        });
      });
    });

    const view = new WebContentsView({
      webPreferences: {
        partition,
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        webSecurity: true,
        spellcheck: false
      }
    });

    applyWebContentsHardening(view.webContents);

    const iocs = new Map<string, IocRecord>();
    const collector = new CdpCollector(caseId, view.webContents, this.evidenceRoot, (ev: NetworkEvent) => {
      this.emitToShell('soc:network-event', ev);
      const beforeSize = iocs.size;
      extractIocsFromNetworkEvents([ev], iocs);
      if (iocs.size !== beforeSize) {
        this.emitToShell('soc:iocs-updated', id, Array.from(iocs.values()));
      }
    });
    collector.attach();

    const managed: ManagedCaseTab = {
      meta,
      partition,
      view,
      collector,
      iocs,
      downloads: [],
      popups: new Set()
    };

    this.tabs.set(id, managed);
    this.wireWebContentsEvents(managed);

    this.activateCaseTab(id);
    view.webContents.loadURL(meta.url).catch((err) => {
      console.error(`[CaseManager] Failed to load ${meta.url}:`, err);
    });

    this.broadcastTabs();
    return meta;
  }

  private injectStealth(wc: WebContents): void {
    if (wc.isDestroyed()) return;
    wc.executeJavaScript(`
      try {
        if (navigator.webdriver !== undefined) {
          Object.defineProperty(Object.getPrototypeOf(navigator), 'webdriver', { get: () => false, configurable: true });
          Object.defineProperty(navigator, 'webdriver', { get: () => false, configurable: true });
        }
        if (!window.chrome) window.chrome = {};
        if (!window.chrome.runtime) window.chrome.runtime = {};
      } catch {}
    `).catch(() => {});
  }

  private wireWebContentsEvents(managed: ManagedCaseTab): void {
    const wc = managed.view.webContents;

    wc.on('dom-ready', () => this.injectStealth(wc));

    wc.setWindowOpenHandler(({ url, disposition, features }) => {
      if (!isSafeNavigationUrl(url)) {
        return { action: 'deny' };
      }

      const isPopup = disposition === 'new-window' || Boolean(features && features.includes('width='));
      if (isPopup) {
        const popup = new BrowserWindow({
          width: 520,
          height: 680,
          autoHideMenuBar: true,
          webPreferences: {
            partition: managed.partition,
            sandbox: true,
            contextIsolation: true,
            nodeIntegration: false
          }
        });
        applyWebContentsHardening(popup.webContents);
        popup.webContents.on('dom-ready', () => this.injectStealth(popup.webContents));
        popup.loadURL(url).catch(() => {});
        managed.popups.add(popup);
        popup.on('closed', () => managed.popups.delete(popup));
        return { action: 'deny' };
      }

      void this.createCaseTab(url, managed.meta.proxy, managed.meta.caseId);
      return { action: 'deny' };
    });

    wc.on('will-navigate', (event, url) => {
      if (!isSafeNavigationUrl(url)) {
        event.preventDefault();
      }
    });

    const syncMeta = () => {
      if (wc.isDestroyed()) return;
      managed.meta.title = wc.getTitle() || managed.meta.url;
      managed.meta.url = wc.getURL() || managed.meta.url;
      managed.meta.canGoBack = wc.navigationHistory.canGoBack();
      managed.meta.canGoForward = wc.navigationHistory.canGoForward();
      this.broadcastTabs();
    };

    wc.on('did-start-loading', () => {
      managed.meta.isLoading = true;
      this.broadcastTabs();
    });

    wc.on('did-stop-loading', () => {
      managed.meta.isLoading = false;
      syncMeta();
    });

    wc.on('page-title-updated', syncMeta);
    wc.on('did-navigate', syncMeta);
    wc.on('did-navigate-in-page', syncMeta);
  }

  public activateCaseTab(tabId: string): void {
    const target = this.tabs.get(tabId);
    if (!target) return;

    if (this.activeTabId && this.activeTabId !== tabId) {
      const prev = this.tabs.get(this.activeTabId);
      if (prev) {
        this.hostWindow.contentView.removeChildView(prev.view);
      }
    }

    this.activeTabId = tabId;
    this.hostWindow.contentView.addChildView(target.view);
    this.layoutActiveView();
    this.broadcastTabs();
    this.emitToShell('soc:iocs-updated', tabId, Array.from(target.iocs.values()));
  }

  public async closeCaseTab(tabId: string): Promise<void> {
    const target = this.tabs.get(tabId);
    if (!target) return;

    if (this.activeTabId === tabId) {
      this.hostWindow.contentView.removeChildView(target.view);
      this.activeTabId = null;
    }

    target.collector.detach();
    for (const popup of target.popups) {
      if (!popup.isDestroyed()) popup.close();
    }
    target.view.webContents.close();
    this.tabs.delete(tabId);

    const stillUsed = Array.from(this.tabs.values()).some((t) => t.partition === target.partition);
    if (!stillUsed) {
      const ses = session.fromPartition(target.partition);
      await ses.clearStorageData().catch(() => {});
      await ses.clearCache().catch(() => {});
    }

    const next = Array.from(this.tabs.keys())[0];
    if (next) {
      this.activateCaseTab(next);
    } else {
      this.broadcastTabs();
    }
  }

  public setSidePanelWidth(width: number): void {
    this.sidePanelWidth = Math.max(0, width);
    this.layoutActiveView();
  }

  public layoutActiveView(): void {
    if (!this.activeTabId) return;
    const active = this.tabs.get(this.activeTabId);
    if (!active) return;

    const bounds = this.hostWindow.getContentBounds();
    const viewWidth = Math.max(320, bounds.width - this.sidePanelWidth);
    const viewHeight = Math.max(200, bounds.height - TOP_CHROME_HEIGHT);

    active.view.setBounds({
      x: 0,
      y: TOP_CHROME_HEIGHT,
      width: viewWidth,
      height: viewHeight
    });
  }

  public navigate(tabId: string, rawInput: string): void {
    const target = this.tabs.get(tabId);
    if (!target) return;
    const url = normalizeAddressInput(rawInput);
    if (!isSafeNavigationUrl(url)) return;
    target.view.webContents.loadURL(url).catch(() => {});
  }

  public goBack(tabId: string): void {
    const wc = this.tabs.get(tabId)?.view.webContents;
    if (wc && wc.navigationHistory.canGoBack()) wc.navigationHistory.goBack();
  }

  public goForward(tabId: string): void {
    const wc = this.tabs.get(tabId)?.view.webContents;
    if (wc && wc.navigationHistory.canGoForward()) wc.navigationHistory.goForward();
  }

  public reload(tabId: string): void {
    this.tabs.get(tabId)?.view.webContents.reload();
  }

  public async setProxy(tabId: string, proxy: ProxyConfig): Promise<CaseTab | null> {
    const target = this.tabs.get(tabId);
    if (!target) return null;
    target.meta.proxy = proxy;
    const ses = session.fromPartition(target.partition);
    await this.applySessionProxy(ses, proxy);
    this.broadcastTabs();
    return target.meta;
  }

  private async applySessionProxy(ses: Electron.Session, proxy: ProxyConfig): Promise<void> {
    if (proxy.mode === 'tor') {
      await ses.setProxy({ proxyRules: 'socks5://127.0.0.1:9050' });
    } else if (proxy.mode === 'custom' && proxy.rules.trim()) {
      await ses.setProxy({ proxyRules: proxy.rules.trim() });
    } else {
      await ses.setProxy({ mode: 'direct' });
    }
  }

  public async captureScreenshot(tabId: string): Promise<EvidenceScreenshot | null> {
    const target = this.tabs.get(tabId);
    if (!target) return null;
    return target.collector.captureScreenshot();
  }

  public async scanPageIocs(tabId: string): Promise<IocRecord[]> {
    const target = this.tabs.get(tabId);
    if (!target) return [];

    try {
      const pageText = (await target.view.webContents.executeJavaScript(
        'document.body ? document.body.innerText.slice(0, 250000) : ""',
        true
      )) as string;
      extractIocsFromText(pageText || '', 'dom', target.iocs);
    } catch {
      // Ignore if page is still navigating
    }

    const list = Array.from(target.iocs.values());
    this.emitToShell('soc:iocs-updated', tabId, list);
    return list;
  }

  public async enrichIoc(tabId: string, ioc: IocRecord): Promise<EnrichmentResult> {
    const result = await this.enrichment.enrich(ioc);
    const target = this.tabs.get(tabId);
    if (target) {
      const key = `${ioc.type}:${ioc.value.toLowerCase()}`;
      const existing = target.iocs.get(key);
      if (existing) {
        existing.enrichment = result;
        this.emitToShell('soc:iocs-updated', tabId, Array.from(target.iocs.values()));
      }
    }
    return result;
  }

  public exportCase(tabId: string, format: ExportFormat): { filePath: string; sha256: string; preview: string } {
    const target = this.tabs.get(tabId);
    if (!target) {
      throw new Error(`Case tab ${tabId} not found`);
    }
    return exportCaseBundle(
      {
        tab: target.meta,
        events: target.collector.getEvents(),
        iocs: Array.from(target.iocs.values()),
        screenshots: target.collector.getScreenshots(),
        downloads: target.downloads,
        harJson: target.collector.buildHarJson()
      },
      format,
      this.evidenceRoot
    );
  }

  public async pushToSplunkHec(tabId: string): Promise<SplunkPushResult> {
    const target = this.tabs.get(tabId);
    if (!target) {
      return { ok: false, statusCode: 0, message: `Case tab ${tabId} not found.` };
    }
    return this.splunkHec.pushCase({
      tab: target.meta,
      events: target.collector.getEvents(),
      iocs: Array.from(target.iocs.values()),
      screenshots: target.collector.getScreenshots(),
      downloads: target.downloads
    });
  }

  public saveCaseToVault(tabId: string, notes?: string): VaultCaseSummary {
    const target = this.tabs.get(tabId);
    if (!target) {
      throw new Error(`Case tab ${tabId} not found`);
    }
    return this.vault.saveCaseSnapshot({
      tab: target.meta,
      events: target.collector.getEvents(),
      iocs: Array.from(target.iocs.values()),
      screenshots: target.collector.getScreenshots(),
      downloads: target.downloads,
      notes
    });
  }

  public listVaultCases(): VaultCaseSummary[] {
    return this.vault.listCases();
  }

  public getVaultCaseDetail(caseId: string): VaultCaseDetail | null {
    return this.vault.getCaseDetail(caseId);
  }

  public deleteVaultCase(caseId: string): void {
    this.vault.deleteCase(caseId);
  }

  private broadcastTabs(): void {
    const list = Array.from(this.tabs.values()).map((t) => t.meta);
    this.emitToShell('soc:tabs-updated', list, this.activeTabId);
  }
}
