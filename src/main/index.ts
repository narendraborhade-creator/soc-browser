import { app, BrowserWindow, ipcMain, shell } from 'electron';
import { join } from 'path';
import { CaseManager } from './cases/CaseManager';
import { EnrichmentClient, SecretStore } from './intel/EnrichmentClient';
import { SplunkHecClient } from './export/SplunkHecClient';
import { VaultDb } from './storage/VaultDb';
import { ExportFormat, IocRecord, ProxyConfig, SaveSecretsPayload } from '../shared/types';
import { buildCleanChromeUserAgent } from './hardening/BrowserSpoof';

app.commandLine.appendSwitch('disable-background-networking');
app.commandLine.appendSwitch('disable-sync');
app.commandLine.appendSwitch('disable-features', 'AutofillServerCommunication,MediaRouter');
app.commandLine.appendSwitch('disable-blink-features', 'AutomationControlled');

// Normalize fallback user-agent so Google BotGuard and worker iframes never detect Electron
app.userAgentFallback = buildCleanChromeUserAgent();

let mainWindow: BrowserWindow | null = null;
let caseManager: CaseManager | null = null;
let vaultDb: VaultDb | null = null;

function createShellWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 680,
    backgroundColor: '#0d1117',
    title: 'SOC Analyst Browser',
    webPreferences: {
      preload: join(__dirname, '../preload/shellPreload.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  const userData = app.getPath('userData');
  const secrets = new SecretStore(join(userData, 'secrets.enc'));
  const enrichment = new EnrichmentClient(secrets);
  const splunkHec = new SplunkHecClient(secrets);
  vaultDb = new VaultDb(join(userData, 'vault', 'cases.sqlite'), secrets);

  caseManager = new CaseManager(
    mainWindow,
    join(userData, 'cases'),
    enrichment,
    vaultDb,
    splunkHec,
    (channel, ...args) => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send(channel, ...args);
      }
    }
  );

  ipcMain.handle('soc:create-tab', (_e, url?: string, proxy?: ProxyConfig) =>
    caseManager!.createCaseTab(url, proxy)
  );
  ipcMain.handle('soc:close-tab', (_e, tabId: string) => caseManager!.closeCaseTab(tabId));
  ipcMain.handle('soc:activate-tab', (_e, tabId: string) => caseManager!.activateCaseTab(tabId));
  ipcMain.handle('soc:navigate', (_e, tabId: string, rawInput: string) => caseManager!.navigate(tabId, rawInput));
  ipcMain.handle('soc:go-back', (_e, tabId: string) => caseManager!.goBack(tabId));
  ipcMain.handle('soc:go-forward', (_e, tabId: string) => caseManager!.goForward(tabId));
  ipcMain.handle('soc:reload', (_e, tabId: string) => caseManager!.reload(tabId));
  ipcMain.handle('soc:set-proxy', (_e, tabId: string, proxy: ProxyConfig) => caseManager!.setProxy(tabId, proxy));
  ipcMain.handle('soc:set-panel-width', (_e, width: number) => caseManager!.setSidePanelWidth(width));
  ipcMain.handle('soc:capture-screenshot', (_e, tabId: string) => caseManager!.captureScreenshot(tabId));
  ipcMain.handle('soc:scan-iocs', (_e, tabId: string) => caseManager!.scanPageIocs(tabId));
  ipcMain.handle('soc:enrich-ioc', (_e, tabId: string, ioc: IocRecord) => caseManager!.enrichIoc(tabId, ioc));
  ipcMain.handle('soc:export-case', (_e, tabId: string, format: ExportFormat) => caseManager!.exportCase(tabId, format));
  ipcMain.handle('soc:push-splunk-hec', (_e, tabId: string) => caseManager!.pushToSplunkHec(tabId));
  ipcMain.handle('soc:vault-save', (_e, tabId: string, notes?: string) => caseManager!.saveCaseToVault(tabId, notes));
  ipcMain.handle('soc:vault-list', () => caseManager!.listVaultCases());
  ipcMain.handle('soc:vault-detail', (_e, caseId: string) => caseManager!.getVaultCaseDetail(caseId));
  ipcMain.handle('soc:vault-delete', (_e, caseId: string) => caseManager!.deleteVaultCase(caseId));
  ipcMain.handle('soc:save-keys', (_e, keys: SaveSecretsPayload) => secrets.save(keys));
  ipcMain.handle('soc:get-keys-state', () => secrets.getState());
  ipcMain.handle('soc:open-external', (_e, url: string) => shell.openExternal(url));

  if (process.env.ELECTRON_RENDERER_URL) {
    mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'));
  }

  mainWindow.webContents.once('did-finish-load', () => {
    void caseManager!.createCaseTab('https://www.reddit.com');
  });
}

app.whenReady().then(createShellWindow);

app.on('will-quit', () => {
  vaultDb?.close();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
