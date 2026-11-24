import { contextBridge, ipcRenderer } from 'electron';
import {
  CaseTab,
  ExportFormat,
  IocRecord,
  NetworkEvent,
  ProxyConfig,
  QuarantinedDownload,
  SaveSecretsPayload,
  SocBrowserApi
} from '../shared/types';

const api: SocBrowserApi = {
  createCaseTab: (initialUrl?: string, proxy?: ProxyConfig) =>
    ipcRenderer.invoke('soc:create-tab', initialUrl, proxy),
  closeCaseTab: (tabId: string) => ipcRenderer.invoke('soc:close-tab', tabId),
  activateCaseTab: (tabId: string) => ipcRenderer.invoke('soc:activate-tab', tabId),
  navigate: (tabId: string, rawInput: string) => ipcRenderer.invoke('soc:navigate', tabId, rawInput),
  goBack: (tabId: string) => ipcRenderer.invoke('soc:go-back', tabId),
  goForward: (tabId: string) => ipcRenderer.invoke('soc:go-forward', tabId),
  reload: (tabId: string) => ipcRenderer.invoke('soc:reload', tabId),
  setProxy: (tabId: string, proxy: ProxyConfig) => ipcRenderer.invoke('soc:set-proxy', tabId, proxy),
  setSidePanelWidth: (width: number) => ipcRenderer.invoke('soc:set-panel-width', width),
  captureScreenshot: (tabId: string) => ipcRenderer.invoke('soc:capture-screenshot', tabId),
  scanPageIocs: (tabId: string) => ipcRenderer.invoke('soc:scan-iocs', tabId),
  enrichIoc: (tabId: string, ioc: IocRecord) => ipcRenderer.invoke('soc:enrich-ioc', tabId, ioc),
  exportCase: (tabId: string, format: ExportFormat) => ipcRenderer.invoke('soc:export-case', tabId, format),
  pushToSplunkHec: (tabId: string) => ipcRenderer.invoke('soc:push-splunk-hec', tabId),
  saveCaseToVault: (tabId: string, notes?: string) => ipcRenderer.invoke('soc:vault-save', tabId, notes),
  listVaultCases: () => ipcRenderer.invoke('soc:vault-list'),
  getVaultCaseDetail: (caseId: string) => ipcRenderer.invoke('soc:vault-detail', caseId),
  deleteVaultCase: (caseId: string) => ipcRenderer.invoke('soc:vault-delete', caseId),
  saveApiKeys: (keys: SaveSecretsPayload) => ipcRenderer.invoke('soc:save-keys', keys),
  getApiKeysState: () => ipcRenderer.invoke('soc:get-keys-state'),
  openExternal: (url: string) => ipcRenderer.invoke('soc:open-external', url),

  onTabsUpdated: (cb) => {
    const listener = (_e: Electron.IpcRendererEvent, tabs: CaseTab[], activeTabId: string | null) =>
      cb(tabs, activeTabId);
    ipcRenderer.on('soc:tabs-updated', listener);
    return () => ipcRenderer.removeListener('soc:tabs-updated', listener);
  },
  onNetworkEvent: (cb) => {
    const listener = (_e: Electron.IpcRendererEvent, event: NetworkEvent) => cb(event);
    ipcRenderer.on('soc:network-event', listener);
    return () => ipcRenderer.removeListener('soc:network-event', listener);
  },
  onIocsUpdated: (cb) => {
    const listener = (_e: Electron.IpcRendererEvent, tabId: string, iocs: IocRecord[]) => cb(tabId, iocs);
    ipcRenderer.on('soc:iocs-updated', listener);
    return () => ipcRenderer.removeListener('soc:iocs-updated', listener);
  },
  onDownloadQuarantined: (cb) => {
    const listener = (_e: Electron.IpcRendererEvent, item: QuarantinedDownload) => cb(item);
    ipcRenderer.on('soc:download-quarantined', listener);
    return () => ipcRenderer.removeListener('soc:download-quarantined', listener);
  }
};

contextBridge.exposeInMainWorld('socBrowser', api);
