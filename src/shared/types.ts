export type ProxyMode = 'direct' | 'tor' | 'custom';

export interface ProxyConfig {
  mode: ProxyMode;
  rules: string;
  stripCrossOriginReferer: boolean;
}

export interface CaseTab {
  id: string;
  caseId: string;
  title: string;
  url: string;
  isLoading: boolean;
  canGoBack: boolean;
  canGoForward: boolean;
  proxy: ProxyConfig;
  createdAt: string;
}

export interface NetworkEvent {
  requestId: string;
  caseId: string;
  timestamp: string;
  method: string;
  url: string;
  status?: number;
  mimeType?: string;
  remoteIPAddress?: string;
  protocol?: string;
  redirectFrom?: string;
  securityState?: string;
}

export type IocType = 'ipv4' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256';

export interface IocRecord {
  value: string;
  defanged: string;
  type: IocType;
  source: 'network' | 'dom';
  firstSeen: string;
  enrichment?: EnrichmentResult;
}

export interface EnrichmentResult {
  provider: 'virustotal' | 'abuseipdb';
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  score: string;
  summary: string;
  checkedAt: string;
}

export interface EvidenceScreenshot {
  id: string;
  caseId: string;
  url: string;
  filePath: string;
  sha256: string;
  capturedAt: string;
}

export interface QuarantinedDownload {
  id: string;
  caseId: string;
  filename: string;
  url: string;
  savedPath: string;
  sha256: string;
  bytes: number;
  capturedAt: string;
}

export type ExportFormat = 'splunk' | 'jira' | 'thehive' | 'har';

export interface SplunkHecConfig {
  url: string;
  index: string;
  allowSelfSignedTls: boolean;
}

export interface SplunkPushResult {
  ok: boolean;
  statusCode: number;
  message: string;
}

export interface VaultCaseSummary {
  caseId: string;
  title: string;
  finalUrlDefanged: string;
  iocCount: number;
  screenshotCount: number;
  downloadCount: number;
  savedAt: string;
}

export interface VaultCaseDetail extends VaultCaseSummary {
  proxyMode: ProxyMode;
  iocs: IocRecord[];
  redirects: Array<{ from: string; to: string; ts: string }>;
  screenshots: EvidenceScreenshot[];
  downloads: QuarantinedDownload[];
  notes: string;
}

export interface ApiKeysState {
  hasVirusTotal: boolean;
  hasAbuseIpDb: boolean;
  hasSplunkToken: boolean;
  splunkConfig: SplunkHecConfig;
}

export interface SaveSecretsPayload {
  virusTotal?: string;
  abuseIpDb?: string;
  splunkToken?: string;
  splunkUrl?: string;
  splunkIndex?: string;
  splunkAllowSelfSignedTls?: boolean;
}

export interface SocBrowserApi {
  createCaseTab: (initialUrl?: string, proxy?: ProxyConfig) => Promise<CaseTab>;
  closeCaseTab: (tabId: string) => Promise<void>;
  activateCaseTab: (tabId: string) => Promise<void>;
  navigate: (tabId: string, rawInput: string) => Promise<void>;
  goBack: (tabId: string) => Promise<void>;
  goForward: (tabId: string) => Promise<void>;
  reload: (tabId: string) => Promise<void>;
  setProxy: (tabId: string, proxy: ProxyConfig) => Promise<CaseTab | null>;
  setSidePanelWidth: (width: number) => Promise<void>;
  captureScreenshot: (tabId: string) => Promise<EvidenceScreenshot | null>;
  scanPageIocs: (tabId: string) => Promise<IocRecord[]>;
  enrichIoc: (tabId: string, ioc: IocRecord) => Promise<EnrichmentResult>;
  exportCase: (tabId: string, format: ExportFormat) => Promise<{ filePath: string; sha256: string; preview: string }>;
  pushToSplunkHec: (tabId: string) => Promise<SplunkPushResult>;
  saveCaseToVault: (tabId: string, notes?: string) => Promise<VaultCaseSummary>;
  listVaultCases: () => Promise<VaultCaseSummary[]>;
  getVaultCaseDetail: (caseId: string) => Promise<VaultCaseDetail | null>;
  deleteVaultCase: (caseId: string) => Promise<void>;
  saveApiKeys: (keys: SaveSecretsPayload) => Promise<ApiKeysState>;
  getApiKeysState: () => Promise<ApiKeysState>;
  openExternal: (url: string) => Promise<void>;
  onTabsUpdated: (cb: (tabs: CaseTab[], activeTabId: string | null) => void) => () => void;
  onNetworkEvent: (cb: (event: NetworkEvent) => void) => () => void;
  onIocsUpdated: (cb: (tabId: string, iocs: IocRecord[]) => void) => () => void;
  onDownloadQuarantined: (cb: (item: QuarantinedDownload) => void) => () => void;
}
