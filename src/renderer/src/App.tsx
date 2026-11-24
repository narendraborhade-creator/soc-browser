import React, { useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Camera,
  Copy,
  Database,
  Download,
  ExternalLink,
  PanelRight,
  Plus,
  RefreshCw,
  Search,
  Send,
  Shield,
  Trash2,
  X
} from 'lucide-react';
import {
  ApiKeysState,
  CaseTab,
  ExportFormat,
  IocRecord,
  NetworkEvent,
  ProxyMode,
  QuarantinedDownload,
  SocBrowserApi,
  VaultCaseDetail,
  VaultCaseSummary
} from '@shared/types';

declare global {
  interface Window {
    socBrowser: SocBrowserApi;
  }
}

type PanelView = 'iocs' | 'network' | 'vault' | 'export' | 'keys';

export default function App(): React.ReactElement {
  const [tabs, setTabs] = useState<CaseTab[]>([]);
  const [activeTabId, setActiveTabId] = useState<string | null>(null);
  const [address, setAddress] = useState('https://www.reddit.com');
  const [panelOpen, setPanelOpen] = useState(true);
  const [panelView, setPanelView] = useState<PanelView>('iocs');
  const [networkEvents, setNetworkEvents] = useState<NetworkEvent[]>([]);
  const [iocsByTab, setIocsByTab] = useState<Record<string, IocRecord[]>>({});
  const [downloads, setDownloads] = useState<QuarantinedDownload[]>([]);
  const [statusMsg, setStatusMsg] = useState<string>('');
  const [exportPreview, setExportPreview] = useState<string>('');
  const [customProxy, setCustomProxy] = useState('http://127.0.0.1:8080');

  // Encrypted SQLite Vault state
  const [vaultCases, setVaultCases] = useState<VaultCaseSummary[]>([]);
  const [selectedVaultCase, setSelectedVaultCase] = useState<VaultCaseDetail | null>(null);
  const [caseNotes, setCaseNotes] = useState('');

  // Secrets & Splunk HEC state
  const [keysState, setKeysState] = useState<ApiKeysState>({
    hasVirusTotal: false,
    hasAbuseIpDb: false,
    hasSplunkToken: false,
    splunkConfig: {
      url: 'https://127.0.0.1:8088/services/collector/event',
      index: 'soc_browser',
      allowSelfSignedTls: true
    }
  });
  const [vtInput, setVtInput] = useState('');
  const [abuseInput, setAbuseInput] = useState('');
  const [splunkTokenInput, setSplunkTokenInput] = useState('');
  const [splunkUrlInput, setSplunkUrlInput] = useState('https://127.0.0.1:8088/services/collector/event');
  const [splunkIndexInput, setSplunkIndexInput] = useState('soc_browser');
  const [splunkSelfSigned, setSplunkSelfSigned] = useState(true);

  const activeTab = useMemo(() => tabs.find((t) => t.id === activeTabId) || null, [tabs, activeTabId]);
  const activeIocs = activeTabId ? iocsByTab[activeTabId] || [] : [];
  const activeEvents = useMemo(
    () => (activeTab ? networkEvents.filter((e) => e.caseId === activeTab.caseId).slice(-120).reverse() : []),
    [networkEvents, activeTab]
  );

  const refreshVault = async () => {
    const list = await window.socBrowser.listVaultCases();
    setVaultCases(list);
  };

  useEffect(() => {
    void window.socBrowser.getApiKeysState().then((st) => {
      setKeysState(st);
      setSplunkUrlInput(st.splunkConfig.url);
      setSplunkIndexInput(st.splunkConfig.index);
      setSplunkSelfSigned(st.splunkConfig.allowSelfSignedTls);
    });
    void refreshVault();

    const offTabs = window.socBrowser.onTabsUpdated((nextTabs, nextActive) => {
      setTabs(nextTabs);
      setActiveTabId(nextActive);
      const current = nextTabs.find((t) => t.id === nextActive);
      if (current) setAddress(current.url);
    });

    const offNet = window.socBrowser.onNetworkEvent((ev) => {
      setNetworkEvents((prev) => [...prev.slice(-400), ev]);
    });

    const offIocs = window.socBrowser.onIocsUpdated((tabId, list) => {
      setIocsByTab((prev) => ({ ...prev, [tabId]: list }));
    });

    const offDl = window.socBrowser.onDownloadQuarantined((item) => {
      setDownloads((prev) => [item, ...prev]);
      setStatusMsg(`Quarantined download: ${item.filename} (${item.sha256.slice(0, 12)}…)`);
    });

    return () => {
      offTabs();
      offNet();
      offIocs();
      offDl();
    };
  }, []);

  const togglePanel = async () => {
    const next = !panelOpen;
    setPanelOpen(next);
    await window.socBrowser.setSidePanelWidth(next ? 380 : 0);
  };

  const handleNavigate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeTabId) return;
    void window.socBrowser.navigate(activeTabId, address);
  };

  const handleProxyChange = async (mode: ProxyMode) => {
    if (!activeTab) return;
    await window.socBrowser.setProxy(activeTab.id, {
      mode,
      rules: mode === 'custom' ? customProxy : mode === 'tor' ? 'socks5://127.0.0.1:9050' : '',
      stripCrossOriginReferer: activeTab.proxy.stripCrossOriginReferer
    });
    setStatusMsg(`Proxy updated to ${mode.toUpperCase()} for ${activeTab.caseId}`);
  };

  const handleScreenshot = async () => {
    if (!activeTabId) return;
    const shot = await window.socBrowser.captureScreenshot(activeTabId);
    if (shot) {
      setStatusMsg(`Screenshot saved (SHA-256: ${shot.sha256.slice(0, 16)}…)`);
    }
  };

  const handleExport = async (format: ExportFormat) => {
    if (!activeTabId) return;
    const res = await window.socBrowser.exportCase(activeTabId, format);
    setExportPreview(res.preview);
    setStatusMsg(`Exported ${format.toUpperCase()} -> ${res.filePath}`);
  };

  const handleSplunkPush = async () => {
    if (!activeTabId) return;
    setStatusMsg('Pushing case event to Splunk HEC…');
    const res = await window.socBrowser.pushToSplunkHec(activeTabId);
    setStatusMsg(res.ok ? `Splunk HEC OK (${res.statusCode}): ${res.message}` : `Splunk HEC failed: ${res.message}`);
  };

  const handleSaveToVault = async () => {
    if (!activeTabId) return;
    const summary = await window.socBrowser.saveCaseToVault(activeTabId, caseNotes);
    setCaseNotes('');
    await refreshVault();
    setStatusMsg(`Encrypted & saved ${summary.caseId} to SQLite Vault.`);
  };

  const handleSaveKeys = async (e: React.FormEvent) => {
    e.preventDefault();
    const state = await window.socBrowser.saveApiKeys({
      virusTotal: vtInput || undefined,
      abuseIpDb: abuseInput || undefined,
      splunkToken: splunkTokenInput || undefined,
      splunkUrl: splunkUrlInput,
      splunkIndex: splunkIndexInput,
      splunkAllowSelfSignedTls: splunkSelfSigned
    });
    setKeysState(state);
    setVtInput('');
    setAbuseInput('');
    setSplunkTokenInput('');
    setStatusMsg('Keys & Splunk HEC settings encrypted via OS keychain (safeStorage).');
  };

  return (
    <div className="shell">
      <div className="tab-strip">
        {tabs.map((tab) => (
          <div
            key={tab.id}
            className={`tab ${tab.id === activeTabId ? 'active' : ''}`}
            onClick={() => void window.socBrowser.activateCaseTab(tab.id)}
          >
            <span className="tab-badge">{tab.caseId}</span>
            <span className="tab-title">{tab.title || tab.url}</span>
            <X
              size={14}
              onClick={(e) => {
                e.stopPropagation();
                void window.socBrowser.closeCaseTab(tab.id);
              }}
            />
          </div>
        ))}
        <button className="icon-btn" onClick={() => void window.socBrowser.createCaseTab('https://www.reddit.com')}>
          <Plus size={14} /> New Case
        </button>
      </div>

      <form className="nav-bar" onSubmit={handleNavigate}>
        <button
          type="button"
          className="icon-btn"
          disabled={!activeTab?.canGoBack}
          onClick={() => activeTabId && void window.socBrowser.goBack(activeTabId)}
        >
          <ArrowLeft size={14} />
        </button>
        <button
          type="button"
          className="icon-btn"
          disabled={!activeTab?.canGoForward}
          onClick={() => activeTabId && void window.socBrowser.goForward(activeTabId)}
        >
          <ArrowRight size={14} />
        </button>
        <button
          type="button"
          className="icon-btn"
          onClick={() => activeTabId && void window.socBrowser.reload(activeTabId)}
        >
          <RefreshCw size={14} />
        </button>

        <input
          className="omnibox"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          placeholder="Enter URL, defanged IOC (hxxps://...), or search query"
        />

        <select
          className="proxy-select"
          value={activeTab?.proxy.mode || 'direct'}
          onChange={(e) => void handleProxyChange(e.target.value as ProxyMode)}
        >
          <option value="direct">Direct</option>
          <option value="tor">Tor (SOCKS5 :9050)</option>
          <option value="custom">Custom Proxy</option>
        </select>

        {activeTab?.proxy.mode === 'custom' && (
          <input
            className="omnibox"
            style={{ maxWidth: 180 }}
            value={customProxy}
            onChange={(e) => setCustomProxy(e.target.value)}
            onBlur={() => void handleProxyChange('custom')}
          />
        )}

        <button
          type="button"
          className={`icon-btn ${activeTab?.proxy.stripCrossOriginReferer ? 'active' : ''}`}
          title="Strip cross-origin Referer header"
          onClick={() =>
            activeTab &&
            void window.socBrowser.setProxy(activeTab.id, {
              ...activeTab.proxy,
              stripCrossOriginReferer: !activeTab.proxy.stripCrossOriginReferer
            })
          }
        >
          <Shield size={14} /> OPSEC
        </button>

        <button type="button" className="icon-btn" title="Capture SHA-256 Screenshot" onClick={() => void handleScreenshot()}>
          <Camera size={14} />
        </button>

        <button
          type="button"
          className="icon-btn"
          title="Open current page in default system browser (for external passkey/SSO)"
          onClick={() => {
            if (activeTab?.url) {
              void window.socBrowser.openExternal(activeTab.url);
              setStatusMsg(`Opened in system browser: ${activeTab.url}`);
            }
          }}
        >
          <ExternalLink size={14} /> External
        </button>

        <button type="button" className={`icon-btn ${panelOpen ? 'active' : ''}`} onClick={() => void togglePanel()}>
          <PanelRight size={14} /> SOC
        </button>
      </form>

      <div className="workspace">
        {panelOpen && (
          <aside className="side-panel">
            <div className="panel-tabs">
              <button className={`panel-tab ${panelView === 'iocs' ? 'active' : ''}`} onClick={() => setPanelView('iocs')}>
                IOCs ({activeIocs.length})
              </button>
              <button className={`panel-tab ${panelView === 'network' ? 'active' : ''}`} onClick={() => setPanelView('network')}>
                Net
              </button>
              <button
                className={`panel-tab ${panelView === 'vault' ? 'active' : ''}`}
                onClick={() => {
                  setPanelView('vault');
                  void refreshVault();
                }}
              >
                Vault ({vaultCases.length})
              </button>
              <button className={`panel-tab ${panelView === 'export' ? 'active' : ''}`} onClick={() => setPanelView('export')}>
                Export
              </button>
              <button className={`panel-tab ${panelView === 'keys' ? 'active' : ''}`} onClick={() => setPanelView('keys')}>
                Keys
              </button>
            </div>

            {statusMsg && (
              <div style={{ padding: '6px 10px', background: '#161b22', borderBottom: '1px solid #21262d' }} className="muted">
                {statusMsg}
              </div>
            )}

            <div className="panel-body">
              {panelView === 'iocs' && (
                <>
                  <button
                    className="icon-btn"
                    onClick={() => activeTabId && void window.socBrowser.scanPageIocs(activeTabId)}
                  >
                    <Search size={14} /> Scan Visible Page DOM for IOCs
                  </button>
                  {activeIocs.map((ioc) => (
                    <div key={`${ioc.type}-${ioc.value}`} className="card">
                      <div className="row">
                        <span className="tab-badge">{ioc.type.toUpperCase()}</span>
                        <span className="muted">{ioc.source}</span>
                      </div>
                      <div className="mono">{ioc.defanged}</div>
                      {ioc.enrichment && (
                        <div className={`verdict-${ioc.enrichment.verdict}`}>
                          {ioc.enrichment.provider.toUpperCase()}: {ioc.enrichment.score} — {ioc.enrichment.summary}
                        </div>
                      )}
                      <div className="row" style={{ marginTop: 4 }}>
                        <button
                          className="icon-btn"
                          onClick={() => {
                            void navigator.clipboard.writeText(ioc.defanged);
                            setStatusMsg(`Copied defanged IOC: ${ioc.defanged}`);
                          }}
                        >
                          <Copy size={12} /> Copy Defanged
                        </button>
                        <button
                          className="icon-btn"
                          onClick={() => activeTabId && void window.socBrowser.enrichIoc(activeTabId, ioc)}
                        >
                          Enrich
                        </button>
                      </div>
                    </div>
                  ))}
                </>
              )}

              {panelView === 'network' && (
                <>
                  {downloads.length > 0 && (
                    <div className="card">
                      <strong>Quarantined Downloads ({downloads.length})</strong>
                      {downloads.map((d) => (
                        <div key={d.id} className="mono muted">
                          {d.filename} · {d.sha256.slice(0, 16)}…
                        </div>
                      ))}
                    </div>
                  )}
                  {activeEvents.map((ev, idx) => (
                    <div key={`${ev.requestId}-${idx}`} className="card">
                      <div className="row">
                        <strong>
                          {ev.method} {ev.status || '…'}
                        </strong>
                        <span className="muted">{ev.remoteIPAddress || ev.protocol || ''}</span>
                      </div>
                      {ev.redirectFrom && <div className="muted">Redirect from: {ev.redirectFrom}</div>}
                      <div className="mono">{ev.url}</div>
                    </div>
                  ))}
                </>
              )}

              {panelView === 'vault' && (
                <>
                  <div className="card">
                    <strong>Encrypted SQLite Vault (AES-256-GCM)</strong>
                    <input
                      className="omnibox"
                      placeholder="Optional analyst notes for this case snapshot…"
                      value={caseNotes}
                      onChange={(e) => setCaseNotes(e.target.value)}
                    />
                    <button className="icon-btn" onClick={() => void handleSaveToVault()}>
                      <Database size={14} /> Save Current Case Snapshot
                    </button>
                  </div>

                  {vaultCases.map((vc) => (
                    <div key={vc.caseId} className="card">
                      <div className="row">
                        <span className="tab-badge">{vc.caseId}</span>
                        <span className="muted">{new Date(vc.savedAt).toLocaleString()}</span>
                      </div>
                      <div className="mono">{vc.finalUrlDefanged}</div>
                      <div className="muted">
                        {vc.iocCount} IOCs · {vc.screenshotCount} shots · {vc.downloadCount} quarantined
                      </div>
                      <div className="row" style={{ marginTop: 4 }}>
                        <button
                          className="icon-btn"
                          onClick={() =>
                            void window.socBrowser.getVaultCaseDetail(vc.caseId).then(setSelectedVaultCase)
                          }
                        >
                          Inspect
                        </button>
                        <button
                          className="icon-btn"
                          onClick={async () => {
                            await window.socBrowser.deleteVaultCase(vc.caseId);
                            if (selectedVaultCase?.caseId === vc.caseId) setSelectedVaultCase(null);
                            await refreshVault();
                          }}
                        >
                          <Trash2 size={12} /> Purge
                        </button>
                      </div>
                    </div>
                  ))}

                  {selectedVaultCase && (
                    <div className="card">
                      <div className="row">
                        <strong>{selectedVaultCase.caseId} Details</strong>
                        <X size={14} style={{ cursor: 'pointer' }} onClick={() => setSelectedVaultCase(null)} />
                      </div>
                      {selectedVaultCase.notes && <div className="muted">Notes: {selectedVaultCase.notes}</div>}
                      <pre className="export-preview">{JSON.stringify(selectedVaultCase, null, 2)}</pre>
                    </div>
                  )}
                </>
              )}

              {panelView === 'export' && (
                <>
                  <div className="row" style={{ flexWrap: 'wrap' }}>
                    <button className="icon-btn active" onClick={() => void handleSplunkPush()}>
                      <Send size={13} /> Push to Splunk HEC
                    </button>
                    <button className="icon-btn" onClick={() => void handleExport('splunk')}>
                      <Download size={13} /> Splunk JSON
                    </button>
                    <button className="icon-btn" onClick={() => void handleExport('jira')}>
                      <Download size={13} /> Jira Markdown
                    </button>
                    <button className="icon-btn" onClick={() => void handleExport('thehive')}>
                      <Download size={13} /> TheHive JSON
                    </button>
                    <button className="icon-btn" onClick={() => void handleExport('har')}>
                      <Download size={13} /> HAR 1.2
                    </button>
                  </div>
                  {exportPreview && <pre className="export-preview">{exportPreview}</pre>}
                </>
              )}

              {panelView === 'keys' && (
                <form className="card" onSubmit={handleSaveKeys}>
                  <strong>Threat-Intel &amp; Splunk HEC (OS Keychain)</strong>
                  <div className="muted">
                    VT: {keysState.hasVirusTotal ? 'Set' : '—'} · AbuseIPDB: {keysState.hasAbuseIpDb ? 'Set' : '—'} ·
                    Splunk HEC: {keysState.hasSplunkToken ? 'Set' : '—'}
                  </div>
                  <input
                    className="omnibox"
                    type="password"
                    placeholder="VirusTotal v3 API Key"
                    value={vtInput}
                    onChange={(e) => setVtInput(e.target.value)}
                  />
                  <input
                    className="omnibox"
                    type="password"
                    placeholder="AbuseIPDB v2 API Key"
                    value={abuseInput}
                    onChange={(e) => setAbuseInput(e.target.value)}
                  />
                  <input
                    className="omnibox"
                    placeholder="Splunk HEC URL (https://127.0.0.1:8088/services/collector/event)"
                    value={splunkUrlInput}
                    onChange={(e) => setSplunkUrlInput(e.target.value)}
                  />
                  <input
                    className="omnibox"
                    placeholder="Splunk Index (default: soc_browser)"
                    value={splunkIndexInput}
                    onChange={(e) => setSplunkIndexInput(e.target.value)}
                  />
                  <input
                    className="omnibox"
                    type="password"
                    placeholder="Splunk HEC Token"
                    value={splunkTokenInput}
                    onChange={(e) => setSplunkTokenInput(e.target.value)}
                  />
                  <label className="row muted" style={{ justifyContent: 'flex-start' }}>
                    <input
                      type="checkbox"
                      checked={splunkSelfSigned}
                      onChange={(e) => setSplunkSelfSigned(e.target.checked)}
                    />
                    Allow self-signed TLS cert (local Splunk lab)
                  </label>
                  <button type="submit" className="icon-btn">
                    Save Encrypted Settings
                  </button>
                </form>
              )}
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
