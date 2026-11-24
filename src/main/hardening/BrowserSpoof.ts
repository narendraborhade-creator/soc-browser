import { Session, WebContents } from 'electron';
import { ProxyConfig } from '../../shared/types';

/**
 * Builds a clean desktop Chrome User-Agent from the bundled Chromium version.
 * Stripping "Electron/x.x.x" and app names prevents anti-bot 403s on Reddit,
 * Cloudflare Turnstile, and modern SaaS platforms.
 */
export function buildCleanChromeUserAgent(): string {
  const chromeVersion = process.versions.chrome || '132.0.0.0';
  const platformToken =
    process.platform === 'win32'
      ? 'Windows NT 10.0; Win64; x64'
      : process.platform === 'darwin'
        ? 'Macintosh; Intel Mac OS X 10_15_7'
        : 'X11; Linux x86_64';

  return `Mozilla/5.0 (${platformToken}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion} Safari/537.36`;
}

function getSecChPlatform(): string {
  if (process.platform === 'win32') return '"Windows"';
  if (process.platform === 'darwin') return '"macOS"';
  return '"Linux"';
}

function getChromeMajorVersion(): string {
  const full = process.versions.chrome || '132.0.0.0';
  return full.split('.')[0] || '132';
}

const OAUTH_SSO_HOSTS = [
  'accounts.google.com',
  'login.microsoftonline.com',
  'appleid.apple.com',
  'auth.github.com',
  'github.com',
  'auth0.com',
  'okta.com',
  'id.atlassian.com',
  'discord.com',
  'twitter.com',
  'x.com'
];

/**
 * Applies Chrome-compatible User-Agent and Sec-CH-UA headers to a session,
 * plus optional cross-origin Referer stripping for analyst OPSEC.
 */
export function applyBrowserCompatibilityAndHardening(
  ses: Session,
  getProxyConfig: () => ProxyConfig
): void {
  const cleanUA = buildCleanChromeUserAgent();
  const major = getChromeMajorVersion();
  const secChUa = `"Not A(Brand";v="8", "Chromium";v="${major}", "Google Chrome";v="${major}"`;
  const secChPlatform = getSecChPlatform();

  ses.setUserAgent(cleanUA);

  ses.webRequest.onBeforeSendHeaders((details, callback) => {
    const headers = { ...details.requestHeaders };

    // Normalize UA + Client Hints so Cloudflare / Reddit / Google see standard Chrome
    headers['User-Agent'] = cleanUA;
    headers['Sec-CH-UA'] = secChUa;
    headers['Sec-CH-UA-Mobile'] = '?0';
    headers['Sec-CH-UA-Platform'] = secChPlatform;

    // Strip cross-origin Referer for OPSEC, but preserve for OAuth/SSO identity providers
    // where OAuth 2.0 RFC 8252 explicitly verifies caller domain integrity.
    if (getProxyConfig().stripCrossOriginReferer && headers['Referer']) {
      try {
        const reqHost = new URL(details.url).hostname.toLowerCase();
        const isOAuthFlow = OAUTH_SSO_HOSTS.some((h) => reqHost === h || reqHost.endsWith('.' + h));

        if (!isOAuthFlow) {
          const refOrigin = new URL(headers['Referer']).origin;
          const reqOrigin = new URL(details.url).origin;
          if (refOrigin !== reqOrigin) {
            delete headers['Referer'];
          }
        }
      } catch {
        delete headers['Referer'];
      }
    }

    callback({ requestHeaders: headers });
  });
}

/**
 * Prevents WebRTC from leaking local LAN/VPN-bypassing IP addresses.
 */
export function applyWebContentsHardening(wc: WebContents): void {
  wc.setWebRTCIPHandlingPolicy('disable_non_proxied_udp');
  wc.setUserAgent(buildCleanChromeUserAgent());
}

/**
 * Blocks dangerous OS protocol handlers that phishing pages use to launch local binaries.
 */
export function isSafeNavigationUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' || parsed.protocol === 'about:';
  } catch {
    return false;
  }
}

/**
 * Normalizes omnibox text into a navigable URL or DuckDuckGo search.
 */
export function normalizeAddressInput(rawInput: string): string {
  const trimmed = rawInput.trim();
  if (!trimmed) return 'https://www.reddit.com';

  // Auto-refang if analyst pastes a defanged IOC like hxxps://evil[.]com
  const refanged = trimmed
    .replace(/^hxxps:\/\//i, 'https://')
    .replace(/^hxxp:\/\//i, 'http://')
    .replace(/\[\.\]/g, '.')
    .replace(/\(dot\)/gi, '.');

  if (/^https?:\/\//i.test(refanged)) {
    return refanged;
  }

  // Domain or IP with optional path
  if (/^[\w.-]+\.[a-z]{2,}(:\d+)?(\/.*)?$/i.test(refanged) || /^\d{1,3}(\.\d{1,3}){3}(:\d+)?(\/.*)?$/.test(refanged)) {
    return `https://${refanged}`;
  }

  return `https://duckduckgo.com/?q=${encodeURIComponent(trimmed)}`;
}
