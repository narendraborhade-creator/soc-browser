import { IocRecord, IocType, NetworkEvent } from '../../shared/types';

const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/g;
const SHA1_REGEX = /\b[a-fA-F0-9]{40}\b/g;
const MD5_REGEX = /\b[a-fA-F0-9]{32}\b/g;
const URL_REGEX = /\bhttps?:\/\/[^\s"'<>()]+/gi;
const DOMAIN_REGEX = /\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|gov|edu|co|uk|ru|cn|xyz|top|info|biz|me|dev|app|in|de|fr|jp|ai|cloud|site|online|shop|live)\b/gi;

const PRIVATE_IP_PREFIXES = ['10.', '127.', '192.168.', '0.', '169.254.'];

export function defangIndicator(value: string): string {
  return value
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/\./g, '[.]');
}

export function refangIndicator(value: string): string {
  return value
    .replace(/^hxxps:\/\//i, 'https://')
    .replace(/^hxxp:\/\//i, 'http://')
    .replace(/\[\.\]/g, '.');
}

function isPrivateIpv4(ip: string): boolean {
  if (PRIVATE_IP_PREFIXES.some((p) => ip.startsWith(p))) return true;
  if (ip.startsWith('172.')) {
    const second = Number(ip.split('.')[1]);
    return second >= 16 && second <= 31;
  }
  return false;
}

export function extractIocsFromText(
  text: string,
  source: 'network' | 'dom',
  existingMap = new Map<string, IocRecord>()
): Map<string, IocRecord> {
  const now = new Date().toISOString();

  const add = (raw: string, type: IocType) => {
    const value = raw.trim().replace(/[.,;:'")]+$/, '');
    if (!value) return;
    if (type === 'ipv4' && isPrivateIpv4(value)) return;

    const key = `${type}:${value.toLowerCase()}`;
    if (!existingMap.has(key)) {
      existingMap.set(key, {
        value,
        defanged: defangIndicator(value),
        type,
        source,
        firstSeen: now
      });
    }
  };

  for (const match of text.match(URL_REGEX) || []) add(match, 'url');
  for (const match of text.match(IPV4_REGEX) || []) add(match, 'ipv4');
  for (const match of text.match(SHA256_REGEX) || []) add(match, 'sha256');
  for (const match of text.match(SHA1_REGEX) || []) add(match, 'sha1');
  for (const match of text.match(MD5_REGEX) || []) add(match, 'md5');
  for (const match of text.match(DOMAIN_REGEX) || []) add(match.toLowerCase(), 'domain');

  return existingMap;
}

export function extractIocsFromNetworkEvents(
  events: NetworkEvent[],
  existingMap = new Map<string, IocRecord>()
): Map<string, IocRecord> {
  const now = new Date().toISOString();

  for (const ev of events) {
    if (ev.remoteIPAddress && !isPrivateIpv4(ev.remoteIPAddress)) {
      const ipKey = `ipv4:${ev.remoteIPAddress}`;
      if (!existingMap.has(ipKey)) {
        existingMap.set(ipKey, {
          value: ev.remoteIPAddress,
          defanged: defangIndicator(ev.remoteIPAddress),
          type: 'ipv4',
          source: 'network',
          firstSeen: now
        });
      }
    }

    try {
      const parsed = new URL(ev.url);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        const domKey = `domain:${parsed.hostname.toLowerCase()}`;
        if (!existingMap.has(domKey)) {
          existingMap.set(domKey, {
            value: parsed.hostname.toLowerCase(),
            defanged: defangIndicator(parsed.hostname.toLowerCase()),
            type: 'domain',
            source: 'network',
            firstSeen: now
          });
        }
      }
    } catch {
      // Skip malformed URLs
    }
  }

  return existingMap;
}
