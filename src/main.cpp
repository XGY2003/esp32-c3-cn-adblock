// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include <time.h>
#include <ctype.h>
#include <atomic>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_sntp.h>
#include <esp_netif.h>
#include <esp_wifi.h>
#include "mbedtls/sha256.h"
#include "update-ca.h"           // UPDATE_ROOT_CA PEM, maintained with the deployment
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 223, 5, 5, 5                 // AliDNS (China)
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);
static const IPAddress UPSTREAM_BACKUP(119, 29, 29, 29);  // DNSPod
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const char* BLOCKLIST_NEW = "/blocklist.new";
static const char* BLOCKLIST_BACKUP = "/blocklist.bak";
static const size_t MAX_BLOCKLIST_BYTES = 550000;  // old + new must coexist on 4 MB boards
static const size_t FS_RESERVE_BYTES = 32768;
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t nextCheckMs = 0;
String updateStatus = "never";
static bool fsReady = false, dnsReady = false, updateBusy = false;
static volatile bool ntpSynced = false;

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
// Forward to upstream and wait for the reply that actually belongs to THIS query.
// Issue #10: after one timeout the late reply used to sit in the socket and get relayed
// to the next client (every answer shifted by one). Now: drain stale datagrams first,
// send with a fresh random txid, and only accept a reply whose txid, question section,
// and source address/port match. The client's own txid is restored on the way back.
static int forwardUpstream(int qlen, int qend) {
  if (qlen < 12 || qlen > (int)sizeof(buf)) return 0;
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  uint8_t q[260]; int ql = qend - 12;
  const bool haveQ = ql > 0 && ql <= (int)sizeof(q) && qend <= qlen;
  if (haveQ) memcpy(q, buf + 12, ql);
  uint8_t query[sizeof(buf)]; memcpy(query, buf, qlen);
  for (int attempt = 0; attempt < 2; attempt++) {
    const IPAddress& resolver = attempt ? UPSTREAM_BACKUP : UPSTREAM;
    upstreamCli.flush();
    while (upstreamCli.parsePacket() > 0) upstreamCli.flush();
    const uint16_t wid = (uint16_t)esp_random();
    query[0] = wid >> 8; query[1] = wid & 0xFF;
    upstreamCli.beginPacket(resolver, UPSTREAM_PORT); upstreamCli.write(query, qlen); upstreamCli.endPacket();
    const uint32_t t0 = millis();
    while (millis() - t0 < 600) {
      int sz = upstreamCli.parsePacket();
      if (sz <= 0) { delay(1); continue; }
      const bool fromUp = upstreamCli.remoteIP() == resolver && upstreamCli.remotePort() == UPSTREAM_PORT;
      int n = upstreamCli.read(buf, sizeof(buf));
      upstreamCli.flush();
      if (!fromUp || n < 12 || sz > (int)sizeof(buf)) continue;
      if (buf[0] != (wid >> 8) || buf[1] != (wid & 0xFF)) continue;
      if (haveQ && (n < 12 + ql || memcmp(buf + 12, q, ql) != 0)) continue;
      buf[0] = cid0; buf[1] = cid1;
      return n;
    }
  }
  return 0;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns(int queryBudget = 16) {
  bool did = false;
  for (int budget = 0; budget < queryBudget; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool ban = c && c->banned;
    bool blocked = ban || (blockingOn && dl && isBlocked(domain));
    int rlen;
    if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
    else         { rlen = forwardUpstream(qlen, qend);     totalAllowed++; if (c) c->allowed++; }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- verified blocklist transaction (upload + remote fetch) ----------
// Never remove the active list to make room. Each list is capped so two copies
// fit; a power cut during the two renames is recovered from .bak at boot.
static void serviceUpdateDns() {
  static uint32_t lastService = 0;
  if (dnsReady && millis() - lastService >= 20) {
    handleDns(1);  // Do not call web.handleClient(): that would re-enter updates.
    lastService = millis();
  }
  delay(0);
}
static bool inspectBlocklist(const char* path, String* digest = nullptr, bool serveDns = true) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  size_t size = f.size();
  if (!size || size > MAX_BLOCKLIST_BYTES || size % HASH_BYTES) { f.close(); return false; }
  mbedtls_sha256_context sha; mbedtls_sha256_init(&sha);
  bool ok = mbedtls_sha256_starts_ret(&sha, 0) == 0;
  uint8_t chunk[1000], hash[32];
  uint64_t previous = 0; bool first = true;
  size_t total = 0;
  while (ok && total < size) {
    size_t count = size - total; if (count > sizeof(chunk)) count = sizeof(chunk);
    if (f.read(chunk, count) != count || mbedtls_sha256_update_ret(&sha, chunk, count) != 0) { ok = false; break; }
    for (size_t i = 0; i < count; i += HASH_BYTES) {
      uint64_t value = unpackHash(chunk + i);
      if (!first && value <= previous) { ok = false; break; }
      previous = value; first = false;
    }
    total += count;
    if (serveDns) serviceUpdateDns();
  }
  if (ok) ok = mbedtls_sha256_finish_ret(&sha, hash) == 0;
  mbedtls_sha256_free(&sha); f.close();
  if (ok && digest) {
    char hex[65];
    for (size_t i = 0; i < sizeof(hash); i++) snprintf(hex + i * 2, 3, "%02x", hash[i]);
    hex[64] = 0; *digest = hex;
  }
  return ok;
}
static void reopenBlocklist() {
  if (blocklist) blocklist.close();
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (!blocklist && inspectBlocklist(BLOCKLIST_BACKUP, nullptr, false))
    blocklist = LittleFS.open(BLOCKLIST_BACKUP, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
static bool recoverBlocklist() {
  if (!fsReady) return false;
  bool liveOk = inspectBlocklist(BLOCKLIST_PATH, nullptr, false);
  if (!liveOk && inspectBlocklist(BLOCKLIST_BACKUP, nullptr, false)) {
    if (blocklist) blocklist.close();
    numHashes = 0;
    if (LittleFS.exists(BLOCKLIST_PATH) && !LittleFS.remove(BLOCKLIST_PATH)) {
      blocklist = LittleFS.open(BLOCKLIST_BACKUP, "r");
      numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0; buildFlashIndex();
      return false;
    }
    liveOk = LittleFS.rename(BLOCKLIST_BACKUP, BLOCKLIST_PATH);
    if (!liveOk) { reopenBlocklist(); return false; }
  }
  // A staging file is never trusted after reboot, even if it is well formed:
  // its remote digest and complete HTTP transfer have not been committed.
  LittleFS.remove(BLOCKLIST_NEW);
  if (liveOk) reopenBlocklist();
  else { if (blocklist) blocklist.close(); numHashes = 0; }
  return liveOk;
}
static bool beginBlocklistSwap() {
  if (!fsReady) { updateStatus = "filesystem unavailable"; return false; }
  if (LittleFS.exists(BLOCKLIST_NEW) && !LittleFS.remove(BLOCKLIST_NEW)) {
    updateStatus = "staging cleanup failed"; return false;
  }
  // A previous successful update may have left a backup. Remove it only while
  // there is a verified live copy; otherwise recover it before staging.
  if (LittleFS.exists(BLOCKLIST_BACKUP)) {
    if (!inspectBlocklist(BLOCKLIST_PATH)) {
      if (!recoverBlocklist()) { updateStatus = "backup recovery failed"; return false; }
    }
    if (LittleFS.exists(BLOCKLIST_BACKUP) && !LittleFS.remove(BLOCKLIST_BACKUP)) {
      updateStatus = "backup cleanup failed"; return false;
    }
  }
  if (LittleFS.totalBytes() - LittleFS.usedBytes() < MAX_BLOCKLIST_BYTES + FS_RESERVE_BYTES) {
    updateStatus = "not enough space for safe update"; return false;
  }
  return true;
}
static bool commitNewBlocklist(const String* expectedDigest = nullptr) {
  String digest;
  if (!inspectBlocklist(BLOCKLIST_NEW, &digest) || (expectedDigest && digest != *expectedDigest)) {
    LittleFS.remove(BLOCKLIST_NEW); updateStatus = "invalid list or SHA256 mismatch"; return false;
  }
  if (blocklist) blocklist.close(); numHashes = 0;
  bool hadLive = LittleFS.exists(BLOCKLIST_PATH);
  if (hadLive && !LittleFS.rename(BLOCKLIST_PATH, BLOCKLIST_BACKUP)) {
    reopenBlocklist(); updateStatus = "backup rename failed"; return false;
  }
  if (!LittleFS.rename(BLOCKLIST_NEW, BLOCKLIST_PATH)) {
    // If this rollback rename also fails, .bak remains available at next boot.
    if (hadLive) LittleFS.rename(BLOCKLIST_BACKUP, BLOCKLIST_PATH);
    reopenBlocklist(); updateStatus = "activation rename failed"; return false;
  }
  reopenBlocklist();
  return numHashes > 0;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static bool upWriteOk = false;
static size_t upBytes = 0;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: incomplete, oversized, unsorted, or filesystem error; previous list retained");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; upWriteOk = false; upBytes = 0;
      if (updateBusy || !beginBlocklistSwap()) break;
      updateBusy = true;
      upFile = LittleFS.open(BLOCKLIST_NEW, "w"); upWriteOk = (bool)upFile;
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upWriteOk && upFile) {
        if (u.currentSize > MAX_BLOCKLIST_BYTES - upBytes || upFile.write(u.buf, u.currentSize) != u.currentSize) upWriteOk = false;
        else upBytes += u.currentSize;
        serviceUpdateDns();
      }
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = updateBusy && upWriteOk && upBytes == u.totalSize && commitNewBlocklist();
      if (!upOk) LittleFS.remove(BLOCKLIST_NEW);
      updateBusy = false;
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove(BLOCKLIST_NEW); updateBusy = false;
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static bool setStationResolvers() {
  // The router may hand this board its own DNS address over DHCP. Give the
  // board's HTTP/NTP resolver independent upstreams without disabling DHCP.
  esp_netif_t* station = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (!station) return false;
  esp_netif_dns_info_t dns = {};
  dns.ip.type = ESP_IPADDR_TYPE_V4;
  dns.ip.u_addr.ip4.addr = static_cast<uint32_t>(UPSTREAM);
  bool mainOk = esp_netif_set_dns_info(station, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK;
  dns.ip.u_addr.ip4.addr = static_cast<uint32_t>(UPSTREAM_BACKUP);
  bool backupOk = esp_netif_set_dns_info(station, ESP_NETIF_DNS_BACKUP, &dns) == ESP_OK;
  return mainOk && backupOk;
}
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); long hours = iv.toInt();
  if (hours >= 1 && hours <= 168) updateIntervalH = (uint32_t)hours;
  f.close();
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool isHttpsUrl(const String& url) {
  if (!url.startsWith("https://") || url.length() > 2048 || url.length() < 10) return false;
  if (url.indexOf('\r') >= 0 || url.indexOf('\n') >= 0 || url.indexOf(' ') >= 0 || url.indexOf('#') >= 0) return false;
  int slash = url.indexOf('/', 8);
  String authority = slash < 0 ? url.substring(8) : url.substring(8, slash);
  return authority.length() && authority.indexOf('@') < 0;
}
struct HttpGetJob {
  HTTPClient* http = nullptr;
  int code = 0;
  std::atomic<bool> done{false};
};
static void runHttpGet(void* parameter) {
  HttpGetJob* job = static_cast<HttpGetJob*>(parameter);
  job->code = job->http->GET();
  job->done.store(true, std::memory_order_release);
  // The caller can release the job once done is published. Never touch it again.
  vTaskDelete(nullptr);
}
static bool getWithDnsService(HTTPClient& http, int& code) {
  HttpGetJob job; job.http = &http;
  // ESP-IDF specifies task stack size in bytes. Only GET (DNS/TLS/headers)
  // runs on this temporary worker; the caller retains all filesystem/state work.
  if (xTaskCreate(runHttpGet, "rule-https", 16 * 1024, &job, 1, nullptr) != pdPASS) {
    updateStatus = "HTTPS worker allocation failed"; return false;
  }
  while (!job.done.load(std::memory_order_acquire)) {
    serviceUpdateDns();
    delay(1);
  }
  // Do not abandon this stack job while GET is active. HTTPClient owns its
  // configured connection/read timeouts; access resumes only after completion.
  code = job.code;
  delay(1);  // Let the worker finish deletion and the idle task reclaim its stack.
  return true;
}
static bool openVerifiedHttps(HTTPClient& http, WiFiClientSecure& tls, String url) {
  tls.setCACert(UPDATE_ROOT_CA);
  tls.setHandshakeTimeout(8);
  http.setConnectTimeout(8000); http.setTimeout(8000);
  http.setReuse(false); http.useHTTP10(true);  // require a bounded, unencoded body
  http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
  const char* headers[] = { "Location", "Transfer-Encoding", "Content-Encoding" };
  http.collectHeaders(headers, 3);
  for (int redirects = 0; redirects <= 3; redirects++) {
    if (!isHttpsUrl(url)) { updateStatus = "HTTPS URL required (redirect rejected)"; return false; }
    if (!http.begin(tls, url)) { updateStatus = "HTTPS begin failed"; return false; }
    int code = 0;
    if (!getWithDnsService(http, code)) { http.end(); return false; }
    if (code < 0) {
      char detail[100] = {};
      int tlsError = tls.lastError(detail, sizeof(detail));
      Serial.printf("[remote] HTTP %d, TLS %d: %s; free heap %u\n", code, tlsError, detail, ESP.getFreeHeap());
      http.end();
      updateStatus = "transport " + String(code) + ", TLS " + String(tlsError) + ": " + String(detail);
      return false;
    }
    if (code == HTTP_CODE_OK) {
      String transfer = http.header("Transfer-Encoding"), encoding = http.header("Content-Encoding");
      if (transfer.length() || (encoding.length() && !encoding.equalsIgnoreCase("identity"))) {
        http.end(); updateStatus = "encoded or chunked body unsupported"; return false;
      }
      return true;
    }
    bool redirect = code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    String location = http.header("Location");
    http.end();
    if (!redirect || redirects == 3 || !isHttpsUrl(location)) {
      updateStatus = redirect ? "redirect limit or non-HTTPS redirect" : ("HTTPS HTTP " + String(code));
      return false;
    }
    url = location;
    serviceUpdateDns();
  }
  return false;
}
static bool readUpdateBody(HTTPClient& http, size_t expected, File* file, String* text) {
  WiFiClient* stream = http.getStreamPtr();
  uint8_t chunk[1024]; size_t total = 0;
  uint32_t started = millis(), idle = started;
  while (total < expected && millis() - started < 120000UL) {
    size_t available = stream->available();
    if (available) {
      size_t count = expected - total;
      if (count > available) count = available;
      if (count > sizeof(chunk)) count = sizeof(chunk);
      int received = stream->read(chunk, count);
      if (received <= 0) { updateStatus = "download read failed"; return false; }
      if (file && file->write(chunk, received) != (size_t)received) { updateStatus = "filesystem short write"; return false; }
      if (text) for (int i = 0; i < received; i++) *text += (char)chunk[i];
      total += received; idle = millis();
    } else {
      if (!http.connected() || millis() - idle >= 15000UL) break;
      delay(1);
    }
    serviceUpdateDns();
  }
  if (total != expected) { updateStatus = "incomplete download"; return false; }
  return true;
}
static bool fetchBlocklistInternal(String url) {
  url.trim();
  if (!isHttpsUrl(url) || url.indexOf('?') >= 0) { updateStatus = "stable HTTPS URL without query required"; return false; }
  if (!fsReady || WiFi.status() != WL_CONNECTED) { updateStatus = "filesystem or WiFi unavailable"; return false; }
  if (!setStationResolvers()) { updateStatus = "station DNS configuration failed"; return false; }
  // TLS certificate validity is checked against synchronized time. Never use
  // setInsecure() as a fallback if NTP, DNS, or a certificate check fails.
  if (!ntpSynced || time(nullptr) < 1735689600) { updateStatus = "waiting for NTP time"; return false; }
  WiFiClientSecure tls; HTTPClient http;
  if (!openVerifiedHttps(http, tls, url + ".sha256")) return false;
  int length = http.getSize(); String expected;
  if (length < 64 || length > 66) { http.end(); updateStatus = "invalid SHA256 length"; return false; }
  bool readOk = readUpdateBody(http, length, nullptr, &expected); http.end();
  if (!readOk) return false;
  if (expected.endsWith("\n")) expected.remove(expected.length() - 1);
  if (expected.endsWith("\r")) expected.remove(expected.length() - 1);
  if (expected.length() != 64) { updateStatus = "invalid SHA256 file"; return false; }
  for (size_t i = 0; i < expected.length(); i++) {
    if (!isxdigit((unsigned char)expected[i])) { updateStatus = "invalid SHA256 hex"; return false; }
  }
  expected.toLowerCase();
  String current;
  if (inspectBlocklist(BLOCKLIST_PATH, &current) && current == expected) {
    updateStatus = "unchanged (SHA256 verified)"; return true;
  }
  if (!openVerifiedHttps(http, tls, url)) return false;
  length = http.getSize();
  if (length <= 0 || length > (int)MAX_BLOCKLIST_BYTES || length % HASH_BYTES) {
    http.end(); updateStatus = "missing, oversized, or invalid Content-Length"; return false;
  }
  if (!beginBlocklistSwap()) { http.end(); return false; }
  File file = LittleFS.open(BLOCKLIST_NEW, "w");
  if (!file) { http.end(); updateStatus = "staging open failed"; return false; }
  readOk = readUpdateBody(http, length, &file, nullptr);
  file.flush(); file.close(); http.end();
  if (!readOk) { LittleFS.remove(BLOCKLIST_NEW); return false; }
  if (!commitNewBlocklist(&expected)) return false;
  updateStatus = "ok: " + String(numHashes) + " domains (SHA256 verified)";
  return true;
}
static bool fetchBlocklist(String url) {
  if (updateBusy) { updateStatus = "update already active"; return false; }
  updateBusy = true;
  bool ok = fetchBlocklistInternal(url);
  updateBusy = false;
  nextCheckMs = millis() + (ok ? updateIntervalH * 3600000UL : 900000UL);
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.setAutoReconnect(true);
  WiFi.onEvent([](WiFiEvent_t) { setStationResolvers(); }, ARDUINO_EVENT_WIFI_STA_GOT_IP);
  // Arduino 2.0.17 leaves SAE PWE at its IDF default. Configure credentials
  // without connecting first, then explicitly enable H2E + Hunt-and-Peck so
  // WPA3 H2E-only routers work (Espressif advisory AR2026-003, issue 4.1).
  // This path is shared by secrets.h and credentials saved by the portal.
  if (WiFi.begin(ssid, pass, 0, nullptr, false) == WL_CONNECT_FAILED) {
    Serial.println("[wifi] station credential configuration failed"); return false;
  }
  wifi_config_t stationConfig = {};
  if (esp_wifi_get_config(WIFI_IF_STA, &stationConfig) != ESP_OK) {
    Serial.println("[wifi] station configuration read failed"); return false;
  }
  stationConfig.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
  if (esp_wifi_set_config(WIFI_IF_STA, &stationConfig) != ESP_OK || esp_wifi_connect() != ESP_OK) {
    Serial.println("[wifi] station H2E configuration or connection start failed"); return false;
  }
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  bool connected = WiFi.status() == WL_CONNECTED;
  if (connected && !setStationResolvers()) Serial.println("[wifi] station DNS configuration failed");
  return connected;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");
  fsReady = LittleFS.begin(false);  // Never auto-format a failed mount and erase recovery data.
  if (!fsReady) Serial.println("LittleFS mount FAILED; retained flash, updates disabled");
  else {
    if (!recoverBlocklist()) Serial.println("Blocklist recovery incomplete; backup retained if present, check filesystem");
    Serial.printf("blocklist: %u domains\n", numHashes);
    loadCustom(); loadBanned(); loadUpdateCfg();
  }
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 BOOT button
#else
  const int BOOT_PIN = 0;     // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  sntp_set_time_sync_notification_cb([](struct timeval* value) {
    ntpSynced = value && value->tv_sec >= 1735689600;
  });
  configTime(0, 0, "ntp.aliyun.com", "ntp.tencent.com");
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0); dnsReady = true;
  nextCheckMs = millis() + 60000UL;  // First subscription check one minute after WiFi is ready.
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() { if (!requireAuth()) return; addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() {
    if (!requireAuth()) return;
    bool ok = fetchBlocklist(updateUrl);
    web.send(ok ? 200 : 502, "text/plain", updateStatus);
  });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    String candidate = web.hasArg("u") ? web.arg("u") : updateUrl; candidate.trim();
    long hours = web.hasArg("h") ? web.arg("h").toInt() : (long)updateIntervalH;
    if ((candidate.length() && (!isHttpsUrl(candidate) || candidate.indexOf('?') >= 0)) || hours < 1 || hours > 168) {
      web.send(400, "text/plain", "stable HTTPS URL without query and interval 1..168 hours required"); return;
    }
    updateUrl = candidate; updateIntervalH = (uint32_t)hours;
    nextCheckMs = millis() + 60000UL;
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  static uint32_t lastDnsConfigMs = 0;
  if (WiFi.status() == WL_CONNECTED && millis() - lastDnsConfigMs >= 30000UL) {
    // Reapply after a DHCP lease renewal even if the IP itself did not change.
    if (WiFi.dnsIP(0) != UPSTREAM || WiFi.dnsIP(1) != UPSTREAM_BACKUP) setStationResolvers();
    lastDnsConfigMs = millis();
  }
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length() && !updateBusy) {  // scheduled refresh; failures retry after 15 minutes
    uint32_t now = millis();
    if ((int32_t)(now - nextCheckMs) >= 0) fetchBlocklist(updateUrl);
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
