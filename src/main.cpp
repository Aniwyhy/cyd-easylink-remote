// Philips TV remote ("EasyLink") for the 4" CYD (ESP32-3248S040: ST7796 320x480 portrait, XPT2046 touch).
//
// The CYD has no HDMI, so instead of CEC it talks to the TV over WiFi with Philips's JointSpace API:
//  - 2016+ Android/Google TVs: HTTPS on port 1926, digest auth, one-time PIN pairing (API 6).
//  - Older TVs: plain HTTP on port 1925, no pairing (API 1/5).
// First boot: the board opens a WiFi hotspot (QR on screen) to pick your WiFi, then searches for the
// TV and asks for the PIN the TV shows. Everything is stored in NVS.
// Hold BOOT for 2 s to recalibrate touch.

#include <Arduino.h>
#include <LovyanGFX.hpp>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <MD5Builder.h>
#include <mbedtls/md.h>
#include <mbedtls/base64.h>
#include <lwip/sockets.h>
#include <lwip/etharp.h>
#include <vector>

// ---------------------------------------------------------------- display
class LGFX : public lgfx::LGFX_Device {
  lgfx::Panel_ST7796 _panel;
  lgfx::Bus_SPI _bus;
  lgfx::Light_PWM _light;
  lgfx::Touch_XPT2046 _touch;

 public:
  LGFX() {
    auto b = _bus.config();
    b.spi_host = HSPI_HOST;
    b.spi_mode = 0;
    b.freq_write = 40000000;
    b.freq_read = 16000000;
    b.pin_sclk = 14;
    b.pin_mosi = 13;
    b.pin_miso = 12;
    b.pin_dc = 2;
    _bus.config(b);
    _panel.setBus(&_bus);
    auto p = _panel.config();
    p.pin_cs = 15;
    p.pin_rst = -1;
    p.panel_width = 320;
    p.panel_height = 480;
    p.readable = true;
    p.bus_shared = true;
    _panel.config(p);
    auto l = _light.config();
    l.pin_bl = 27;
    l.freq = 44100;
    l.pwm_channel = 7;
    _light.config(l);
    _panel.setLight(&_light);
    auto t = _touch.config();
    t.x_min = 300;
    t.x_max = 3900;
    t.y_min = 200;
    t.y_max = 3900;
    t.pin_int = -1;
    t.bus_shared = true;
    t.offset_rotation = 0;
    t.spi_host = HSPI_HOST;
    t.freq = 1000000;
    t.pin_sclk = 14;
    t.pin_mosi = 13;
    t.pin_miso = 12;
    t.pin_cs = 33;
    _touch.config(t);
    _panel.setTouch(&_touch);
    setPanel(&_panel);
  }
};

static LGFX tft;
static Preferences prefs;
static const int SCR_W = 320, SCR_H = 480;

// ---------------------------------------------------------------- palette
static constexpr uint32_t C_BG = 0x121314;
static constexpr uint32_t C_KEYBG = 0x26282B;
static constexpr uint32_t C_KEY_HI = 0x4A4E54;
static constexpr uint32_t C_RING = 0x1E2023;
static constexpr uint32_t C_FG = 0xF2F3F5;
static constexpr uint32_t C_DIM = 0x8D9299;
static constexpr uint32_t C_FAINT = 0x50555C;
static constexpr uint32_t C_ACCENT = 0x3D8BFF;   // Philips-ish blue
static constexpr uint32_t C_ACCENT_HI = 0x6AA6FF;
static constexpr uint32_t C_POWERBG = 0xD9453F;
static constexpr uint32_t C_POWER_HI = 0xF06A64;
static constexpr uint32_t C_OK = 0x3FBF6A;
static constexpr uint32_t C_AMBER = 0xE8A33A;
static constexpr uint32_t C_RED = 0xD8433D, C_GREEN = 0x2FA457, C_YELLOW = 0xE3C02D, C_BLUE = 0x2F6FDB;

static const lgfx::IFont* F_TITLE = &fonts::FreeSansBold12pt7b;
static const lgfx::IFont* F_BIG = &fonts::FreeSansBold18pt7b;
static const lgfx::IFont* F_UI = &fonts::FreeSans9pt7b;
static const lgfx::IFont* F_UIB = &fonts::FreeSansBold9pt7b;
static const lgfx::IFont* F_KEY = &fonts::FreeSansBold12pt7b;

static uint32_t mix(uint32_t a, uint32_t b, float t) {
  auto ch = [&](int s) { return (uint32_t)(((a >> s) & 0xFF) * (1 - t) + ((b >> s) & 0xFF) * t) << s; };
  return ch(16) | ch(8) | ch(0);
}

// ---------------------------------------------------------------- TV connection (JointSpace)
struct TvConn {
  String ip;
  uint16_t port = 1925;
  bool https = false;
  int api = 6;
  String user, pass;  // digest credentials from pairing (https only)

  WiFiClientSecure tls;
  WiFiClient plain;
  String realm, nonce, opaque;
  bool qop = false;
  uint32_t nc = 0;

  Client& sock() { return https ? (Client&)tls : (Client&)plain; }
  void hangup() { tls.stop(); plain.stop(); }

  bool ensure() {
    if (sock().connected()) return true;
    sock().stop();
    if (https) {
      tls.setInsecure();  // the TV uses a self-signed certificate
      tls.setHandshakeTimeout(6);
      return tls.connect(ip.c_str(), port, 4000);
    }
    return plain.connect(ip.c_str(), port, 1500);
  }

  static bool readLine(Client& c, String& line, uint32_t deadline) {
    line = "";
    while ((int32_t)(deadline - millis()) > 0) {
      while (c.available()) {
        char ch = c.read();
        if (ch == '\n') { line.trim(); return true; }
        if (line.length() < 2048) line += ch;
      }
      if (!c.connected()) return false;
      delay(1);
    }
    return false;
  }

  static bool readN(Client& c, String& out, int n, uint32_t deadline) {
    while (n > 0 && (int32_t)(deadline - millis()) > 0) {
      int a = c.available();
      if (a <= 0) {
        if (!c.connected()) return false;
        delay(1);
        continue;
      }
      char buf[256];
      int r = c.read((uint8_t*)buf, min(n, min(a, (int)sizeof(buf))));
      if (r <= 0) continue;
      if (out.length() < 16384) out.concat(buf, r);
      n -= r;
    }
    return n == 0;
  }

  void parseChallenge(const String& h) {
    realm = nonce = opaque = "";
    qop = false;
    int i = h.indexOf(' ');
    while (i >= 0 && i < (int)h.length()) {
      while (i < (int)h.length() && (h[i] == ' ' || h[i] == ',')) i++;
      int eq = h.indexOf('=', i);
      if (eq < 0) break;
      String k = h.substring(i, eq);
      k.trim();
      String v;
      int j = eq + 1;
      if (j < (int)h.length() && h[j] == '"') {
        int e = h.indexOf('"', j + 1);
        if (e < 0) e = h.length();
        v = h.substring(j + 1, e);
        i = e + 1;
      } else {
        int e = h.indexOf(',', j);
        if (e < 0) e = h.length();
        v = h.substring(j, e);
        v.trim();
        i = e;
      }
      k.toLowerCase();
      if (k == "realm") realm = v;
      else if (k == "nonce") nonce = v;
      else if (k == "opaque") opaque = v;
      else if (k == "qop") qop = v.indexOf("auth") >= 0;
    }
    nc = 0;
  }

  static String md5(const String& s) {
    MD5Builder m;
    m.begin();
    m.add(s);
    m.calculate();
    return m.toString();
  }

  String authHeader(const char* method, const String& uri) {
    nc++;
    char ncs[9], cn[17];
    snprintf(ncs, sizeof ncs, "%08x", (unsigned)nc);
    snprintf(cn, sizeof cn, "%08x%08x", (unsigned)esp_random(), (unsigned)esp_random());
    String ha1 = md5(user + ":" + realm + ":" + pass);
    String ha2 = md5(String(method) + ":" + uri);
    String resp = qop ? md5(ha1 + ":" + nonce + ":" + ncs + ":" + cn + ":auth:" + ha2) : md5(ha1 + ":" + nonce + ":" + ha2);
    String h = "Digest username=\"" + user + "\", realm=\"" + realm + "\", nonce=\"" + nonce + "\", uri=\"" + uri +
               "\", algorithm=MD5, response=\"" + resp + "\"";
    if (opaque.length()) h += ", opaque=\"" + opaque + "\"";
    if (qop) h += ", qop=auth, nc=" + String(ncs) + ", cnonce=\"" + cn + "\"";
    return h;
  }

  // One round trip. Returns HTTP status, or -1 (no connection) / -2 (broken response).
  int once(const char* method, const String& uri, const String& body, bool auth, String& out, String& wwwAuth, uint32_t timeout) {
    out = "";
    wwwAuth = "";
    if (!ensure()) { sock().stop(); return -1; }
    Client& c = sock();
    String req = String(method) + " " + uri + " HTTP/1.1\r\nHost: " + ip + ":" + port +
                 "\r\nConnection: keep-alive\r\nAccept: application/json\r\n";
    if (auth && user.length() && nonce.length()) req += "Authorization: " + authHeader(method, uri) + "\r\n";
    if (body.length() || strcmp(method, "POST") == 0)
      req += "Content-Type: application/json\r\nContent-Length: " + String(body.length()) + "\r\n";
    req += "\r\n";
    req += body;
    if (c.write((const uint8_t*)req.c_str(), req.length()) != req.length()) { c.stop(); return -2; }

    uint32_t deadline = millis() + timeout;
    String line;
    if (!readLine(c, line, deadline) || !line.startsWith("HTTP/")) { c.stop(); return -2; }
    int code = line.substring(line.indexOf(' ') + 1).toInt();
    int len = -1;
    bool chunked = false, keep = true;
    while (true) {
      if (!readLine(c, line, deadline)) { c.stop(); return -2; }
      if (!line.length()) break;
      int colon = line.indexOf(':');
      if (colon < 0) continue;
      String k = line.substring(0, colon), v = line.substring(colon + 1);
      k.toLowerCase();
      v.trim();
      if (k == "content-length") len = v.toInt();
      else if (k == "transfer-encoding" && v.indexOf("chunked") >= 0) chunked = true;
      else if (k == "connection" && v.equalsIgnoreCase("close")) keep = false;
      else if (k == "www-authenticate" && v.startsWith("Digest")) wwwAuth = v;
    }
    bool ok = true;
    if (chunked) {
      while (true) {
        if (!readLine(c, line, deadline)) { ok = false; break; }
        int n = strtol(line.c_str(), nullptr, 16);
        if (n <= 0) { readLine(c, line, deadline); break; }
        if (!readN(c, out, n, deadline) || !readLine(c, line, deadline)) { ok = false; break; }
      }
    } else if (len >= 0) {
      ok = readN(c, out, len, deadline);
    } else if (code != 204 && code != 304) {
      while (c.connected() && (int32_t)(deadline - millis()) > 0) readN(c, out, 1, millis() + 200);
      keep = false;
    }
    if (!ok || !keep) c.stop();
    return code;
  }

  // Request with digest auth; reconnects once if a kept-alive socket went stale.
  int request(const char* method, const String& path, const String& body, String& out, bool auth = true, uint32_t timeout = 4000) {
    String uri = path.startsWith("/") ? path : "/" + String(api) + "/" + path;
    String www;
    int code = -1;
    bool fresh = false;
    for (int attempt = 0; attempt < 3; attempt++) {
      code = once(method, uri, body, auth, out, www, timeout);
      if (code == -2) { hangup(); continue; }
      if (code == 401 && auth && user.length() && www.length() && !fresh) {
        parseChallenge(www);
        fresh = true;
        continue;
      }
      break;
    }
    return code;
  }
};

static TvConn tv;
static SemaphoreHandle_t netMx;
static String tvName, tvMac;

static void saveTv() {
  prefs.putString("tv_ip", tv.ip);
  prefs.putUShort("tv_port", tv.port);
  prefs.putBool("tv_https", tv.https);
  prefs.putInt("tv_api", tv.api);
  prefs.putString("tv_user", tv.user);
  prefs.putString("tv_pass", tv.pass);
  prefs.putString("tv_name", tvName);
  prefs.putString("tv_mac", tvMac);
}
static void loadTv() {
  tv.ip = prefs.getString("tv_ip", "");
  tv.port = prefs.getUShort("tv_port", 1925);
  tv.https = prefs.getBool("tv_https", false);
  tv.api = prefs.getInt("tv_api", 6);
  tv.user = prefs.getString("tv_user", "");
  tv.pass = prefs.getString("tv_pass", "");
  tvName = prefs.getString("tv_name", "Philips TV");
  tvMac = prefs.getString("tv_mac", "");
}
static bool tvReady() { return tv.ip.length() && (!tv.https || tv.user.length()); }

// ---------------------------------------------------------------- discovery
struct Found { String ip, name; int api; bool https; };
static std::vector<Found> found;

// Ask http://ip:1925/<v>/system like the Philips apps do.
static bool probeTv(const String& ip, Found& f) {
  TvConn t;
  t.ip = ip;
  t.port = 1925;
  t.https = false;
  const int vers[] = {6, 5, 1};
  for (int v : vers) {
    String body;
    int code = t.request("GET", "/" + String(v) + "/system", "", body, false, 1500);
    if (code < 0) break;  // nothing listening
    if (code != 200) continue;
    JsonDocument d;
    if (deserializeJson(d, body)) continue;
    f.ip = ip;
    f.api = d["api_version"]["Major"] | v;
    const char* nm = d["name"] | "";
    f.name = strlen(nm) ? nm : "Philips TV";
    String pt = d["featuring"]["systemfeatures"]["pairing_type"] | "";
    f.https = pt == "digest_auth_pairing";
    t.hangup();
    return true;
  }
  t.hangup();
  // Some sets only answer on the HTTPS port
  t.https = true;
  t.port = 1926;
  String body;
  if (t.request("GET", "/6/system", "", body, false, 3000) == 200) {
    JsonDocument d;
    deserializeJson(d, body);
    f.ip = ip;
    f.api = d["api_version"]["Major"] | 6;
    const char* nm = d["name"] | "";
    f.name = strlen(nm) ? nm : "Philips TV";
    f.https = true;
    t.hangup();
    return true;
  }
  t.hangup();
  return false;
}

static void addFound(const Found& f) {
  for (auto& x : found)
    if (x.ip == f.ip) return;
  found.push_back(f);
}

// SSDP M-SEARCH: Philips sets answer as DIAL/UPnP renderers. Returns the IPs that replied.
static std::vector<String> ssdpScan(uint32_t ms) {
  std::vector<String> ips;
  WiFiUDP u;
  if (!u.begin(1901 + (esp_random() % 1000))) return ips;
  const char* msg =
      "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
  for (int i = 0; i < 2; i++) {
    u.beginPacket(IPAddress(239, 255, 255, 250), 1900);
    u.write((const uint8_t*)msg, strlen(msg));
    u.endPacket();
    delay(30);
  }
  uint32_t t0 = millis();
  while (millis() - t0 < ms) {
    int n = u.parsePacket();
    if (n > 0) {
      String ip = u.remoteIP().toString();
      u.flush();
      bool dup = false;
      for (auto& x : ips) dup |= x == ip;
      if (!dup && ip != WiFi.localIP().toString()) ips.push_back(ip);
    }
    delay(5);
  }
  u.stop();
  return ips;
}

// Fallback: connect to port 1925 across the /24, a few sockets at a time.
template <typename CB>
static std::vector<String> portScan(CB progress) {
  std::vector<String> hits;
  IPAddress me = WiFi.localIP();
  const int B = 6;
  for (int start = 1; start < 255; start += B) {
    progress(start * 100 / 254);
    int fds[B], host[B], n = 0;
    for (int h = start; h < start + B && h < 255; h++) {
      if (h == me[3]) continue;
      int s = socket(AF_INET, SOCK_STREAM, 0);
      if (s < 0) break;
      fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
      sockaddr_in a = {};
      a.sin_family = AF_INET;
      a.sin_port = htons(1925);
      a.sin_addr.s_addr = (uint32_t)IPAddress(me[0], me[1], me[2], h);
      connect(s, (sockaddr*)&a, sizeof a);
      fds[n] = s;
      host[n] = h;
      n++;
    }
    bool done[B] = {};
    uint32_t t0 = millis();
    while (millis() - t0 < 400) {
      fd_set w;
      FD_ZERO(&w);
      int mx = -1;
      for (int i = 0; i < n; i++)
        if (!done[i]) { FD_SET(fds[i], &w); mx = max(mx, fds[i]); }
      if (mx < 0) break;
      timeval tvl = {0, 40000};
      if (select(mx + 1, nullptr, &w, nullptr, &tvl) <= 0) continue;
      for (int i = 0; i < n; i++) {
        if (done[i] || !FD_ISSET(fds[i], &w)) continue;
        done[i] = true;
        int err = 0;
        socklen_t l = sizeof err;
        getsockopt(fds[i], SOL_SOCKET, SO_ERROR, &err, &l);
        if (!err) hits.push_back(IPAddress(me[0], me[1], me[2], host[i]).toString());
      }
    }
    for (int i = 0; i < n; i++) close(fds[i]);
  }
  return hits;
}

// ---------------------------------------------------------------- pairing (API 6)
static const char* PAIR_SECRET = "JCqdN5AcnAHgJYseUn7ER5k3qgtemfUvMRghQpTfTZq7Cvv8EPQPqfz6dDxPQPSu4gKFPWkJGw32zyASgJkHwCjU";
static String pairDevId, pairAuthKey, pairTimestamp, pairError;

static String deviceJson(const String& id) {
  return "{\"device_name\":\"heliotrope\",\"device_os\":\"Android\",\"app_name\":\"CYD Remote\",\"type\":\"native\","
         "\"app_id\":\"app.id\",\"id\":\"" + id + "\"}";
}

static String hmacSignature(const String& msg) {
  uint8_t key[96];
  size_t klen = 0;
  mbedtls_base64_decode(key, sizeof key, &klen, (const uint8_t*)PAIR_SECRET, strlen(PAIR_SECRET));
  uint8_t mac[20];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), key, klen, (const uint8_t*)msg.c_str(), msg.length(), mac);
  char hex[41];
  for (int i = 0; i < 20; i++) sprintf(hex + i * 2, "%02x", mac[i]);
  uint8_t b64[64];
  size_t blen = 0;
  mbedtls_base64_encode(b64, sizeof b64, &blen, (const uint8_t*)hex, 40);
  return String((const char*)b64).substring(0, blen);
}

static bool pairRequest() {
  const char* al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  pairDevId = "";
  for (int i = 0; i < 16; i++) pairDevId += al[esp_random() % 62];
  String body = "{\"scope\":[\"read\",\"write\",\"control\"],\"device\":" + deviceJson(pairDevId) + "}", out;
  xSemaphoreTake(netMx, portMAX_DELAY);
  tv.user = tv.pass = "";
  tv.hangup();
  int code = tv.request("POST", "pair/request", body, out, false, 6000);
  xSemaphoreGive(netMx);
  Serial.printf("[pair] request -> %d %s\n", code, out.c_str());
  JsonDocument d;
  if (code != 200 || deserializeJson(d, out)) {
    pairError = code < 0 ? "The TV didn't answer. Is it on?" : "The TV refused (HTTP " + String(code) + ")";
    return false;
  }
  String err = d["error_id"] | "";
  if (err != "SUCCESS") {
    pairError = err == "CONCURRENT_PAIRING" ? "Another pairing is in progress on the TV" : "The TV said " + err;
    return false;
  }
  pairAuthKey = d["auth_key"] | "";
  pairTimestamp = "";
  serializeJson(d["timestamp"], pairTimestamp);
  pairTimestamp.replace("\"", "");
  return pairAuthKey.length() > 0;
}

static bool pairGrant(const String& pin) {
  String auth = "{\"auth_AppId\":\"1\",\"pin\":\"" + pin + "\",\"auth_timestamp\":" + pairTimestamp +
                ",\"auth_signature\":\"" + hmacSignature(pairTimestamp + pin) + "\"}";
  String body = "{\"auth\":" + auth + ",\"device\":" + deviceJson(pairDevId) + "}", out;
  xSemaphoreTake(netMx, portMAX_DELAY);
  tv.user = pairDevId;
  tv.pass = pairAuthKey;
  tv.nonce = "";
  int code = tv.request("POST", "pair/grant", body, out, true, 6000);
  Serial.printf("[pair] grant -> %d %s\n", code, out.c_str());
  bool ok = code == 200 && out.indexOf("INVALID") < 0 && out.indexOf("FAIL") < 0;
  if (ok) {  // the new credentials must open a protected endpoint
    String vb;
    int vc = tv.request("GET", "audio/volume", "", vb);
    Serial.printf("[pair] verify -> %d\n", vc);
    if (vc == 401) ok = false;
  }
  if (!ok) tv.user = tv.pass = "";
  xSemaphoreGive(netMx);
  if (!ok) pairError = code == 200 ? "Wrong PIN" : code < 0 ? "Lost the TV during pairing" : "Pairing failed (HTTP " + String(code) + ")";
  return ok;
}

// ---------------------------------------------------------------- network worker (core 0)
enum CmdType : uint8_t { CM_KEY, CM_POWER, CM_AMBI, CM_SOURCES, CM_POLL };
struct Cmd { CmdType type; char key[24]; };
static QueueHandle_t cmdQ;

enum TvState : int { TS_UNKNOWN, TS_ON, TS_STANDBY, TS_OFFLINE, TS_AUTH };
static volatile int tvState = TS_UNKNOWN;
static volatile bool stateDirty = true, macDirty = false;
static volatile bool volFresh = false;
static volatile int volCur = 0, volMax = 60;
static volatile bool volMuted = false;
static volatile bool busy = false;
static volatile bool workerOn = false;   // remote screens active
static volatile bool screenAwake = true;
static uint32_t wakeSentAt = 0;

static void setState(int s) {
  if (tvState != s) { tvState = s; stateDirty = true; }
}

static void stateFromCode(int code) {
  if (code < 0) setState(TS_OFFLINE);
  else if (code == 401) setState(TS_AUTH);
}

static void sendKey(const char* k) {
  String out;
  int code = tv.request("POST", "input/key", String("{\"key\":\"") + k + "\"}", out);
  stateFromCode(code);
  if (code == 200 && tvState != TS_ON && tvState != TS_STANDBY) setState(TS_ON);
}

static void fetchVolume() {
  String out;
  if (tv.request("GET", "audio/volume", "", out) != 200) return;
  JsonDocument d;
  if (deserializeJson(d, out)) return;
  volCur = d["current"] | 0;
  volMax = d["max"] | 60;
  if (volMax <= 0) volMax = 60;
  volMuted = d["muted"].is<bool>() ? d["muted"].as<bool>() : String(d["muted"] | "") == "true";
  volFresh = true;
}

static void pollPower() {
  if (tv.api < 6) {  // old API: reachable means on
    String out;
    int code = tv.request("GET", "audio/volume", "", out, true, 2000);
    setState(code == 200 ? TS_ON : code < 0 ? TS_OFFLINE : tvState);
    return;
  }
  String out;
  int code = tv.request("GET", "powerstate", "", out, true, 2500);
  if (code != 200) { stateFromCode(code); return; }
  JsonDocument d;
  if (deserializeJson(d, out)) return;
  String ps = d["powerstate"] | "";
  setState(ps.equalsIgnoreCase("On") ? TS_ON : TS_STANDBY);
}

static void learnMac() {
  if (tvMac.length()) return;
  String out;
  if (tv.api >= 6 && tv.request("GET", "network/devices", "", out) == 200) {
    JsonDocument d;
    if (!deserializeJson(d, out))
      for (JsonObject o : d.as<JsonArray>()) {
        String ip = o["ipaddress"] | "", mac = o["mac"] | "";
        if (ip == tv.ip && mac.length() >= 17) { tvMac = mac; macDirty = true; return; }
      }
  }
  IPAddress want;
  want.fromString(tv.ip);
  for (size_t i = 0; i < ARP_TABLE_SIZE; i++) {
    ip4_addr_t* ip;
    struct netif* nif;
    struct eth_addr* eth;
    if (etharp_get_entry(i, &ip, &nif, &eth) && ip->addr == (uint32_t)want) {
      char m[18];
      snprintf(m, sizeof m, "%02x:%02x:%02x:%02x:%02x:%02x", eth->addr[0], eth->addr[1], eth->addr[2], eth->addr[3],
               eth->addr[4], eth->addr[5]);
      tvMac = m;
      macDirty = true;
      return;
    }
  }
}

static void wakeOnLan() {
  uint8_t mac[6];
  if (sscanf(tvMac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
    uint8_t pkt[102];
    memset(pkt, 0xFF, 6);
    for (int i = 0; i < 16; i++) memcpy(pkt + 6 + i * 6, mac, 6);
    WiFiUDP u;
    u.begin(9);
    IPAddress me = WiFi.localIP(), mask = WiFi.subnetMask();
    IPAddress bc(me[0] | ~mask[0], me[1] | ~mask[1], me[2] | ~mask[2], me[3] | ~mask[3]);
    for (int r = 0; r < 3; r++) {
      u.beginPacket(bc, 9); u.write(pkt, sizeof pkt); u.endPacket();
      u.beginPacket(IPAddress(255, 255, 255, 255), 9); u.write(pkt, sizeof pkt); u.endPacket();
      delay(20);
    }
    u.stop();
  }
  // Philips Android sets also wake from deep standby through their Chromecast endpoint
  WiFiClient c;
  if (c.connect(tv.ip.c_str(), 8008, 800)) {
    c.print("POST /apps/ChromeCast HTTP/1.1\r\nHost: " + tv.ip + ":8008\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    delay(100);
    c.stop();
  }
}

static void doPower() {
  if (tvState == TS_ON) { sendKey("Standby"); setState(TS_STANDBY); return; }
  if (tvState == TS_STANDBY && tv.api >= 6) {
    String out;
    int code = tv.request("POST", "powerstate", "{\"powerstate\":\"On\"}", out);
    if (code != 200) sendKey("Standby");
    setState(TS_ON);
    return;
  }
  if (tvState == TS_STANDBY) { sendKey("Standby"); return; }
  wakeOnLan();
  wakeSentAt = millis();
  tv.hangup();
  pollPower();
  if (tvState == TS_STANDBY) {
    String out;
    tv.request("POST", "powerstate", "{\"powerstate\":\"On\"}", out);
    setState(TS_ON);
  }
}

// Android Philips sets ignore the Source key over the network, so open their Sources drawer
// directly (the intent the TV lists in /6/applications). Older sets still get the key.
static void doSources() {
  if (tv.api >= 6) {
    String out;
    int code = tv.request("POST", "activities/launch",
                          "{\"id\":\"org.droidtv.sources.SourcesDrawerActivity-org.droidtv.settings\",\"intent\":{\"component\":"
                          "{\"packageName\":\"org.droidtv.settings\",\"className\":\"org.droidtv.sources.SourcesDrawerActivity\"},"
                          "\"action\":\"Intent { act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] "
                          "flg=0x10000000 pkg=org.droidtv.settings cmp=org.droidtv.settings/.SetupMenuAlias }\"}}",
                          out);
    Serial.printf("[sources] launch -> %d\n", code);
    stateFromCode(code);
    if (code == 200) return;
  }
  sendKey("Source");
}

static void doAmbilight() {
  String out;
  if (tv.api >= 6 && tv.request("GET", "ambilight/power", "", out) == 200) {
    JsonDocument d;
    if (!deserializeJson(d, out)) {
      bool on = String(d["power"] | "Off").equalsIgnoreCase("On");
      tv.request("POST", "ambilight/power", on ? "{\"power\":\"Off\"}" : "{\"power\":\"On\"}", out);
      return;
    }
  }
  sendKey("AmbilightOnOff");
}

static void netTask(void*) {
  uint32_t lastPoll = 0;
  for (;;) {
    Cmd c;
    bool got = xQueueReceive(cmdQ, &c, pdMS_TO_TICKS(250)) == pdTRUE;
    if (!workerOn || !tvReady() || WiFi.status() != WL_CONNECTED) continue;
    uint32_t pollEvery = wakeSentAt && millis() - wakeSentAt < 20000 ? 2000 : 6000;
    if (!got) {
      if (!screenAwake || millis() - lastPoll < pollEvery) continue;
      c.type = CM_POLL;
    }
    xSemaphoreTake(netMx, portMAX_DELAY);
    busy = true;
    switch (c.type) {
      case CM_KEY:
        sendKey(c.key);
        if (!strncmp(c.key, "Volume", 6) || !strcmp(c.key, "Mute"))
          if (!uxQueueMessagesWaiting(cmdQ)) fetchVolume();
        break;
      case CM_POWER: doPower(); break;
      case CM_AMBI: doAmbilight(); break;
      case CM_SOURCES: doSources(); break;
      case CM_POLL:
        pollPower();
        if (tvState == TS_ON || tvState == TS_STANDBY) learnMac();
        lastPoll = millis();
        break;
    }
    busy = false;
    xSemaphoreGive(netMx);
  }
}

static void queueCmd(CmdType t, const char* key = "") {
  Cmd c;
  c.type = t;
  strlcpy(c.key, key, sizeof c.key);
  if (uxQueueMessagesWaiting(cmdQ) < 4) xQueueSend(cmdQ, &c, 0);
}

// ---------------------------------------------------------------- UI model
enum Screen { S_REMOTE, S_MORE, S_SETTINGS, S_FIND, S_PAD, S_INFO, S_AP };
enum Shape : uint8_t { SH_RR, SH_CIRCLE, SH_DPAD, SH_OK, SH_TAB, SH_CARD };
enum Act : uint8_t {
  A_NONE, A_KEY, A_POWER, A_AMBI, A_SOURCES, A_TAB, A_SETTINGS, A_DONE, A_FIND, A_ENTER_IP, A_PICK, A_CHAR, A_BKSP, A_PAD_OK,
  A_PAD_CANCEL, A_REPAIR, A_CALIB, A_WIFI, A_INFO1, A_INFO2, A_RESTART
};
enum Icon : uint8_t {
  IC_NONE, IC_POWER, IC_MUTE, IC_PLAYPAUSE, IC_REW, IC_FF, IC_PREV, IC_NEXT, IC_STOP, IC_BACK, IC_HOME, IC_MENU,
  IC_PLUS, IC_MINUS, IC_UP, IC_DOWN, IC_LEFT, IC_RIGHT, IC_BKSP, IC_GEAR
};
enum Style : uint8_t { ST_KEY, ST_ACCENT, ST_POWER, ST_GHOST, ST_CR, ST_CG, ST_CY, ST_CB };

struct Btn {
  int16_t x, y, w, h;
  Shape shape;
  Act act;
  int16_t arg;
  Style style;
  Icon icon;
  bool rep;
  const char* key;
  String label;
  String sub;
};

static std::vector<Btn> btns;
static Screen screen = S_REMOTE;
static int pressed = -1;

static Btn& add(int x, int y, int w, int h, Act a, const char* key = nullptr, const String& label = "", Icon ic = IC_NONE,
                Style st = ST_KEY, bool rep = false) {
  btns.push_back(Btn{(int16_t)x, (int16_t)y, (int16_t)w, (int16_t)h, SH_RR, a, 0, st, ic, rep, key, label, ""});
  return btns.back();
}

// ---------------------------------------------------------------- icons
static void icon(Icon ic, int cx, int cy, uint32_t c, uint32_t bg) {
  switch (ic) {
    case IC_POWER:
      tft.fillArc(cx, cy, 8, 11, 300, 360, c);
      tft.fillArc(cx, cy, 8, 11, 0, 240, c);
      tft.fillRoundRect(cx - 1, cy - 14, 3, 13, 1, c);
      break;
    case IC_MUTE:
      tft.fillRect(cx - 12, cy - 4, 6, 8, c);
      tft.fillTriangle(cx - 9, cy, cx - 2, cy - 9, cx - 2, cy + 9, c);
      tft.drawWideLine(cx + 3, cy - 5, cx + 12, cy + 5, 1.4f, c);
      tft.drawWideLine(cx + 3, cy + 5, cx + 12, cy - 5, 1.4f, c);
      break;
    case IC_PLAYPAUSE:
      tft.fillTriangle(cx - 12, cy - 8, cx - 12, cy + 8, cx - 1, cy, c);
      tft.fillRect(cx + 3, cy - 8, 3, 16, c);
      tft.fillRect(cx + 9, cy - 8, 3, 16, c);
      break;
    case IC_REW:
      tft.fillTriangle(cx - 10, cy, cx, cy - 7, cx, cy + 7, c);
      tft.fillTriangle(cx, cy, cx + 10, cy - 7, cx + 10, cy + 7, c);
      break;
    case IC_FF:
      tft.fillTriangle(cx + 10, cy, cx, cy - 7, cx, cy + 7, c);
      tft.fillTriangle(cx, cy, cx - 10, cy - 7, cx - 10, cy + 7, c);
      break;
    case IC_PREV:
      tft.fillRect(cx - 8, cy - 7, 3, 14, c);
      tft.fillTriangle(cx - 5, cy, cx + 7, cy - 7, cx + 7, cy + 7, c);
      break;
    case IC_NEXT:
      tft.fillRect(cx + 6, cy - 7, 3, 14, c);
      tft.fillTriangle(cx + 6, cy, cx - 6, cy - 7, cx - 6, cy + 7, c);
      break;
    case IC_STOP: tft.fillRect(cx - 6, cy - 6, 12, 12, c); break;
    case IC_BACK:
      tft.fillArc(cx + 2, cy + 1, 4, 7, 270, 360, c);
      tft.fillArc(cx + 2, cy + 1, 4, 7, 0, 90, c);
      tft.fillRect(cx - 4, cy - 6, 6, 3, c);
      tft.fillRect(cx - 6, cy + 5, 8, 3, c);
      tft.fillTriangle(cx - 10, cy - 4.5f, cx - 3, cy - 10, cx - 3, cy + 1, c);
      break;
    case IC_HOME:
      tft.fillTriangle(cx, cy - 10, cx - 11, cy, cx + 11, cy, c);
      tft.fillRect(cx - 7, cy, 14, 9, c);
      tft.fillRect(cx - 2, cy + 3, 4, 6, bg);
      break;
    case IC_MENU:
      for (int i = -1; i <= 1; i++) tft.fillRoundRect(cx - 9, cy + i * 6 - 1, 18, 3, 1, c);
      break;
    case IC_PLUS:
      tft.fillRect(cx - 9, cy - 1, 19, 3, c);
      tft.fillRect(cx - 1, cy - 9, 3, 19, c);
      break;
    case IC_MINUS: tft.fillRect(cx - 9, cy - 1, 19, 3, c); break;
    case IC_UP: tft.fillTriangle(cx, cy - 7, cx - 10, cy + 5, cx + 10, cy + 5, c); break;
    case IC_DOWN: tft.fillTriangle(cx, cy + 7, cx - 10, cy - 5, cx + 10, cy - 5, c); break;
    case IC_LEFT: tft.fillTriangle(cx - 7, cy, cx + 5, cy - 10, cx + 5, cy + 10, c); break;
    case IC_RIGHT: tft.fillTriangle(cx + 7, cy, cx - 5, cy - 10, cx - 5, cy + 10, c); break;
    case IC_BKSP:
      tft.fillTriangle(cx - 13, cy, cx - 5, cy - 9, cx - 5, cy + 9, c);
      tft.fillRect(cx - 5, cy - 9, 18, 18, c);
      tft.drawWideLine(cx - 1, cy - 4, cx + 7, cy + 4, 1.3f, bg);
      tft.drawWideLine(cx - 1, cy + 4, cx + 7, cy - 4, 1.3f, bg);
      break;
    case IC_GEAR:
      for (int i = 0; i < 8; i++) {
        float a = i * PI / 4;
        tft.drawWideLine(cx + cosf(a) * 6, cy + sinf(a) * 6, cx + cosf(a) * 10, cy + sinf(a) * 10, 2.2f, c);
      }
      tft.fillCircle(cx, cy, 7, c);
      tft.fillCircle(cx, cy, 3, bg);
      break;
    default: break;
  }
}

// ---------------------------------------------------------------- drawing
static const int DP_X = 160, DP_Y = 194, DP_R = 88, DP_OK = 36;

static void styleColors(Style st, bool down, uint32_t& bg, uint32_t& fg) {
  switch (st) {
    case ST_ACCENT: bg = down ? C_ACCENT_HI : C_ACCENT; fg = 0xFFFFFF; break;
    case ST_POWER: bg = down ? C_POWER_HI : C_POWERBG; fg = 0xFFFFFF; break;
    case ST_GHOST: bg = down ? C_KEY_HI : C_BG; fg = C_FG; break;
    case ST_CR: bg = down ? mix(C_RED, 0xFFFFFF, 0.3f) : C_RED; fg = 0xFFFFFF; break;
    case ST_CG: bg = down ? mix(C_GREEN, 0xFFFFFF, 0.3f) : C_GREEN; fg = 0xFFFFFF; break;
    case ST_CY: bg = down ? mix(C_YELLOW, 0xFFFFFF, 0.3f) : C_YELLOW; fg = 0x202020; break;
    case ST_CB: bg = down ? mix(C_BLUE, 0xFFFFFF, 0.3f) : C_BLUE; fg = 0xFFFFFF; break;
    default: bg = down ? C_KEY_HI : C_KEYBG; fg = C_FG; break;
  }
}

static void drawDpad(int downPart) {  // downPart: -1 none, 0..3 = up/right/down/left, 4 = OK
  tft.fillSmoothCircle(DP_X, DP_Y, DP_R + 2, C_RING);
  const int seg[4][2] = {{225, 315}, {315, 405}, {45, 135}, {135, 225}};
  for (int i = 0; i < 4; i++) {
    uint32_t c = downPart == i ? C_KEY_HI : C_KEYBG;
    int a0 = seg[i][0], a1 = seg[i][1];
    if (a1 > 360) { tft.fillArc(DP_X, DP_Y, DP_OK + 6, DP_R, a0, 360, c); tft.fillArc(DP_X, DP_Y, DP_OK + 6, DP_R, 0, a1 - 360, c); }
    else tft.fillArc(DP_X, DP_Y, DP_OK + 6, DP_R, a0, a1, c);
  }
  float d = 0.7071f;
  for (int s = -1; s <= 1; s += 2) {
    tft.drawWideLine(DP_X + d * (DP_OK + 4), DP_Y + s * d * (DP_OK + 4), DP_X + d * (DP_R + 1), DP_Y + s * d * (DP_R + 1), 1.6f, C_RING);
    tft.drawWideLine(DP_X - d * (DP_OK + 4), DP_Y + s * d * (DP_OK + 4), DP_X - d * (DP_R + 1), DP_Y + s * d * (DP_R + 1), 1.6f, C_RING);
  }
  int m = (DP_OK + DP_R) / 2 + 3;
  icon(IC_UP, DP_X, DP_Y - m, C_FG, 0);
  icon(IC_RIGHT, DP_X + m, DP_Y, C_FG, 0);
  icon(IC_DOWN, DP_X, DP_Y + m, C_FG, 0);
  icon(IC_LEFT, DP_X - m, DP_Y, C_FG, 0);
  tft.fillSmoothCircle(DP_X, DP_Y, DP_OK, downPart == 4 ? C_ACCENT_HI : C_ACCENT);
  tft.setFont(F_KEY);
  tft.setTextDatum(textdatum_t::middle_center);
  tft.setTextColor(0xFFFFFF);
  tft.drawString("OK", DP_X, DP_Y + 1);
}

static void drawBtn(int i, bool down) {
  Btn& b = btns[i];
  if (b.shape == SH_DPAD || b.shape == SH_OK) { drawDpad(down ? (b.shape == SH_OK ? 4 : b.arg) : -1); return; }
  uint32_t bg, fg;
  styleColors(b.style, down, bg, fg);
  int cx = b.x + b.w / 2, cy = b.y + b.h / 2;
  if (b.shape == SH_TAB) {
    bool active = b.arg == (screen == S_MORE ? 1 : 0);
    tft.fillRect(b.x, b.y, b.w, b.h, down ? C_KEYBG : C_BG);
    tft.setFont(active ? F_UIB : F_UI);
    tft.setTextDatum(textdatum_t::middle_center);
    tft.setTextColor(active ? C_FG : C_DIM);
    tft.drawString(b.label, cx, cy);
    if (active) tft.fillRoundRect(cx - 22, b.y + b.h - 5, 44, 3, 1, C_ACCENT);
    return;
  }
  if (b.shape == SH_CIRCLE) {
    tft.fillSmoothCircle(cx, cy, b.w / 2, bg);
  } else {
    tft.fillRect(b.x, b.y, b.w, b.h, b.style == ST_GHOST ? (down ? C_KEY_HI : C_BG) : C_BG);
    tft.fillSmoothRoundRect(b.x, b.y, b.w, b.h, min(12, b.h / 2), bg);
    if (b.style == ST_GHOST && !down) tft.drawRoundRect(b.x, b.y, b.w, b.h, min(12, b.h / 2), C_FAINT);
  }
  if (b.shape == SH_CARD) {
    tft.setTextDatum(textdatum_t::middle_left);
    tft.setFont(F_UIB);
    tft.setTextColor(fg);
    tft.drawString(b.label, b.x + 16, cy - 10);
    tft.setFont(F_UI);
    tft.setTextColor(C_DIM);
    tft.drawString(b.sub, b.x + 16, cy + 12);
    icon(IC_RIGHT, b.x + b.w - 20, cy, C_DIM, bg);
    return;
  }
  if (b.icon != IC_NONE && b.label.length()) {  // icon over a small caption (rockers)
    icon(b.icon, cx, cy - 6, fg, bg);
    tft.setFont(&fonts::Font0);
    tft.setTextDatum(textdatum_t::middle_center);
    tft.setTextColor(C_DIM);
    tft.drawString(b.label, cx, cy + 15);
  } else if (b.icon != IC_NONE) {
    icon(b.icon, cx, cy, fg, bg);
  } else {
    tft.setFont(b.h >= 48 && b.label.length() <= 2 ? F_KEY : F_UIB);
    tft.setTextDatum(textdatum_t::middle_center);
    tft.setTextColor(fg);
    tft.drawString(b.label, cx, cy + 1);
  }
}

// header: name + status, power button on the right
static uint32_t volUntil = 0;

static String statusDrawn;
static void drawStatus(bool force = false) {
  bool vol = volUntil && millis() < volUntil;
  bool waking = wakeSentAt && millis() - wakeSentAt < 20000;
  String sig = String(tvState) + (vol ? "v" + String(volCur) + "/" + String(volMax) + (volMuted ? "m" : "") : "") +
               (waking ? "w" : "") + (WiFi.status() == WL_CONNECTED ? "" : "x");
  if (!force && sig == statusDrawn) return;
  statusDrawn = sig;
  tft.fillRect(0, 32, 250, 20, C_BG);
  tft.setTextDatum(textdatum_t::middle_left);
  tft.setFont(F_UI);
  if (vol) {
    int w = 150;
    int fill = volMax > 0 ? w * volCur / volMax : 0;
    tft.fillRoundRect(16, 38, w, 7, 3, C_KEYBG);
    tft.fillRoundRect(16, 38, max(7, fill), 7, 3, volMuted ? C_DIM : C_ACCENT);
    tft.setTextColor(C_FG);
    tft.drawString(volMuted ? "Muted" : String(volCur), 16 + w + 10, 42);
    return;
  }
  uint32_t dot;
  const char* txt;
  switch (tvState) {
    case TS_ON: dot = C_OK; txt = "On"; break;
    case TS_STANDBY: dot = C_AMBER; txt = "Standby"; break;
    case TS_OFFLINE: dot = C_FAINT; txt = WiFi.status() == WL_CONNECTED ? "Not reachable" : "WiFi lost"; break;
    case TS_AUTH: dot = C_POWERBG; txt = "Pairing lost: Settings > Pair again"; break;
    default: dot = C_FAINT; txt = "Connecting..."; break;
  }
  if (waking && tvState == TS_OFFLINE) { dot = C_AMBER; txt = "Waking up..."; }
  tft.fillCircle(20, 42, 4, dot);
  tft.setTextColor(C_DIM);
  tft.drawString(txt, 32, 42);
}

static void drawBusy(bool on) { tft.fillCircle(246, 16, 3, on ? C_ACCENT : C_BG); }

static void drawHeader(const String& title) {
  tft.fillRect(0, 0, SCR_W, 56, C_BG);
  tft.setTextDatum(textdatum_t::middle_left);
  tft.setFont(F_TITLE);
  tft.setTextColor(C_FG);
  String t = title;
  while (t.length() > 3 && tft.textWidth(t) > 220) t.remove(t.length() - 1);
  tft.drawString(t, 16, 16);
}

static void drawAll() {
  tft.fillScreen(C_BG);
  if (screen == S_REMOTE || screen == S_MORE) {
    drawHeader(tvName);
    drawStatus(true);
  }
  for (int i = 0; i < (int)btns.size(); i++)
    if (btns[i].shape != SH_DPAD) drawBtn(i, false);  // the OK entry draws the whole pad
}

// ---------------------------------------------------------------- screens
static void addTabs() {
  for (int i = 0; i < 2; i++) {
    Btn& b = add(i * 160, 444, 160, 36, A_TAB, nullptr, i ? "Keypad & more" : "Remote");
    b.shape = SH_TAB;
    b.arg = i;
  }
}

static void addPower() {
  Btn& p = add(262, 6, 44, 44, A_POWER, nullptr, "", IC_POWER, ST_POWER);
  p.shape = SH_CIRCLE;
}

static void buildRemote() {
  btns.clear();
  addPower();
  // top row
  const int RW = 68, RX = 12, RG = 8, RY = 62, RH = 38;
  add(RX + 0 * (RW + RG), RY, RW, RH, A_SOURCES, nullptr, "Sources");
  add(RX + 1 * (RW + RG), RY, RW, RH, A_KEY, "WatchTV", "TV");
  add(RX + 2 * (RW + RG), RY, RW, RH, A_KEY, "Home", "", IC_HOME);
  add(RX + 3 * (RW + RG), RY, RW, RH, A_AMBI, nullptr, "Ambi");
  // d-pad: OK first so its hit test wins
  Btn& ok = add(DP_X - DP_OK, DP_Y - DP_OK, DP_OK * 2, DP_OK * 2, A_KEY, "Confirm");
  ok.shape = SH_OK;
  const char* dirs[4] = {"CursorUp", "CursorRight", "CursorDown", "CursorLeft"};
  for (int d = 0; d < 4; d++) {
    Btn& b = add(DP_X - DP_R, DP_Y - DP_R, DP_R * 2, DP_R * 2, A_KEY, dirs[d], "", IC_NONE, ST_KEY, true);
    b.shape = SH_DPAD;
    b.arg = d;
  }
  // corner keys around the pad
  auto corner = [&](int cx, int cy, const char* key, const char* label, Icon ic) {
    Btn& b = add(cx - 22, cy - 22, 44, 44, A_KEY, key, label, ic);
    b.shape = SH_CIRCLE;
  };
  corner(34, 130, "Info", "i", IC_NONE);
  corner(286, 130, "Subtitle", "CC", IC_NONE);
  corner(34, 262, "Back", "", IC_BACK);
  corner(286, 262, "Options", "", IC_MENU);
  // rockers
  const int KY = 296, KH = 47;
  add(12, KY, 72, KH, A_KEY, "VolumeUp", "VOL", IC_PLUS, ST_KEY, true);
  add(12, KY + KH + 2, 72, KH, A_KEY, "VolumeDown", "VOL", IC_MINUS, ST_KEY, true);
  add(236, KY, 72, KH, A_KEY, "ChannelStepUp", "CH", IC_UP, ST_KEY, true);
  add(236, KY + KH + 2, 72, KH, A_KEY, "ChannelStepDown", "CH", IC_DOWN, ST_KEY, true);
  add(96, KY, 128, KH, A_KEY, "Mute", "", IC_MUTE);
  add(96, KY + KH + 2, 128, KH, A_KEY, "PlayPause", "", IC_PLAYPAUSE);
  // media row
  const char* mk[5] = {"Rewind", "Previous", "Stop", "Next", "FastForward"};
  const Icon mi[5] = {IC_REW, IC_PREV, IC_STOP, IC_NEXT, IC_FF};
  for (int i = 0; i < 5; i++) add(12 + i * 60, 400, 52, 36, A_KEY, mk[i], "", mi[i]);
  addTabs();
}

static void buildMore() {
  btns.clear();
  addPower();
  const int W = 93, G = 8, X = 12, Y = 62, H = 48, RS = 54;
  const char* lab[12] = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "Text", "0", "."};
  const char* key[12] = {"Digit1", "Digit2", "Digit3", "Digit4", "Digit5", "Digit6", "Digit7", "Digit8", "Digit9",
                         "Teletext", "Digit0", "Dot"};
  for (int i = 0; i < 12; i++) add(X + (i % 3) * (W + G), Y + (i / 3) * RS, W, H, A_KEY, key[i], lab[i]);
  const int CY = Y + 4 * RS + 2, CW = 68;
  const char* ck[4] = {"RedColour", "GreenColour", "YellowColour", "BlueColour"};
  const Style cs[4] = {ST_CR, ST_CG, ST_CY, ST_CB};
  for (int i = 0; i < 4; i++) add(X + i * (CW + G), CY, CW, 32, A_KEY, ck[i], "", IC_NONE, cs[i]);
  const int R2 = CY + 42;
  add(X, R2, W, 40, A_KEY, "Viewmode", "Format");
  add(X + W + G, R2, W, 40, A_KEY, "Adjust", "Adjust");
  add(X + 2 * (W + G), R2, W, 40, A_KEY, "Find", "Search");
  add(X, R2 + 48, 296, 40, A_SETTINGS, nullptr, "Settings", IC_NONE, ST_GHOST);
  addTabs();
}

static void showRemote(bool more) {
  screen = more ? S_MORE : S_REMOTE;
  more ? buildMore() : buildRemote();
  workerOn = true;
  stateDirty = true;
  drawAll();
}

// settings
static void showSettings() {
  screen = S_SETTINGS;
  btns.clear();
  int y = 196;
  add(16, y, 288, 44, A_FIND, nullptr, "Find another TV");
  if (tv.https) add(16, y += 52, 288, 44, A_REPAIR, nullptr, "Pair again");
  add(16, y += 52, 288, 44, A_CALIB, nullptr, "Calibrate touch");
  add(16, y += 52, 288, 44, A_WIFI, nullptr, "Change WiFi", IC_NONE, ST_GHOST);
  add(16, 420, 288, 44, A_DONE, nullptr, "Done", IC_NONE, ST_ACCENT);
  drawAll();
  drawHeader("Settings");
  tft.setFont(F_UI);
  tft.setTextDatum(textdatum_t::top_left);
  const String rows[6][2] = {{"TV", tvName},
                             {"Address", tv.ip + (tv.https ? "  (secure)" : "")},
                             {"API", String(tv.api)},
                             {"TV MAC", tvMac.length() ? tvMac : String("not learned yet")},
                             {"WiFi", WiFi.SSID()},
                             {"This remote", WiFi.localIP().toString()}};
  for (int i = 0; i < 6; i++) {
    tft.setTextColor(C_DIM);
    tft.drawString(rows[i][0], 16, 44 + i * 24);
    tft.setTextColor(C_FG);
    tft.drawString(rows[i][1], 116, 44 + i * 24);
  }
}

// info/message screen with up to two buttons
static Act infoAct1, infoAct2;
static void showInfo(const String& title, const String& sub, const char* b1 = nullptr, Act a1 = A_NONE,
                     const char* b2 = nullptr, Act a2 = A_NONE) {
  screen = S_INFO;
  workerOn = false;
  btns.clear();
  infoAct1 = a1;
  infoAct2 = a2;
  if (b1 && b2) {
    add(16, 410, 136, 48, A_INFO2, nullptr, b2, IC_NONE, ST_GHOST);
    add(168, 410, 136, 48, A_INFO1, nullptr, b1, IC_NONE, ST_ACCENT);
  } else if (b1) {
    add(16, 410, 288, 48, A_INFO1, nullptr, b1, IC_NONE, ST_ACCENT);
  }
  drawAll();
  tft.setTextDatum(textdatum_t::middle_center);
  tft.setFont(F_TITLE);
  tft.setTextColor(C_FG);
  tft.drawString(title, SCR_W / 2, 200);
  tft.setFont(F_UI);
  tft.setTextColor(C_DIM);
  // naive wrap on spaces
  String s = sub, line;
  int y = 236;
  while (s.length()) {
    int sp = s.indexOf(' ');
    String w = sp < 0 ? s : s.substring(0, sp + 1);
    s = sp < 0 ? "" : s.substring(sp + 1);
    if (tft.textWidth(line + w) > 280 && line.length()) { tft.drawString(line, SCR_W / 2, y); y += 22; line = ""; }
    line += w;
  }
  if (line.length()) tft.drawString(line, SCR_W / 2, y);
}

// number pad (PIN or IP)
static bool padIp = false;
static String padText;
static void drawPadField() {
  tft.fillSmoothRoundRect(16, 104, 288, 58, 12, C_KEYBG);
  tft.setTextDatum(textdatum_t::middle_center);
  tft.setFont(F_BIG);
  tft.setTextColor(padText.length() ? C_FG : C_FAINT);
  String t = padText.length() ? padText : String(padIp ? "192.168." : "- - - -");
  if (!padIp && padText.length()) {
    t = "";
    for (size_t i = 0; i < padText.length(); i++) t += String(i ? " " : "") + padText[i];
  }
  tft.drawString(t, SCR_W / 2, 134);
}

static void showPad(bool ip) {
  screen = S_PAD;
  workerOn = false;
  padIp = ip;
  padText = "";
  btns.clear();
  const int W = 93, G = 8, X = 12, Y = 176, H = 50, RS = 56;
  for (int i = 0; i < 9; i++) {
    Btn& b = add(X + (i % 3) * (W + G), Y + (i / 3) * RS, W, H, A_CHAR, nullptr, String(i + 1));
    b.arg = '1' + i;
  }
  if (ip) { Btn& d = add(X, Y + 3 * RS, W, H, A_CHAR, nullptr, "."); d.arg = '.'; }
  Btn& z = add(X + W + G, Y + 3 * RS, W, H, A_CHAR, nullptr, "0");
  z.arg = '0';
  add(X + 2 * (W + G), Y + 3 * RS, W, H, A_BKSP, nullptr, "", IC_BKSP, ST_KEY, true);
  add(16, 416, 120, 48, A_PAD_CANCEL, nullptr, "Cancel", IC_NONE, ST_GHOST);
  add(148, 416, 156, 48, A_PAD_OK, nullptr, ip ? "Connect" : "Pair", IC_NONE, ST_ACCENT);
  drawAll();
  drawHeader(ip ? "TV address" : "Enter the PIN");
  tft.setFont(F_UI);
  tft.setTextDatum(textdatum_t::top_left);
  tft.setTextColor(C_DIM);
  tft.drawString(ip ? "Find it on the TV under Settings >" : "Your TV is showing a PIN code.", 16, 44);
  tft.drawString(ip ? "Network > View network settings." : "Type it here to pair this remote.", 16, 66);
  drawPadField();
}

// TV finder
static void drawFindStatus(const String& s) {
  tft.fillRect(0, 40, SCR_W, 50, C_BG);
  tft.setFont(F_UI);
  tft.setTextDatum(textdatum_t::top_left);
  tft.setTextColor(C_DIM);
  tft.drawString(s, 16, 48);
}

static void buildFind() {
  btns.clear();
  for (int i = 0; i < (int)found.size() && i < 4; i++) {
    Btn& b = add(16, 96 + i * 72, 288, 62, A_PICK, nullptr, found[i].name);
    b.shape = SH_CARD;
    b.arg = i;
    b.sub = found[i].ip + (found[i].https ? "  -  needs pairing" : "") + "  -  API " + String(found[i].api);
  }
  add(16, 416, 136, 48, A_FIND, nullptr, "Search again", IC_NONE, ST_GHOST);
  add(168, 416, 136, 48, A_ENTER_IP, nullptr, "Enter IP");
}

static void runFind() {
  screen = S_FIND;
  workerOn = false;
  found.clear();
  btns.clear();
  drawAll();
  drawHeader("Find your TV");
  drawFindStatus("Make sure the TV is on. Searching...");
  xSemaphoreTake(netMx, portMAX_DELAY);
  tv.hangup();
  std::vector<String> ips = ssdpScan(2500);
  int n = 0;
  for (auto& ip : ips) {
    drawFindStatus("Checking " + ip + "  (" + String(++n) + "/" + String(ips.size()) + ")");
    Found f;
    if (probeTv(ip, f)) addFound(f);
  }
  if (found.empty()) {
    std::vector<String> hits = portScan([](int pct) { drawFindStatus("Scanning the network... " + String(pct) + "%"); });
    for (auto& ip : hits) {
      drawFindStatus("Checking " + ip);
      Found f;
      if (probeTv(ip, f)) addFound(f);
    }
  }
  xSemaphoreGive(netMx);
  buildFind();
  drawAll();
  drawHeader("Find your TV");
  if (found.empty()) {
    drawFindStatus("No Philips TV found. Is it on and on the same WiFi?");
    tft.setFont(F_UI);
    tft.setTextDatum(textdatum_t::top_left);
    tft.setTextColor(C_DIM);
    tft.drawString("Older sets: turn on JointSpace by typing", 16, 150);
    tft.drawString("5646877223 on the TV's remote while", 16, 172);
    tft.drawString("watching TV, then search again.", 16, 194);
  } else {
    drawFindStatus(found.size() == 1 ? "Found your TV. Tap it to connect." : "Tap the TV to control.");
  }
}

static void startPairing() {
  showInfo("Pairing", "Asking the TV for a PIN...");
  if (pairRequest()) { showPad(false); return; }
  showInfo("Couldn't pair", pairError, "Try again", A_REPAIR, "Choose TV", A_FIND);
}

static void selectTv(const Found& f) {
  xSemaphoreTake(netMx, portMAX_DELAY);
  tv.hangup();
  tv.ip = f.ip;
  tv.api = f.api;
  tv.https = f.https;
  tv.port = f.https ? 1926 : 1925;
  tv.user = tv.pass = "";
  tv.nonce = "";
  xSemaphoreGive(netMx);
  tvName = f.name;
  tvMac = "";
  tvState = TS_UNKNOWN;
  saveTv();
  if (tv.https) startPairing();
  else showRemote(false);
}

// ---------------------------------------------------------------- WiFi setup portal
static WebServer server(80);
static DNSServer dns;
static String apPass, wifiSsid, wifiPass, connectError;
static bool apMode = false;
static const char* AP_NAME = "TV-Remote";

static String htmlEsc(const String& s) {
  String o;
  for (char c : s) {
    if (c == '<') o += "&lt;";
    else if (c == '>') o += "&gt;";
    else if (c == '&') o += "&amp;";
    else if (c == '\'') o += "&#39;";
    else if (c == '"') o += "&quot;";
    else o += c;
  }
  return o;
}

static const char PAGE_HEAD[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>TV remote</title><style>
:root{--bg:#f4f5f7;--card:#fff;--fg:#17181a;--dim:#686c73;--acc:#3d8bff;--line:#e2e4e8}
@media(prefers-color-scheme:dark){:root{--bg:#121314;--card:#1f2124;--fg:#f2f3f5;--dim:#9a9fa6;--line:#33363b}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 -apple-system,system-ui,sans-serif}
main{max-width:460px;margin:0 auto;padding:28px 16px}h1{font-size:22px;margin:0 0 4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px;margin:16px 0}
p{color:var(--dim);margin:8px 0}label{display:block;font-weight:600;margin:12px 0 6px}
input{width:100%;box-sizing:border-box;padding:12px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--fg);font-size:16px}
.btn{display:block;width:100%;padding:13px;border-radius:12px;border:0;background:var(--acc);color:#fff;font-weight:600;font-size:16px;margin-top:14px}
</style></head><body><main><h1>TV remote</h1>)HTML";

static void sendPage(const String& body) {
  String s = FPSTR(PAGE_HEAD);
  s += body;
  s += "</main></body></html>";
  server.send(200, "text/html", s);
}

static void pageWifi() {
  int n = WiFi.scanNetworks();
  String opts;
  for (int i = 0; i < n && i < 25; i++) {
    String s = htmlEsc(WiFi.SSID(i));
    if (s.length() && opts.indexOf(">" + s + "<") < 0) opts += "<option>" + s + "</option>";
  }
  String b = connectError.length() ? "<p style='color:#e5484d'>" + htmlEsc(connectError) + "</p>" : "";
  b += "<p>Pick the WiFi network your TV is on.</p><div class=card><form method=post action=/wifi>"
       "<label>Network</label><input name=ssid list=nets autocomplete=off placeholder='Network name' value='" +
       htmlEsc(wifiSsid) + "'><datalist id=nets>" + opts +
       "</datalist><label>Password</label><input name=pass type=password autocomplete=off>"
       "<button class=btn>Connect</button></form></div>";
  sendPage(b);
}

static void setupRoutes() {
  server.on("/", HTTP_GET, pageWifi);
  server.on("/wifi", HTTP_POST, [] {
    prefs.putString("ssid", server.arg("ssid"));
    prefs.putString("pass", server.arg("pass"));
    sendPage("<div class=card><b>Saved.</b><p>The remote is restarting and joining <b>" + htmlEsc(server.arg("ssid")) +
             "</b>. Reconnect this phone to your normal WiFi.</p></div>");
    delay(1500);
    ESP.restart();
  });
  server.onNotFound([] {
    server.sendHeader("Location", "http://192.168.4.1/");
    server.send(302);
  });
}

static void drawAP();
static void enterAP() {
  apMode = true;
  screen = S_AP;
  workerOn = false;
  WiFi.disconnect(true);
  WiFi.mode(WIFI_AP_STA);
  char p[9];
  snprintf(p, sizeof p, "%08u", (unsigned)(esp_random() % 100000000UL));
  apPass = p;
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP(AP_NAME, apPass.c_str());
  dns.start(53, "*", IPAddress(192, 168, 4, 1));
  setupRoutes();
  server.begin();
  drawAP();
}

static void drawAP() {
  btns.clear();
  if (wifiSsid.length()) add(16, 420, 288, 44, A_RESTART, nullptr, "Retry " + wifiSsid, IC_NONE, ST_GHOST);
  drawAll();
  drawHeader("WiFi setup");
  String qr = "WIFI:T:WPA;S:" + String(AP_NAME) + ";P:" + apPass + ";;";
  tft.fillRoundRect(60, 48, 200, 200, 14, TFT_WHITE);
  tft.qrcode(qr.c_str(), 70, 58, 180, 3);
  tft.setTextDatum(textdatum_t::top_left);
  const char* lines[] = {"1. Scan to join the setup WiFi", nullptr, "2. Open http://192.168.4.1", "   (usually opens by itself)",
                         "3. Pick the WiFi your TV is on"};
  for (int i = 0; i < 5; i++) {
    tft.setFont(lines[i] ? F_UI : F_UIB);
    tft.setTextColor(lines[i] ? C_DIM : C_FG);
    tft.drawString(lines[i] ? String(lines[i]) : "   " + String(AP_NAME) + "  /  " + apPass, 16, 262 + i * 24);
  }
  if (connectError.length()) {
    tft.setFont(F_UIB);
    tft.setTextColor(C_AMBER);
    tft.drawString(connectError, 16, 390);
  }
}

static bool connectWifi() {
  showInfo("Connecting", "Joining " + wifiSsid);
  WiFi.mode(WIFI_STA);
  WiFi.setHostname("tv-remote");
  WiFi.setSleep(false);  // keeps key presses snappy
  WiFi.begin(wifiSsid.c_str(), wifiPass.c_str());
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) delay(200);
  if (WiFi.status() != WL_CONNECTED) { connectError = "Couldn't join " + wifiSsid; return false; }
  WiFi.setAutoReconnect(true);
  Serial.printf("[wifi] %s\n", WiFi.localIP().toString().c_str());
  return true;
}

// ---------------------------------------------------------------- touch + actions
static const char* CAL_KEY = "cal_p";
static void runCalibration() {
  tft.fillScreen(C_BG);
  tft.setTextDatum(textdatum_t::middle_center);
  tft.setFont(F_UIB);
  tft.setTextColor(C_FG);
  tft.drawString("Touch calibration", SCR_W / 2, SCR_H / 2 - 16);
  tft.setFont(F_UI);
  tft.setTextColor(C_DIM);
  tft.drawString("Tap the tip of each arrow", SCR_W / 2, SCR_H / 2 + 12);
  uint16_t cal[8];
  tft.calibrateTouch(cal, C_ACCENT, C_BG, 18);
  prefs.putBytes(CAL_KEY, cal, sizeof(cal));
  tft.fillScreen(C_BG);
}

static void goHome() {
  if (apMode) return;
  if (!tv.ip.length()) runFind();
  else if (!tvReady()) startPairing();
  else showRemote(false);
}

static int hitTest(int x, int y) {
  for (int i = 0; i < (int)btns.size(); i++) {
    Btn& b = btns[i];
    int dx = x - DP_X, dy = y - DP_Y;
    if (b.shape == SH_OK) {
      if (dx * dx + dy * dy <= (DP_OK + 4) * (DP_OK + 4)) return i;
      continue;
    }
    if (b.shape == SH_DPAD) {
      int r2 = dx * dx + dy * dy;
      if (r2 > (DP_R + 6) * (DP_R + 6)) continue;
      int dir = abs(dx) > abs(dy) ? (dx > 0 ? 1 : 3) : (dy > 0 ? 2 : 0);
      if (dir == b.arg) return i;
      continue;
    }
    const int slop = 3;
    if (x >= b.x - slop && x < b.x + b.w + slop && y >= b.y - slop && y < b.y + b.h + slop) return i;
  }
  return -1;
}

static void fire(int i) {
  Btn& b = btns[i];
  switch (b.act) {
    case A_KEY: queueCmd(CM_KEY, b.key); break;
    case A_POWER: queueCmd(CM_POWER); break;
    case A_AMBI: queueCmd(CM_AMBI); break;
    case A_SOURCES: queueCmd(CM_SOURCES); break;
    case A_CHAR:
      if (padText.length() < (padIp ? 15u : 8u)) { padText += (char)b.arg; drawPadField(); }
      break;
    case A_BKSP:
      if (padText.length()) { padText.remove(padText.length() - 1); drawPadField(); }
      break;
    default: break;
  }
}

static void release(int i) {  // actions that run on release (they change screens)
  Btn b = btns[i];
  switch (b.act) {
    case A_TAB: if (b.arg != (screen == S_MORE ? 1 : 0)) showRemote(b.arg == 1); break;
    case A_SETTINGS: showSettings(); break;
    case A_DONE: showRemote(false); break;
    case A_FIND: runFind(); break;
    case A_ENTER_IP: showPad(true); break;
    case A_PICK: selectTv(found[b.arg]); break;
    case A_REPAIR: startPairing(); break;
    case A_CALIB: runCalibration(); showSettings(); break;
    case A_WIFI:
      prefs.remove("ssid");
      prefs.remove("pass");
      ESP.restart();
      break;
    case A_RESTART: ESP.restart(); break;
    case A_INFO1: if (infoAct1 == A_FIND) runFind(); else if (infoAct1 == A_REPAIR) startPairing(); else if (infoAct1 == A_ENTER_IP) showPad(true); else goHome(); break;
    case A_INFO2: if (infoAct2 == A_FIND) runFind(); else if (infoAct2 == A_ENTER_IP) showPad(true); else goHome(); break;
    case A_PAD_CANCEL:
      if (padIp || !tv.ip.length()) runFind();
      else showInfo("Not paired", "The remote needs the PIN the TV shows to control it.", "Try again", A_REPAIR, "Choose TV", A_FIND);
      break;
    case A_PAD_OK:
      if (padIp) {
        IPAddress a;
        if (!a.fromString(padText)) { showInfo("Not an address", "Type it like 192.168.1.40", "OK", A_ENTER_IP); break; }
        showInfo("Connecting", "Looking for a Philips TV at " + padText);
        Found f;
        xSemaphoreTake(netMx, portMAX_DELAY);
        bool ok = probeTv(padText, f);
        xSemaphoreGive(netMx);
        if (ok) selectTv(f);
        else showInfo("No TV there", "Nothing answered at " + padText + ". Check the address and that the TV is on.", "Try again", A_ENTER_IP, "Search", A_FIND);
      } else {
        if (padText.length() < 4) break;
        showInfo("Pairing", "Checking the PIN...");
        if (pairGrant(padText)) {
          saveTv();
          tvState = TS_UNKNOWN;
          showRemote(false);
        } else {
          showInfo("Couldn't pair", pairError, "Try again", A_REPAIR, "Choose TV", A_FIND);
        }
      }
      break;
    default: break;
  }
}

static bool tDown = false, consumed = false;
static int dnCount = 0, upCount = 0;
static uint32_t lastActivity = 0, repeatAt = 0, pressT = 0;
static bool dimmed = false;

static void pollTouch() {
  int32_t x, y;
  bool raw = tft.getTouch(&x, &y);
  uint32_t now = millis();
  if (raw) {
    upCount = 0;
    lastActivity = now;
    if (dimmed) {  // first touch only wakes the screen
      dimmed = false;
      screenAwake = true;
      tft.setBrightness(210);
      consumed = tDown = true;
      return;
    }
    if (!tDown) {
      if (++dnCount < 2) return;
      tDown = true;
      consumed = false;
      pressed = hitTest(x, y);
      if (pressed >= 0) {
        drawBtn(pressed, true);
        pressT = now;
        fire(pressed);
        repeatAt = now + 450;
      }
    } else if (pressed >= 0 && btns[pressed].rep && now >= repeatAt) {
      if (hitTest(x, y) == pressed) fire(pressed);
      repeatAt = now + 160;
    }
  } else {
    dnCount = 0;
    if (tDown && ++upCount >= 3) {
      tDown = false;
      if (consumed) { consumed = false; return; }
      int p = pressed;
      pressed = -1;
      if (p >= 0 && p < (int)btns.size()) {
        drawBtn(p, false);
        release(p);
        lastActivity = millis();  // searching and pairing can block for a while
      }
    }
  }
}

// ---------------------------------------------------------------- main
void setup() {
  Serial.begin(115200);
  pinMode(0, INPUT_PULLUP);
  tft.init();
  tft.setRotation(0);  // portrait, USB at the bottom
  tft.setBrightness(210);
  tft.fillScreen(C_BG);

  prefs.begin("tvremote", false);
  uint16_t cal[8];
  if (prefs.getBytes(CAL_KEY, cal, sizeof(cal)) == sizeof(cal) && digitalRead(0) == HIGH) tft.setTouchCalibrate(cal);
  else runCalibration();

  netMx = xSemaphoreCreateMutex();
  cmdQ = xQueueCreate(6, sizeof(Cmd));
  wifiSsid = prefs.getString("ssid", "");
  wifiPass = prefs.getString("pass", "");
  loadTv();
  xTaskCreatePinnedToCore(netTask, "net", 12288, nullptr, 1, nullptr, 0);

  if (!wifiSsid.length() || !connectWifi()) enterAP();
  else goHome();
  lastActivity = millis();
}

void loop() {
  static uint32_t nextFrame = 0, bootHeld = 0, lastStatus = 0;
  uint32_t now = millis();
  if (apMode) {
    server.handleClient();
    dns.processNextRequest();
  }
  if (now < nextFrame) { delay(1); return; }
  nextFrame = now + 12;

  pollTouch();

  if (screen == S_REMOTE || screen == S_MORE) {
    static bool lastBusy = false;
    if (busy != lastBusy) { lastBusy = busy; drawBusy(lastBusy); }
    if (volFresh) { volFresh = false; volUntil = now + 2500; }
    if (stateDirty || now - lastStatus > 200) {
      stateDirty = false;
      lastStatus = now;
      drawStatus();
    }
    if (macDirty) { macDirty = false; prefs.putString("tv_mac", tvMac); }
  }

  // dim after a minute idle
  // millis() here, not the frame's `now`: a touch read this frame can be newer than `now`,
  // and the unsigned difference would wrap around and dim the screen on every tap.
  if (!dimmed && (int32_t)(millis() - lastActivity) > 60000) {
    dimmed = true;
    screenAwake = false;
    tft.setBrightness(20);
  }

  // hold BOOT for 2 s to recalibrate touch
  if (digitalRead(0) == LOW) {
    if (!bootHeld) bootHeld = now;
    else if (now - bootHeld > 2000) {
      bootHeld = 0;
      runCalibration();
      if (apMode) drawAP();
      else goHome();
      lastActivity = millis();
    }
  } else {
    bootHeld = 0;
  }
}
