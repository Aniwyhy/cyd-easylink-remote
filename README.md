# CYD TV Remote (Philips EasyLink)

Touch remote for Philips TVs on the 4" "Cheap Yellow Display" (ESP32-3248S040: ST7796 320×480, XPT2046 touch, CH340 USB), in portrait.

EasyLink is Philips's name for HDMI-CEC, and the CYD has no HDMI port. So the remote controls the TV over WiFi with Philips's JointSpace API, the same one the Philips TV Remote app uses:

- **2016 and newer (Android / Google TV):** HTTPS on port 1926, paired once with a PIN the TV shows (API 6).
- **Older sets:** plain HTTP on port 1925, no pairing (API 1/5). On some of them JointSpace must be turned on first: while watching TV, type `5646877223` on the TV's own remote.

Devices linked to the TV through EasyLink (soundbar, receiver) still follow it, because the TV passes the commands on over CEC.

## Screens

- **Remote:** power, Sources, TV, Home, Ambilight on/off, D-pad with OK, Info, Subtitles, Back, Options, volume and channel rockers, Mute, Play/Pause, and a media row (rewind, previous, stop, next, fast forward). D-pad, volume and channel repeat while held. After a volume change the header shows the TV's volume.
- **Keypad & more:** digits, Teletext, Dot, the four colour keys, Format, Adjust, Search, Settings.
- **Settings:** TV and network details, Find another TV, Pair again, Calibrate touch, Change WiFi.

The header dot shows the TV's state: green = on, amber = standby, grey = not reachable. Power works from standby; from fully off it sends Wake-on-LAN and the Chromecast wake call. For that, turn on **Settings > Wireless & networks > Turn on with WiFi (WoWLAN)** (or **Turn on with Chromecast**) on the TV.

The screen dims after a minute idle; the first touch only wakes it.

## Setup

1. **WiFi:** on first boot the board opens a hotspot called `TV-Remote`. Scan the QR code on screen (the password is shown under it), then pick your WiFi on the page that opens (http://192.168.4.1).
2. **TV:** with the TV on, the remote searches the network (SSDP, then a scan of port 1925) and lists the Philips TVs it finds. Tap yours. If it isn't found, use **Enter IP** (the TV shows its address under Settings > Network).
3. **PIN:** newer TVs show a 4-digit PIN. Type it on the remote and tap **Pair**.

Everything (WiFi, TV address, pairing keys, touch calibration) is stored in the board's flash (NVS).

## Flash a release (no tools needed)

Download the zip from [Releases](https://github.com/Aniwyhy/cyd-easylink-remote/releases), unzip it, plug in the CYD and run the flash script: **Windows** double-click `flash.bat`; **macOS** `bash flash.sh` in Terminal; **Linux** `bash flash.sh`. It fetches Espressif's standalone esptool and finds the board by itself.

## Build and flash

```bash
pio run -t upload --upload-port /dev/cu.usbserial-10
```

Upload speed is 460800 because the CH340 is unreliable at 921600.

## Touch calibration

On first boot the screen asks you to tap four corner arrows; the result is saved. Hold **BOOT** for 2 seconds at any time to recalibrate.

## Notes

- Pairing follows the method used by [pylips](https://github.com/eslavnov/pylips) and Home Assistant's Philips integration (digest auth, HMAC-SHA1 signed PIN).
- Philips's newer Titan OS sets (non-Android, 2023+) may not expose JointSpace; they'd need an IR LED instead.
- Serial output (115200 baud) logs the pairing requests, which helps if a TV refuses to pair.
