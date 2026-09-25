# -*- coding: utf-8 -*-
"""MEOW-SEC :: EXIF — Image Metadata OSINT (module #64)"""
import os, io, json, struct, re
from datetime import datetime
from urllib.parse import urlparse

from core.ui import (console, show_module_banner, ok, err, info, warn, find,
                     ask_choice, G1, G2, CY, OR, RD, DM)
from core.cats import cat_talk, CAT_FOUND, CAT_SCAN
from rich.panel  import Panel
from rich.table  import Table
from rich.prompt import Prompt, Confirm
from rich.rule   import Rule
from rich        import box

try:
    import requests as _req
    _req.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAS_PILLOW = True
except Exception:
    HAS_PILLOW = False


# ─── TAGS EXIF importants ────────────────────────────────────────────────────

_IMPORTANT_TAGS = {
    0x0132: "DateTime",
    0x010F: "Make",
    0x0110: "Model",
    0x0131: "Software",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x9286: "UserComment",
    0x8825: "GPSInfo",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0xA420: "ImageUniqueID",
    0x013E: "WhitePoint",
    0x0112: "Orientation",
}

_GPS_TAGS = {
    0: "GPSVersionID",
    1: "GPSLatitudeRef",
    2: "GPSLatitude",
    3: "GPSLongitudeRef",
    4: "GPSLongitude",
    5: "GPSAltitudeRef",
    6: "GPSAltitude",
    7: "GPSTimeStamp",
    12: "GPSSpeedRef",
    13: "GPSSpeed",
    16: "GPSImgDirectionRef",
    17: "GPSImgDirection",
    29: "GPSDateStamp",
}


# ─── PARSING BINAIRE EXIF (sans dépendance externe) ──────────────────────────

def _read_rational(data: bytes, offset: int, endian: str) -> float:
    """Lit un rationnel EXIF (2 uint32) et retourne le float."""
    fmt = f"{endian}II"
    num, den = struct.unpack_from(fmt, data, offset)
    return num / den if den != 0 else 0.0


def _read_srational(data: bytes, offset: int, endian: str) -> float:
    fmt = f"{endian}ii"
    num, den = struct.unpack_from(fmt, data, offset)
    return num / den if den != 0 else 0.0


def _read_value(data: bytes, type_: int, count: int, value_offset: int,
                endian: str, base_offset: int):
    """Lit la valeur d'un tag EXIF selon son type."""
    # Types TIFF:
    # 1=BYTE, 2=ASCII, 3=SHORT, 4=LONG, 5=RATIONAL
    # 6=SBYTE, 7=UNDEFINED, 8=SSHORT, 9=SLONG, 10=SRATIONAL
    try:
        if type_ == 2:  # ASCII
            size = count
            if size <= 4:
                raw = struct.pack(f"{endian}I", value_offset)[:size]
            else:
                raw = data[base_offset + value_offset: base_offset + value_offset + size]
            return raw.rstrip(b"\x00").decode("latin-1", errors="replace")

        elif type_ == 3:  # SHORT
            if count == 1:
                if count * 2 <= 4:
                    raw = struct.pack(f"{endian}I", value_offset)
                    return struct.unpack_from(f"{endian}H", raw)[0]
                else:
                    return struct.unpack_from(f"{endian}H", data, base_offset + value_offset)[0]
            else:
                offset = base_offset + value_offset if count * 2 > 4 else None
                vals = []
                raw = struct.pack(f"{endian}I", value_offset) if count * 2 <= 4 else b""
                for i in range(min(count, 4)):
                    if offset:
                        vals.append(struct.unpack_from(f"{endian}H", data, offset + i * 2)[0])
                    else:
                        vals.append(struct.unpack_from(f"{endian}H", raw, i * 2)[0])
                return vals[0] if len(vals) == 1 else vals

        elif type_ == 4:  # LONG
            if count * 4 <= 4:
                raw = struct.pack(f"{endian}I", value_offset)
                return struct.unpack_from(f"{endian}I", raw)[0]
            else:
                return struct.unpack_from(f"{endian}I", data, base_offset + value_offset)[0]

        elif type_ == 5:  # RATIONAL
            ptr = base_offset + value_offset
            if count == 1:
                return _read_rational(data, ptr, endian)
            else:
                return [_read_rational(data, ptr + i * 8, endian) for i in range(min(count, 8))]

        elif type_ == 10:  # SRATIONAL
            ptr = base_offset + value_offset
            return _read_srational(data, ptr, endian)

        elif type_ == 1 or type_ == 7:  # BYTE / UNDEFINED
            size = count
            if size <= 4:
                raw = struct.pack(f"{endian}I", value_offset)[:size]
            else:
                raw = data[base_offset + value_offset: base_offset + value_offset + size]
            if type_ == 7:
                return raw.decode("latin-1", errors="replace")
            return list(raw)

    except Exception:
        pass
    return None


def _parse_ifd(data: bytes, ifd_offset: int, endian: str, base_offset: int) -> dict:
    """Parse un IFD TIFF et retourne un dict de tags."""
    tags = {}
    try:
        num_entries = struct.unpack_from(f"{endian}H", data, base_offset + ifd_offset)[0]
        entry_offset = base_offset + ifd_offset + 2
        for i in range(num_entries):
            off = entry_offset + i * 12
            if off + 12 > len(data):
                break
            tag_id, type_, count, val_raw = struct.unpack_from(f"{endian}HHI I", data, off)[:4]
            # val_raw est soit la valeur directe (si <=4 bytes) soit un offset
            # on passe value_offset = val_raw
            val = _read_value(data, type_, count, val_raw, endian, base_offset)
            if val is not None:
                tags[tag_id] = val
    except Exception:
        pass
    return tags


def _parse_gps_ifd(data: bytes, gps_offset: int, endian: str, base_offset: int) -> dict:
    """Parse l'IFD GPS et retourne les données GPS."""
    raw = _parse_ifd(data, gps_offset, endian, base_offset)
    gps = {}
    for k, v in raw.items():
        name = _GPS_TAGS.get(k, f"GPS_{k:#06x}")
        gps[name] = v
    return gps


def _exif_from_bytes(data: bytes) -> dict:
    """Parse les données EXIF d'un JPEG depuis ses bytes bruts."""
    result = {}
    if len(data) < 12:
        return result

    # Chercher le segment APP1 (FF E1)
    pos = 2  # sauter SOI (FF D8)
    while pos < len(data) - 4:
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        seg_len = struct.unpack_from(">H", data, pos + 2)[0]

        if marker == 0xE1:  # APP1
            app1_data = data[pos + 4: pos + 2 + seg_len]
            # Vérifier signature "Exif\x00\x00"
            if app1_data[:6] == b"Exif\x00\x00":
                tiff_data = app1_data[6:]
                # Détecter endianness
                if tiff_data[:2] == b"II":
                    endian = "<"
                elif tiff_data[:2] == b"MM":
                    endian = ">"
                else:
                    pos += 2 + seg_len
                    continue

                # Vérifier magic 42
                magic = struct.unpack_from(f"{endian}H", tiff_data, 2)[0]
                if magic != 42:
                    pos += 2 + seg_len
                    continue

                # Offset du premier IFD
                ifd0_offset = struct.unpack_from(f"{endian}I", tiff_data, 4)[0]
                ifd0 = _parse_ifd(tiff_data, ifd0_offset, endian, 0)

                for tag_id, val in ifd0.items():
                    name = _IMPORTANT_TAGS.get(tag_id, f"0x{tag_id:04x}")
                    result[name] = val

                # GPS SubIFD
                if 0x8825 in ifd0:
                    gps_offset = ifd0[0x8825]
                    if isinstance(gps_offset, int):
                        gps = _parse_gps_ifd(tiff_data, gps_offset, endian, 0)
                        if gps:
                            result["GPSInfo"] = gps

                # Exif SubIFD (0x8769)
                if 0x8769 in ifd0:
                    exif_offset = ifd0[0x8769]
                    if isinstance(exif_offset, int):
                        exif_sub = _parse_ifd(tiff_data, exif_offset, endian, 0)
                        for tag_id, val in exif_sub.items():
                            name = _IMPORTANT_TAGS.get(tag_id, None)
                            if name:
                                result[name] = val
            break
        pos += 2 + seg_len

    return result


# ─── GPS → degrés décimaux ───────────────────────────────────────────────────

def _dms_to_decimal(dms, ref: str) -> float:
    """Convertit [deg, min, sec] (rationnels) en degrés décimaux."""
    try:
        if isinstance(dms, list) and len(dms) >= 3:
            deg = float(dms[0])
            mn  = float(dms[1])
            sec = float(dms[2])
        else:
            return None
        decimal = deg + mn / 60.0 + sec / 3600.0
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 7)
    except Exception:
        return None


def _extract_gps(gps_info: dict) -> dict:
    """Extrait lat/lon/alt depuis le dict GPSInfo brut."""
    result = {}
    lat = _dms_to_decimal(
        gps_info.get("GPSLatitude"),
        str(gps_info.get("GPSLatitudeRef", "N"))
    )
    lon = _dms_to_decimal(
        gps_info.get("GPSLongitude"),
        str(gps_info.get("GPSLongitudeRef", "E"))
    )
    if lat is not None and lon is not None:
        result["latitude"]  = lat
        result["longitude"] = lon
        result["maps_url"]  = f"https://www.google.com/maps?q={lat},{lon}"

    alt_raw = gps_info.get("GPSAltitude")
    if alt_raw is not None:
        try:
            result["altitude_m"] = round(float(alt_raw), 2)
        except Exception:
            pass

    date = gps_info.get("GPSDateStamp")
    ts   = gps_info.get("GPSTimeStamp")
    if date:
        result["gps_date"] = str(date)
    if ts:
        result["gps_time"] = str(ts)
    return result


# ─── PILLOW (si disponible) ──────────────────────────────────────────────────

def _exif_via_pillow(img_bytes: bytes) -> dict:
    """Utilise Pillow pour extraire les EXIF si disponible."""
    result = {}
    try:
        img = Image.open(io.BytesIO(img_bytes))
        raw_exif = img._getexif()
        if not raw_exif:
            return result
        for tag_id, val in raw_exif.items():
            tag_name = TAGS.get(tag_id, f"0x{tag_id:04x}")
            if tag_name == "GPSInfo" and isinstance(val, dict):
                gps_decoded = {}
                for gk, gv in val.items():
                    gps_decoded[GPSTAGS.get(gk, f"GPS_{gk}")] = gv
                result["GPSInfo"] = gps_decoded
            else:
                try:
                    result[tag_name] = str(val)[:200]
                except Exception:
                    pass
    except Exception:
        pass
    return result


# ─── ANALYSE PRINCIPALE ──────────────────────────────────────────────────────

def _analyze_image(img_bytes: bytes, filename: str) -> dict:
    """Extrait les EXIF d'une image et retourne un rapport structuré."""
    report = {
        "filename": filename,
        "size_bytes": len(img_bytes),
        "exif": {},
        "gps": {},
        "risk": "NONE",
        "risk_reasons": [],
        "maps_url": None,
    }

    # Utiliser Pillow en priorité si dispo
    if HAS_PILLOW:
        raw = _exif_via_pillow(img_bytes)
    else:
        raw = _exif_from_bytes(img_bytes)

    if not raw:
        report["risk"] = "NONE"
        return report

    report["exif"] = {k: v for k, v in raw.items() if k != "GPSInfo"}

    # GPS
    gps_raw = raw.get("GPSInfo", {})
    if gps_raw:
        gps = _extract_gps(gps_raw)
        report["gps"] = gps
        if "latitude" in gps and "longitude" in gps:
            report["maps_url"] = gps.get("maps_url")
            report["risk"] = "CRITICAL"
            report["risk_reasons"].append("GPS location exposed")

    # Device/Author
    make     = raw.get("Make", "")
    model    = raw.get("Model", "")
    artist   = raw.get("Artist", "")
    comment  = raw.get("UserComment", "")
    if make or model or artist or comment:
        if report["risk"] not in ("CRITICAL",):
            report["risk"] = "HIGH"
        if make or model:
            report["risk_reasons"].append(f"Device fingerprint: {make} {model}".strip())
        if artist:
            report["risk_reasons"].append(f"Author/Identity: {artist}")
        if comment:
            report["risk_reasons"].append("User comment present")

    # Software
    software = raw.get("Software", "")
    if software:
        if report["risk"] not in ("CRITICAL", "HIGH"):
            report["risk"] = "MEDIUM"
        report["risk_reasons"].append(f"Software fingerprint: {software}")

    # Dates seulement
    dt = raw.get("DateTime") or raw.get("DateTimeOriginal") or raw.get("DateTimeDigitized")
    if dt and report["risk"] == "NONE":
        report["risk"] = "LOW"
        report["risk_reasons"].append(f"Date metadata: {dt}")

    return report


def _fetch_image(url: str) -> tuple:
    """Télécharge une image depuis une URL. Retourne (bytes, filename)."""
    if not HAS_REQUESTS:
        return None, None
    try:
        r = _req.get(url, timeout=15, verify=False,
                     headers={"User-Agent": "MEOW-EXIF/1.0"})
        if r.status_code == 200:
            filename = url.split("/")[-1].split("?")[0] or "image"
            return r.content, filename
    except Exception as e:
        err(f"Download error: {e}")
    return None, None


def _scrape_images(page_url: str) -> list:
    """Scrape une page web et retourne les URLs des images trouvées."""
    if not HAS_REQUESTS:
        return []
    try:
        r = _req.get(page_url, timeout=15, verify=False,
                     headers={"User-Agent": "MEOW-EXIF/1.0"})
        if r.status_code != 200:
            return []
        parsed = urlparse(page_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        img_urls = []
        # <img src="...">
        for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', r.text, re.I):
            src = m.group(1)
            if src.startswith("http"):
                img_urls.append(src)
            elif src.startswith("//"):
                img_urls.append(f"{parsed.scheme}:{src}")
            elif src.startswith("/"):
                img_urls.append(f"{base}{src}")

        # Filtrer les formats supportés
        ext_ok = (".jpg", ".jpeg", ".png", ".tiff", ".tif")
        img_urls = [u for u in img_urls
                    if any(u.lower().split("?")[0].endswith(e) for e in ext_ok)]
        return list(dict.fromkeys(img_urls))  # dédupliquer
    except Exception as e:
        err(f"Scrape error: {e}")
        return []


def _print_report(report: dict):
    """Affiche un rapport EXIF formaté."""
    filename = report["filename"]
    risk = report["risk"]
    risk_colors = {"CRITICAL": RD, "HIGH": RD, "MEDIUM": OR, "LOW": CY, "NONE": DM}
    rc = risk_colors.get(risk, DM)

    console.print(f"\n  [{G1}]◈[/] [{G2}]{filename}[/]  [[{rc}]{risk}[/]]")

    exif = report.get("exif", {})
    gps  = report.get("gps", {})

    if not exif and not gps:
        info("  No EXIF data found.")
        return

    # Table EXIF
    important_keys = ["Make", "Model", "Software", "Artist", "Copyright",
                      "DateTime", "DateTimeOriginal", "UserComment", "Orientation"]
    rows = []
    for k in important_keys:
        v = exif.get(k)
        if v:
            rows.append((k, str(v)[:80]))
    # Tags inconnus restants
    for k, v in exif.items():
        if k not in important_keys and not k.startswith("0x"):
            rows.append((k, str(v)[:80]))

    if rows:
        t = Table(box=box.SIMPLE, border_style=G2, header_style=CY, show_header=True,
                  padding=(0, 1))
        t.add_column("Tag",   style=CY, min_width=20)
        t.add_column("Value", style=WH if False else "grey93", min_width=40)
        for row in rows:
            t.add_row(*row)
        console.print(t)

    # GPS
    if gps and "latitude" in gps:
        find(f"GPS: [{CY}]{gps['latitude']}, {gps['longitude']}[/]")
        if report.get("maps_url"):
            info(f"Google Maps: [{CY}]{report['maps_url']}[/]")
        if "altitude_m" in gps:
            info(f"Altitude: {gps['altitude_m']} m")

    for reason in report.get("risk_reasons", []):
        if risk in ("CRITICAL", "HIGH"):
            warn(reason)
        elif risk == "MEDIUM":
            info(reason)


def _save(target: str, results: list):
    os.makedirs("data", exist_ok=True)
    safe_name = re.sub(r"[^\w\-]", "_", target)[:40]
    fname = f"data/exif_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump({
            "target": target,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2, default=str)
    ok(f"Results saved: [bold]{fname}[/]")


# ─── POINT D'ENTRÉE ──────────────────────────────────────────────────────────

def run():
    show_module_banner("exif")
    cat_talk(CAT_SCAN, "Image EXIF metadata OSINT — GPS, device, author, software", CY)
    console.print()

    if not HAS_PILLOW:
        warn("Pillow not installed — using built-in parser (JPEG/TIFF only).")
        info("For full support: [bold]pip install Pillow[/]")
    if not HAS_REQUESTS:
        warn("requests not installed — URL/scrape modes disabled.")

    console.print(f"\n  [{G1}][1][/] Local file")
    console.print(f"  [{G1}][2][/] Image URL")
    console.print(f"  [{G1}][3][/] Scrape all images from a web page")
    console.print(f"  [{G1}][4][/] Local folder (batch)")
    mode = Prompt.ask(f"  [{CY}]◈ Mode[/]", default="1").strip()

    all_reports = []
    target_label = ""

    # ── Mode 1 : fichier local ──────────────────────────────────
    if mode == "1":
        path = Prompt.ask(f"  [{G1}]◈ Image path[/]").strip().strip('"')
        if not os.path.isfile(path):
            err(f"File not found: {path}"); return
        target_label = path
        with open(path, "rb") as f:
            img_bytes = f.read()
        report = _analyze_image(img_bytes, os.path.basename(path))
        all_reports.append(report)
        _print_report(report)

    # ── Mode 2 : URL ────────────────────────────────────────────
    elif mode == "2":
        if not HAS_REQUESTS:
            err("requests required for URL mode."); return
        url = Prompt.ask(f"  [{G1}]◈ Image URL[/]").strip()
        if not url.startswith("http"):
            url = "https://" + url
        target_label = url
        info(f"Downloading {url}...")
        img_bytes, filename = _fetch_image(url)
        if not img_bytes:
            err("Failed to download image."); return
        report = _analyze_image(img_bytes, filename)
        all_reports.append(report)
        _print_report(report)

    # ── Mode 3 : scraping ───────────────────────────────────────
    elif mode == "3":
        if not HAS_REQUESTS:
            err("requests required for scrape mode."); return
        page_url = Prompt.ask(f"  [{G1}]◈ Page URL[/]").strip()
        if not page_url.startswith("http"):
            page_url = "https://" + page_url
        target_label = page_url
        info(f"Scraping images from {page_url}...")
        img_urls = _scrape_images(page_url)
        if not img_urls:
            warn("No images found on that page."); return
        info(f"Found [{G1}]{len(img_urls)}[/] image(s)")

        max_n = IntPrompt_or_default(f"  [{CY}]◈ Max images to analyse[/]", 20)
        for i, img_url in enumerate(img_urls[:max_n], 1):
            info(f"[{i}/{min(len(img_urls), max_n)}] {img_url[:70]}")
            img_bytes, filename = _fetch_image(img_url)
            if img_bytes:
                report = _analyze_image(img_bytes, filename)
                all_reports.append(report)
                _print_report(report)

    # ── Mode 4 : dossier ────────────────────────────────────────
    elif mode == "4":
        folder = Prompt.ask(f"  [{G1}]◈ Folder path[/]").strip().strip('"')
        if not os.path.isdir(folder):
            err(f"Folder not found: {folder}"); return
        target_label = folder
        ext_ok = (".jpg", ".jpeg", ".png", ".tiff", ".tif")
        files = [os.path.join(folder, f) for f in os.listdir(folder)
                 if f.lower().endswith(ext_ok)]
        if not files:
            warn("No image files found in folder."); return
        info(f"Found [{G1}]{len(files)}[/] image file(s)")
        for path in files:
            with open(path, "rb") as f:
                img_bytes = f.read()
            report = _analyze_image(img_bytes, os.path.basename(path))
            all_reports.append(report)
            _print_report(report)
    else:
        err("Unknown mode."); return

    # ── Résumé ──────────────────────────────────────────────────
    console.print()
    if all_reports:
        risk_counts = {}
        gps_found = 0
        for r in all_reports:
            rv = r.get("risk", "NONE")
            risk_counts[rv] = risk_counts.get(rv, 0) + 1
            if r.get("gps", {}).get("latitude"):
                gps_found += 1

        info(f"Analysed [{G1}]{len(all_reports)}[/] image(s)")
        if gps_found:
            find(f"[{RD}]{gps_found}[/] image(s) with GPS location!")
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            cnt = risk_counts.get(level, 0)
            if cnt:
                lc = RD if level in ("CRITICAL", "HIGH") else OR if level == "MEDIUM" else CY
                info(f"  [{lc}]{level}[/]: {cnt}")

        _save(target_label, all_reports)
    else:
        warn("No results to save.")


def IntPrompt_or_default(prompt: str, default: int) -> int:
    """Prompt entier avec valeur par défaut."""
    try:
        from rich.prompt import IntPrompt
        return IntPrompt.ask(prompt, default=default)
    except Exception:
        return default
