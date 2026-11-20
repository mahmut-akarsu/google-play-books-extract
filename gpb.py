#!/usr/bin/env python3
"""
gpb-extract — Google Play Books web okuyucudan kitabı metin + görsel olarak
çıkarıp EPUB ve PDF'e dönüştürür.

Neden gerçek tarayıcı gerekir:
  Google, tarayıcı olmayan istemcilere (curl/requests) reader sayfasında SAHTE bir
  anahtar gifi servis eder ve segmentleri o sahte anahtarla şifreler; ayrıca
  sayfa/görseller için "image not available" placeholder'ı döndürür. Gerçek Chrome
  oturumunda anahtar sabittir ve içerik doğru gelir. Bu yüzden anahtar çıkarımı ve
  tüm indirmeler Playwright + gerçek Chrome içinde yapılır; şifre çözme Python'da
  (pycryptodome) yapılır.

Şifreleme biçimleri:
  - Metin segmenti : base64 gövde -> [16B IV][4B uzunluk (LE)][AES-128-CBC]
  - Görsel         : ikili gövde  -> [16B IV][AES-128-CBC]
  - Anahtar        : reader HTML'indeki ilk `src="data:..."` elemanının base64'ü,
                     Google'ın "bit-shuffle" şemasıyla çözülür.

Kullanım:
  python gpb.py --book-id BOOK_ID --authuser 0 --cookies cookies.json --out books
  python gpb.py --stages extract,images,epub,pdf        # (varsayılan: hepsi)

Yalnızca satın aldığınız/erişim hakkınız olan kitapların kişisel yedeği içindir.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html as htmllib
import json
import os
import re
import sys
import time
import zipfile

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sys.exit("Eksik paket: pip install playwright")

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover
    sys.exit("Eksik paket: pip install pycryptodome")


# --------------------------------------------------------------------------- #
#  JS köprüleri
# --------------------------------------------------------------------------- #
JS_KEY = r"""
() => {
  // Google'ın kendi yöntemi: <body> içindeki ilk src'li eleman (gizli anahtar).
  let el = null;
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
  let n; while ((n = w.nextNode())) { if (n.src) { el = n; break; } }
  if (!el) return null;
  const raw = atob(el.src.split(",")[1]);
  const groups = raw.match(/([^\d]+\d)/g);
  if (!groups || groups.length !== 128) return "ERR_GROUPS_" + (groups ? groups.length : 0);
  let bits = groups.map(g => {
    const c = +g.slice(-1);
    return g.charAt(c) === g.charAt(g.length - 2) ? 1 : 0;
  });
  const shift = 64 % bits.length;
  bits = bits.slice(-shift).concat(bits.slice(0, -shift));
  const key = new Uint8Array(16);
  for (let i = 0; i < 128; i += 8) {
    let v = 0;
    for (let f = 0; f < 8; f++) if (bits[i + f]) v += (1 << f);
    key[i / 8] = v;
  }
  return [...key].map(x => x.toString(16).padStart(2, "0")).join("");
}
"""

# Herhangi bir URL'yi tarayıcı bağlamında (çerez + parmak izi) indirir,
# gövdeyi base64 olarak döndürür.
JS_FETCH = r"""
async (url) => {
  const r = await fetch(url, { credentials: 'include' });
  const buf = new Uint8Array(await r.arrayBuffer());
  let s = ""; const C = 0x8000;
  for (let i = 0; i < buf.length; i += C) s += String.fromCharCode.apply(null, buf.subarray(i, i + C));
  return { status: r.status, ctype: r.headers.get('content-type'), b64: btoa(s) };
}
"""

PLACEHOLDER_MD5 = {"e840da9dbe7e"}  # Google'ın "image not available" görseli


# --------------------------------------------------------------------------- #
#  Yardımcılar
# --------------------------------------------------------------------------- #
def load_cookies(path: str) -> list[dict]:
    """EditThisCookie tarzı JSON'u Playwright formatına çevirir."""
    data = json.load(open(path, encoding="utf-8"))
    out = []
    for c in data:
        ss = c.get("sameSite")
        if ss not in ("Strict", "Lax", "None"):
            ss = "Lax"
        o = {
            "name": c["name"], "value": c["value"],
            "domain": c.get("domain", ".google.com"), "path": c.get("path", "/"),
            "httpOnly": bool(c.get("httpOnly")), "secure": bool(c.get("secure")),
            "sameSite": ss,
        }
        if c.get("expirationDate"):
            o["expires"] = int(c["expirationDate"])
        out.append(o)
    return out


def ext_of(b: bytes) -> str | None:
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if b[:3] == b"\xff\xd8\xff":
        return "jpg"
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "webp"
    return None


def decrypt_segment(blob: bytes, key: bytes) -> bytes:
    """[IV(16)][len(4 LE)][AES-128-CBC] -> düz metin."""
    iv, expected, data = blob[:16], int.from_bytes(blob[16:20], "little"), blob[20:]
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)[:expected]


def decrypt_image(blob: bytes, key: bytes) -> bytes:
    """[IV(16)][AES-128-CBC] -> görsel baytları."""
    return AES.new(key, AES.MODE_CBC, blob[:16]).decrypt(blob[16:])


class Reader:
    """Gerçek Chrome oturumu; anahtarı ve içeriği buradan çeker."""

    def __init__(self, book: str, authuser: str, cookies: list[dict], headless=True):
        self.book = book
        self.authuser = authuser
        self.cookies = cookies
        self.headless = headless

    def __enter__(self):
        self._p = sync_playwright().start()
        self.browser = self._p.chromium.launch(
            channel="chrome", headless=self.headless,
            args=["--disable-blink-features=AutomationControlled"])
        self.ctx = self.browser.new_context(locale="tr-TR")
        self.ctx.add_cookies(self.cookies)
        self.page = self.ctx.new_page()
        url = (f"https://play.google.com/books/reader?id={self.book}"
               f"&hl=en&authuser={self.authuser}")
        self.page.goto(url, wait_until="domcontentloaded", timeout=60000)
        time.sleep(6)
        kh = self.page.evaluate(JS_KEY)
        if not isinstance(kh, str) or len(kh) != 32:
            raise RuntimeError(f"AES anahtarı alınamadı: {kh!r}")
        self.key = bytes.fromhex(kh)
        return self

    def __exit__(self, *exc):
        try:
            self.browser.close()
        finally:
            self._p.stop()

    def fetch(self, url: str) -> dict:
        return self.page.evaluate(JS_FETCH, url)

    def fetch_raw(self, url: str) -> bytes:
        r = self.fetch(url)
        if r["status"] != 200:
            raise RuntimeError(f"HTTP {r['status']}")
        return base64.b64decode(r["b64"])


# --------------------------------------------------------------------------- #
#  Aşamalar
# --------------------------------------------------------------------------- #
def seg_url(book: str, authuser: str, label: str) -> str:
    return ("https://play.google.com/books/volumes/%s/content/segment"
            "?authuser=%s&av=2&avail_pid=0&cds=2&ef=4&enc_all=1&flvers=1"
            "&hl=en&inline=0&multi_toc=1&source=ge-web-app&start=%s&svg=2&vert=1"
            % (book, authuser, label))


def stage_extract(rd: Reader, out: str) -> dict:
    """Manifest + tüm metin segmentlerini indirip çözer, xhtml/css yazar."""
    segdir = os.path.join(out, "segments")
    os.makedirs(segdir, exist_ok=True)
    manifest_url = (f"https://play.google.com/books/volumes/{rd.book}/manifest"
                    f"?hl=en&authuser={rd.authuser}&source=ge-web-app")
    manifest = json.loads(rd.fetch_raw(manifest_url).decode("utf-8"))
    json.dump(manifest, open(os.path.join(out, "manifest.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    preview = manifest.get("metadata", {}).get("preview")
    print(f"[extract] preview={preview} segment={len(manifest.get('segment', []))}")
    if preview != "full":
        print("[extract] UYARI: preview 'full' değil — kitap bu hesapta tam açık değil.")

    ok = 0
    for s in manifest.get("segment", []):
        label = s["label"]
        try:
            raw = rd.fetch_raw(seg_url(rd.book, rd.authuser, label))  # gövde = base64 metin
            blob = base64.b64decode(raw)
            obj = json.loads(decrypt_segment(blob, rd.key).decode("utf-8"))
            open(os.path.join(segdir, f"{label}.xhtml"), "w", encoding="utf-8").write(obj.get("content", ""))
            if obj.get("style"):
                open(os.path.join(segdir, f"{label}.css"), "w", encoding="utf-8").write(obj["style"])
            ok += 1
        except Exception as e:  # noqa: BLE001
            print(f"    [!!] {label}: {e}")
    print(f"[extract] {ok} segment yazıldı -> {segdir}")
    return manifest


def stage_images(rd: Reader, out: str) -> int:
    """xhtml'lerdeki görselleri indirip çözer, referansları yerelleştirir."""
    segdir = os.path.join(out, "segments")
    imgdir = os.path.join(out, "images")
    os.makedirs(imgdir, exist_ok=True)

    pg2url: dict[str, str] = {}
    per_file: dict[str, list[str]] = {}
    for f in sorted(os.listdir(segdir)):
        if not f.endswith(".xhtml"):
            continue
        s = open(os.path.join(segdir, f), encoding="utf-8").read()
        for u in re.findall(r'<img[^>]*?src="(https://play\.google\.com/books/publisher/content/reader[^"]+)"', s):
            u = u.replace("&amp;", "&")
            m = re.search(r"pg=([^&]+)", u)
            if not m:
                continue
            pg = m.group(1)
            # enc_all ekle; img=1 İKİNCİ KEZ EKLENMEZ (aksi halde yanıt bozulur)
            if "enc_all=1" not in u:
                u += "&enc_all=1&source=ge-web-app"
            pg2url[pg] = u
            per_file.setdefault(f, []).append(pg)

    pg2file: dict[str, str] = {}
    ok = ph = 0
    for pg, u in pg2url.items():
        try:
            blob = rd.fetch_raw(u)
            dec = decrypt_image(blob, rd.key) if not ext_of(blob) else blob
            ext = ext_of(dec)
            if not ext:
                raise RuntimeError("görsel imzası yok")
            name = f"{pg}.{ext}" if not pg.lower().endswith(("." + ext,)) else pg
            name = f"{pg}.{ext}"
            open(os.path.join(imgdir, name), "wb").write(dec)
            pg2file[pg] = name
            if hashlib.md5(dec).hexdigest()[:12] in PLACEHOLDER_MD5:
                ph += 1
            else:
                ok += 1
        except Exception as e:  # noqa: BLE001
            print(f"    [!!] {pg}: {e}")
    print(f"[images] ok={ok} placeholder={ph} -> {imgdir}")

    # ön kapak
    try:
        cpath = f"https://play.google.com/books/publisher/content/images/frontcover/{rd.book}?fife=s1200"
        raw = rd.fetch_raw(cpath)
        dec = raw if ext_of(raw) else decrypt_image(raw, rd.key)
        ce = ext_of(dec)
        if ce:
            os.makedirs(os.path.join(out, "pages"), exist_ok=True)
            open(os.path.join(out, "pages", f"000_frontcover.{ce}"), "wb").write(dec)
            print(f"[images] kapak -> 000_frontcover.{ce}")
    except Exception as e:  # noqa: BLE001
        print(f"    [!!] kapak: {e}")

    # xhtml referanslarını yerelleştir
    for f, pgs in per_file.items():
        path = os.path.join(segdir, f)
        s = open(path, encoding="utf-8").read()

        def repl(m):
            u = m.group(1).replace("&amp;", "&")
            pm = re.search(r"pg=([^&]+)", u)
            pg = pm.group(1) if pm else None
            if pg in pg2file:
                return 'src="images/' + pg2file[pg] + '"'
            return m.group(0)

        s2 = re.sub(r'src="(https://play\.google\.com/books/publisher/content/reader[^"]+)"', repl, s)
        if s2 != s:
            open(path, "w", encoding="utf-8").write(s2)
    return ok


def _segments_in_order(manifest: dict):
    return sorted(manifest.get("segment", []), key=lambda s: s.get("order", 0))


def _keep(raw: str, txt: str) -> bool:
    return len(txt.strip()) >= 20 or "<img" in raw


def stage_epub(out: str) -> str:
    """Çözülmüş segmentlerden (+ görseller + kapak) EPUB 3 üretir."""
    segdir = os.path.join(out, "segments")
    manifest = json.load(open(os.path.join(out, "manifest.json"), encoding="utf-8"))
    meta = manifest.get("metadata", {})
    title = htmllib.unescape(meta.get("title", "book"))
    author = htmllib.unescape(meta.get("authors", ""))
    lang = meta.get("language", "tr")

    cover = None
    pdir = os.path.join(out, "pages")
    if os.path.isdir(pdir):
        for f in sorted(os.listdir(pdir)):
            if f.startswith("000_frontcover"):
                cover = os.path.join(pdir, f)
                break

    def xhtml(t, body, css_href=None):
        link = f'<link rel="stylesheet" type="text/css" href="{css_href}"/>' if css_href else ""
        return ('<?xml version="1.0" encoding="utf-8"?>\n'
                f'<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="{lang}" lang="{lang}">\n'
                f'<head><meta charset="utf-8"/><title>{htmllib.escape(str(t))}</title>{link}</head>\n'
                f'<body>{body}</body></html>')

    files: dict[str, bytes | str] = {}
    manifest_items, spine, nav_items = [], [], []
    referenced_imgs = set()
    chapters = []

    for s in _segments_in_order(manifest):
        label = s["label"]
        p = os.path.join(segdir, label + ".xhtml")
        if not os.path.exists(p):
            continue
        raw = open(p, encoding="utf-8").read()
        txt = htmllib.unescape(re.sub(r"<[^>]+>", " ", raw))
        if not _keep(raw, txt):
            continue
        css = os.path.join(segdir, label + ".css")
        css = open(css, encoding="utf-8").read() if os.path.exists(css) else ""
        chapters.append((label, s.get("title", label), raw, css))

    if cover:
        files["OEBPS/images/cover.jpg"] = open(cover, "rb").read()
        files["OEBPS/cover.xhtml"] = xhtml(
            "Kapak",
            '<div style="text-align:center;"><img src="images/cover.jpg" alt="Kapak" '
            'style="max-width:100%;height:auto;"/></div>')
        manifest_items.append('<item id="cover-img" href="images/cover.jpg" media-type="image/jpeg"/>')
        manifest_items.append('<item id="cover" href="cover.xhtml" media-type="application/xhtml+xml"/>')
        spine.append('<itemref idref="cover"/>')
        nav_items.append('<li><a href="cover.xhtml">Kapak</a></li>')

    for n, (label, ttitle, body, css) in enumerate(chapters, 1):
        cid = f"c{n}"
        xhref = f"{label}.xhtml"
        css_href = None
        if css.strip():
            css_href = f"{label}.css"
            files[f"OEBPS/{css_href}"] = css
            manifest_items.append(f'<item id="css{n}" href="{css_href}" media-type="text/css"/>')
        files[f"OEBPS/{xhref}"] = xhtml(ttitle, body, css_href)
        manifest_items.append(f'<item id="{cid}" href="{xhref}" media-type="application/xhtml+xml"/>')
        spine.append(f'<itemref idref="{cid}"/>')
        nav_items.append(f'<li><a href="{xhref}">{htmllib.escape(str(ttitle))}</a></li>')
        for ref in re.findall(r'src="(images/[^"]+)"', body):
            referenced_imgs.add(ref)

    for k, ref in enumerate(sorted(referenced_imgs), 1):
        fp = os.path.join(out, ref)
        if not os.path.exists(fp):
            continue
        name = ref.split("/")[-1]
        files[f"OEBPS/images/{name}"] = open(fp, "rb").read()
        low = name.lower()
        mt = ("image/jpeg" if low.endswith((".jpg", ".jpeg")) else
              "image/gif" if low.endswith(".gif") else
              "image/webp" if low.endswith(".webp") else "image/png")
        manifest_items.append(f'<item id="img{k}" href="images/{name}" media-type="{mt}"/>')

    files["OEBPS/nav.xhtml"] = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops" '
        f'xml:lang="{lang}" lang="{lang}"><head><meta charset="utf-8"/><title>İçindekiler</title></head>'
        '<body><nav epub:type="toc" id="toc"><h1>İçindekiler</h1><ol>'
        + "".join(nav_items) + "</ol></nav></body></html>")
    manifest_items.append('<item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/>')

    uid = "urn:uuid:" + str(meta.get("volume_id", "book"))
    files["OEBPS/content.opf"] = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="bookid">\n'
        '<metadata xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f'<dc:identifier id="bookid">{uid}</dc:identifier>'
        f'<dc:title>{htmllib.escape(title)}</dc:title>'
        f'<dc:creator>{htmllib.escape(author)}</dc:creator>'
        f'<dc:language>{lang}</dc:language>'
        f'<dc:publisher>{htmllib.escape(meta.get("publisher", ""))}</dc:publisher>'
        '<meta property="dcterms:modified">2026-01-01T00:00:00Z</meta>'
        '</metadata>\n<manifest>' + "".join(manifest_items) + '</manifest>\n'
        '<spine>' + "".join(spine) + '</spine>\n</package>')
    files["META-INF/container.xml"] = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">'
        '<rootfiles><rootfile full-path="OEBPS/content.opf" '
        'media-type="application/oebps-package+xml"/></rootfiles></container>')

    epub_path = os.path.join(out, "book.epub")
    with zipfile.ZipFile(epub_path, "w") as z:
        z.writestr("mimetype", "application/epub+zip", zipfile.ZIP_STORED)
        for name, data in files.items():
            z.writestr(name, data, zipfile.ZIP_DEFLATED)
    print(f"[epub] {epub_path}  bölüm={len(chapters)}  görsel={len(referenced_imgs)}")
    return epub_path


def stage_pdf(out: str) -> str:
    """Segmentlerden, görselleri sayfaya sığdırarak PDF üretir (Chrome print)."""
    segdir = os.path.join(out, "segments")
    manifest = json.load(open(os.path.join(out, "manifest.json"), encoding="utf-8"))
    meta = manifest.get("metadata", {})
    title = htmllib.unescape(meta.get("title", "book"))
    lang = meta.get("language", "tr")

    cover = None
    pdir = os.path.join(out, "pages")
    if os.path.isdir(pdir):
        for f in sorted(os.listdir(pdir)):
            if f.startswith("000_frontcover"):
                cover = os.path.join(pdir, f)
                break

    parts, all_css = [], []
    if cover:
        parts.append(f'<section class="cover"><img src="file:///{cover.replace(os.sep, "/")}"/></section>')
    for s in _segments_in_order(manifest):
        label = s["label"]
        p = os.path.join(segdir, label + ".xhtml")
        if not os.path.exists(p):
            continue
        raw = open(p, encoding="utf-8").read()
        txt = htmllib.unescape(re.sub(r"<[^>]+>", " ", raw))
        if not _keep(raw, txt):
            continue
        raw = re.sub(r'(<img\b[^>]*?)\s+width="\d+"\s+height="\d+"', r"\1", raw)
        raw = re.sub(r'(<img\b[^>]*?)\s+height="\d+"\s+width="\d+"', r"\1", raw)
        parts.append(f'<section class="seg">{raw}</section>')
        css = os.path.join(segdir, label + ".css")
        if os.path.exists(css):
            all_css.append(re.sub(r"@font-face\s*\{[^}]*\}", "", open(css, encoding="utf-8").read()))

    doc = f"""<!DOCTYPE html><html lang="{lang}"><head><meta charset="utf-8"/>
<title>{htmllib.escape(title)}</title><style>
  @page {{ size: A5; margin: 12mm; }}
  * {{ box-sizing: border-box; }}
  html, body {{ font-family: "Georgia","Times New Roman",serif; font-size: 10.5pt; line-height: 1.5; color:#000; }}
  section.cover {{ break-after: page; text-align:center; }}
  section.cover img {{ max-width:100%; max-height:180mm; }}
  section.seg {{ break-after: page; }}
  section.seg:last-child {{ break-after: auto; }}
  img {{ max-width:100% !important; max-height:170mm !important; width:auto !important;
        height:auto !important; display:block; margin:0 auto; break-inside: avoid; }}
  p {{ text-align: justify; margin: 0 0 6pt; }}
  p.img_buyuk {{ text-align:center; margin:0; }}
  h1,h2,h3 {{ break-after: avoid; }}
  {''.join(all_css)}
</style></head><body>{''.join(parts)}</body></html>"""

    tmp = os.path.join(out, "_render.html")
    open(tmp, "w", encoding="utf-8").write(doc)
    pdf_path = os.path.join(out, "book.pdf")
    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome", headless=True)
        pg = b.new_page()
        pg.goto("file:///" + tmp.replace(os.sep, "/"), wait_until="networkidle")
        time.sleep(2)
        pg.pdf(path=pdf_path, format="A5", print_background=True,
               margin={"top": "12mm", "bottom": "12mm", "left": "12mm", "right": "12mm"})
        b.close()
    os.remove(tmp)
    print(f"[pdf] {pdf_path}")
    return pdf_path


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Google Play Books -> EPUB/PDF")
    ap.add_argument("--book-id", required=True)
    ap.add_argument("--authuser", default="0", help="Hesap indeksi (satın alan hesap)")
    ap.add_argument("--cookies", default="cookies.json", help="Çerez JSON dosyası")
    ap.add_argument("--out", default="books")
    ap.add_argument("--stages", default="extract,images,epub,pdf")
    a = ap.parse_args()

    stages = [s.strip() for s in a.stages.split(",") if s.strip()]
    out = os.path.join(a.out, a.book_id)
    os.makedirs(out, exist_ok=True)

    if not os.path.exists(a.cookies):
        sys.exit(f"Çerez dosyası yok: {a.cookies}")

    need_browser = any(s in stages for s in ("extract", "images"))
    if need_browser:
        cookies = load_cookies(a.cookies)
        with Reader(a.book_id, a.authuser, cookies) as rd:
            print(f"[key] {rd.key.hex()}")
            if "extract" in stages:
                stage_extract(rd, out)
            if "images" in stages:
                stage_images(rd, out)

    # manifest gerekli
    if not os.path.exists(os.path.join(out, "manifest.json")):
        sys.exit("manifest.json yok; önce 'extract' çalıştırın.")
    if "epub" in stages:
        stage_epub(out)
    if "pdf" in stages:
        stage_pdf(out)


if __name__ == "__main__":
    main()
