# google-play-books-extract

Turn a book you have legitimate access to in the **Google Play Books web reader**
into a clean **EPUB 3** and **PDF** — reflowable text **and** the original page
/scanned images, in their correct positions.

Built as *interoperability / personal-backup* tooling: Google Play Books only
offers reading in the browser (and a DRM'd download in the app), so this
reconstructs a usable local copy of books you can already read in full.

> **Use it only for books you own / are entitled to read.** Don't use it to
> distribute someone else's work. You are responsible for how you use it.

---

## Why a real browser is required

This is the single most important thing to understand.

Google's Play Books reader does **not** hand out a PDF or EPUB. It streams the
book as encrypted **segments** from:

```
GET https://play.google.com/books/volumes/<BOOK_ID>/content/segment?start=<label>&enc_all=1&...
```

Every response body is **base64** wrapping an **AES-128-CBC** ciphertext:

```
[ 16-byte IV ][ 4-byte plaintext length (little-endian) ][ AES-128-CBC ciphertext ]
```

The AES key is **not** in the network traffic. It is hidden in the reader HTML
page (`https://play.google.com/books/reader?id=<BOOK_ID>`) inside a
`src="data:...;base64,..."` blob, obfuscated with a custom **bit-shuffle** scheme.

### The anti-scraping trap

If you request the reader page with a non-browser client (`curl`, `requests`),
Google serves a **fake, randomised key** and encrypts that request's segments
with the fake key — so naive scraping always decrypts to garbage. Page images
similarly come back as the *"image not available"* placeholder.

A **real Chrome** session gets a stable, correct key, and all downloads work.
That is why this tool drives Chrome through **Playwright** for key extraction and
every download, then decrypts in Python with `pycryptodome`.

### Account index (`authuser`) matters

If the browser profile is signed into multiple Google accounts, the one that owns
the book may not be `authuser=0`. If the manifest reports `"preview": "partial"`
even though you own the book, try other indices (`--authuser 1`, `2`, …). With the
right one the manifest reports `"preview": "full"`.

---

## Requirements

- Python 3.10+
- Google **Chrome** installed (Playwright is launched with `channel="chrome"`)
- Packages:

```bash
pip install playwright pycryptodome
# optional, only for verifying the output yourself:
pip install pypdf pymupdf
```

---

## Cookies

Export your Google cookies as **EditThisCookie / JSON** (a list of cookie
objects). Any of the usual browser extensions works.

> **Never commit your cookie file.** It is a full session token. This repo's
> `.gitignore` already excludes `cookies.json` and friends — keep it that way.

The tool normalises the JSON internally, so `sameSite: null` / `"unspecified"`
etc. are fine.

---

## Usage

```bash
# full pipeline: extract text -> fetch images -> build EPUB -> build PDF
python gpb.py --book-id <BOOK_ID> --authuser 0 --cookies cookies.json --out books
```

`<BOOK_ID>` is the `id=` value in the reader URL, e.g.
`https://play.google.com/books/reader?id=MysZEgAAQBAJ` → `MysZEgAAQBAJ`.

Run individual stages with `--stages`:

```bash
python gpb.py --book-id <ID> --authuser 0 --stages extract          # manifest + text segments
python gpb.py --book-id <ID> --authuser 0 --stages images           # download + decrypt images
python gpb.py --book-id <ID> --stages epub                          # build EPUB (no browser)
python gpb.py --book-id <ID> --stages pdf                           # build PDF  (no browser)
```

Output layout:

```
books/<BOOK_ID>/
├── manifest.json
├── segments/            # decrypted XHTML + CSS (images localised to ../images)
├── images/              # decrypted page / facsimile images
└── book.epub  book.pdf
```

---

## How it works (technical)

1. **Manifest** — `…/volumes/<ID>/manifest` lists every segment (`label`,
   `link`) and page. `metadata.preview` is `full` when the book is fully open.

2. **Key extraction** — the reader page's first element with a `src` carries a
   `data:image/gif;base64,…` blob. Its decoded text is split with `/([^\d]+\d)/g`
   into 128 groups; each group yields one bit
   (`group[group[-1]] == group[-2]`). The 128 bits are rotated by `64 % len`,
   packed 8-to-a-byte with reversed bit order → the 16-byte AES key. This is
   Google's own client algorithm.

3. **Text segments** — body is base64 text → decoded to
   `[IV][len LE][AES-CBC ct]` → decrypt → UTF-8 JSON with `content` (XHTML) and
   `style` (CSS).

4. **Images** — referenced inline in the XHTML as
   `…/publisher/content/reader?…&pg=imageNNN.png&…&sig=…`. Body is binary
   `[IV][AES-CBC ct]` (no length prefix). `sig` is a content signature; add
   `&enc_all=1` for encrypted delivery. **Do not append `img=1` a second time** —
   the request then returns a broken/placeholder response. Decrypted images are
   saved locally and the `<img src>` references rewritten to relative paths.

5. **EPUB** — segments become XHTML chapters (each keeps its own CSS), all
   referenced images are embedded under `OEBPS/images/`, plus the front cover and
   an EPUB 3 `nav`. Built as a plain zip.

6. **PDF** — Chromium prints one combined HTML to PDF. Segment sections use
   `break-after: page`; images are constrained with `max-width/max-height` and
   their `width`/`height` attributes stripped, so tall scans fit the page instead
   of overflowing (which otherwise produces cut-off images and blank pages).

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `preview: partial`, most segments empty | Wrong `authuser`, or the book isn't owned by that account. Try other indices. |
| Decrypted text is garbage | You're hitting a non-browser client path; make sure Playwright + Chrome is used (this tool does). |
| Images are the "image not available" placeholder | You duplicated `img=1`, or the `sig` URL was altered. Use the URL exactly as it appears in the XHTML, only adding `enc_all=1`. |
| PDF: cut-off images / many blank pages | Images overflowing the page. Keep the PDF CSS constraints (`max-height` on `img`, `break-after` per section). |
| Key extraction returns `ERR_GROUPS_n` | The reader HTML changed; update `JS_KEY` regex. |

---

## Legal / ethical note

This project is for reading and backing up books **you have legitimately
purchased or have access to**, on the devices and formats of your choosing. It
does not circumvent anything you don't already have access to, and it is not
intended for redistribution. Respect copyright and Google's terms of service.

## License

MIT — see [LICENSE](LICENSE).
