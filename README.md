# Contact Email

Publishes a contact address on a **Bludit 3.21** site without publishing it to
crawlers. The address is never in the served HTML - it is encoded, split across
randomly named attributes and only reassembled when a visitor actually clicks.

Optionally the address is genuinely **encrypted**, and the browser has to compute
the key before it can be shown. A visitor waits a few seconds once. A harvester
pays the same cost for every address on every page it fetches.

## Screenshots
### Frontend (proof of work)
<img width="400" height="399" alt="bludit-plugin-contac-email_screenshot" src="https://github.com/user-attachments/assets/25275704-7c94-4bba-92c6-7eb91b9d701c" />

### Backend (admin panel)
<img width="1291" height="847" alt="bludit-plugin-contact-email_admin" src="https://github.com/user-attachments/assets/6026c6c9-4221-4adc-9ef8-e1c5dc1a64dc" />

---
## Installing
[Download](https://github.com/toby-sutor/bludit-plugin-contact-email/releases/download/v0.2.3/contact-email.zip) the latest release.
Extract and copy the folder as it is:

```
bl-plugins/contact-email/
├── plugin.php
├── metadata.json
├── css/contact-email.css
├── js/contact-email.js
├── js/sha256.js
└── languages/
```

1. Upload `contact-email/` into your site's `bl-plugins/` directory.
2. Go to **Settings → Plugins** and click **Activate** on *Contact Email*.
3. Open its settings and enter the address.
4. Write `{{contact-email}}` into a page, or switch on the sidebar widget.

Keep the folder name. Bludit derives the plugin's storage directory from it, and
renaming it after install orphans your settings.

Requires Bludit **3.21**. `js/sha256.js` is only served when proof of work is on.
Languages: English, German (`de_DE.json`).

---

## Settings

| Setting | Default | Effect |
|---|---|---|
| Email address | - | Stored in plain text on the server, never sent to the browser in readable form. |
| Button text | *Show email address* | What the visitor clicks. |
| Subject line | - | Pre-filled in the visitor's mail client. Empty for none. |
| Extra CSS class | - | Added to the button. The plugin's own class stays regardless. |
| Appearance | Button | The theme's own `btn btn-primary`, or a plain text link. |
| Require proof of work | on | Encrypts the address and makes the browser compute the key. |
| Difficulty in bits | 22 | 8-26; each extra bit doubles the work. Values outside the range are clamped server-side, not just in the form. |
| Sidebar widget | off | The same button in the theme sidebar, on every page. |
| Sidebar heading | *Contact* | |
| Debug | off | Explains the reveal in the browser console. Publishes a checksum of the address **and the decryption key**, so it voids the proof of work while it is on. |

Rough guide for the difficulty, on a desktop at ~650,000 hashes/second - a phone
is about four times slower. Measured in a real browser on a real page; an idle
machine running headless Chromium reports nearer 840,000, which flatters every
row below:

| Bits | Average | Worst case |
|---|---|---|
| 19 | 0.4 s | 0.8 s |
| 20 | 0.8 s | 1.6 s |
| 22 | 3 s | 6 s |
| 24 | 13 s | 26 s |
| 25 | 26 s | 52 s |
| 26 | 52 s | 103 s |

The average is what almost everyone experiences: the secret is drawn uniformly
from the range, so the search finds it around halfway. The worst case is real
but rare.

---

## Features

### The address is not in the page

What ships to the browser is `str_rot13` of the address, base64'd, cut into three
pieces and written into three `data-x<random hex>` attributes in shuffled order,
alongside a fourth attribute holding a plausible decoy address in plain text. A
harvester that greps the HTML for `@` finds the decoy and nothing else; one that
reads `data-` attributes has to know which three of the four to take, in which
order, and what to do with them.

There is no `href` at all until the click, so nothing walks the page for
`mailto:` and finds it either.

### Proof of work (optional, recommended)

Where obfuscation only raises the cost of parsing, this raises the cost of
*wanting to*.

The server picks a random secret below 2^*bits*, publishes
`sha256(salt + secret)`, and encrypts the address with a key derived from the
secret the other way round - `sha256(secret + salt)`. The browser has to find the
secret by trying every value, and only then can it decrypt anything.

That distinction is what makes it worth having. A plugin that merely waits five
seconds and then reveals a string it already had is bypassed by calling the
reveal function directly; this one cannot be, because **the answer to the puzzle
is the decryption key**. There is no code path, in the browser or in the page,
that produces the address without doing the work. The test suite asserts exactly
that.

Cost is asymmetric on purpose: your visitor solves one puzzle, once, deliberately.
A harvester crawling 10,000 pages solves 10,000 puzzles, each one fresh - every
render mints a new salt, a new secret and new ciphertext, so nothing is cacheable
across pages or reusable across runs.

While it runs, the button shows a progress bar and a percentage; the search space
is bounded, so the percentage is real rather than decorative. The work happens on
the main thread in adaptive slices sized to about 16 ms and yields between them
via `MessageChannel`, so the page stays scrollable and the browser does not offer
to kill the tab.

### Debugging a reveal that does not work

Every button carries the version of the plugin that rendered it, and the script
compares it against its own. If they differ the script **refuses to decode** and
says so in the console, rather than producing the mojibake an old decoder makes
of new ciphertext. That check is always on and costs nothing.

The *Debug* setting adds the rest: a step-by-step account of the reveal in the
console, a server-side self-test of the cipher, the PHP and Bludit versions,
`mbstring.func_overload` (which would silently corrupt every byte), a checksum of
the address so the console can state whether the decrypted text is *correct*
rather than merely non-empty, and the decryption key so a failed decode can be
reproduced by hand.

Switch it off again afterwards. With the key in the page, anybody can decrypt
the address without solving the puzzle - the proof of work is off in all but
name for as long as debug is on.

### Placement

- **A token in the page text.** Write `{{contact-email}}` anywhere in a page or
  post. Bludit has no server-side content filter hook, so the substitution
  happens in the browser - which is better here, because only the token itself
  is ever in the HTML source.
- **A sidebar widget**, on every page, for themes that render the `siteSidebar`
  hook.

### Appearance

Either a text link or a button that takes the theme's own `btn btn-primary`
classes, so it matches the other buttons on the site. The plugin's own fallback
styling is written with `:where()`, which has zero specificity - any theme rule
at all overrides it, and no `!important` is needed on either side. The revealed
`mailto:` link keeps whatever classes the button had.

The trigger is a real `<button>`, so it is keyboard reachable and Enter and Space
work; the revealed address is announced through `aria-live`, and the progress bar
is `aria-hidden` so a screen reader is not read a percentage twelve times a
second. Without JavaScript the button is replaced by a short explanatory note
rather than a dead control.

---

## Limitations

- **The obfuscation is obfuscation, not secrecy.** Everything needed to decode
  the address is in the page, by necessity - a browser has to be able to do it.
  A harvester that runs a real browser, executes the JavaScript and synthesises a
  click gets the address. The point is that this costs orders of magnitude more
  than `grep -o '[^ ]*@[^ ]*'` over a fetched page, and most harvesting is the
  latter.
- **Proof of work raises that cost, it does not close the door.** A determined
  scraper that wants *your* address specifically will pay a few seconds of CPU
  for it. What becomes impractical is scraping the whole web this way.
- **The difficulty is a trade against your visitors.** At roughly 650,000
  hashes/second on a desktop, 22 bits averages about 3 seconds and can take 6; a
  phone is around four times slower. The default of 22 is near the top of what a
  general audience tolerates; lower it if your visitors are mostly mobile. The
  range goes to 26, but 25 and 26 are for a page whose visitors are motivated -
  an abuse contact, a disclosure address - not for a contact page. At 26 bits a
  desktop averages about 50 seconds and a phone several minutes.
- **Old browsers get nothing.** The reveal needs `Promise` and a working
  `MessageChannel` or `setTimeout`; the encryption needs a JS SHA-256, which is
  bundled and only loaded when proof of work is on.
- **The address is stored in plain text on the server**, in the plugin's own
  database file, like every other Bludit plugin setting.
- **The token substitution runs on the rendered page**, so a token inside a
  `<code>` block or an attribute value is also replaced. Do not write
  `{{contact-email}}` in a page that is documenting it.
- **The sidebar widget needs a theme that renders `siteSidebar`.** Not all do.
  Nothing breaks if yours does not; the widget simply never appears.

---

## Changelog

### 0.2.3

- **Changed** the defaults now describe how the plugin is meant to be used:
  proof of work is **on**, and the appearance is the **theme-styled button**. An
  existing install keeps whatever it has stored; this only affects a fresh one.
- **Changed** the difficulty range is **8 to 26 bits**, up from 8 to 24. 25 and
  26 are deliberately past what suits a contact page - a desktop averages 26 and
  52 seconds there - and exist for an address whose visitors are motivated. The
  default is still 22.
- **Changed** the timing guidance is measured at ~650,000 hashes/second rather
  than ~840,000. The old figure came from headless Chromium on an idle machine;
  a real browser on a real page is about 25% slower, which made every published
  estimate optimistic. 22 bits is ~3 s average, not ~2.5 s.
- **Changed** *Require proof of work* is labeled *(recommended)*, and the
  button reads *Calculating the address...* while it works - it is computing,
  not waiting.

### 0.2.2

- **Added** a version handshake. The server stamps the rendering version onto
  every button and into the config; the script compares it against its own and
  refuses to decode a mismatch, with an explanation in the console. A stale
  cached script now announces itself instead of returning mojibake.
- **Added** a *Debug* setting: server-side cipher self-test, environment
  (`mbstring.func_overload`, PHP and Bludit versions), a checksum of the address
  so the client can verify the decrypt was *correct*, the per-render key, and a
  step-by-step console trace of the reveal. Off by default, and documented as
  voiding the proof of work while it is on.

### 0.2.1

- **Fixed** the reveal failed on browsers that had already loaded an earlier
  version, showing either *"the address could not be shown"* or a line of
  mojibake. Bludit's `includeJS()` cache-busts with the *Bludit* version, so
  upgrading this plugin did not change the script URL and the old script kept
  running against the new markup. The plugin now appends its own version to its
  asset URLs. **Force-reload the page once** after upgrading from 0.2.0
  (Ctrl+Shift+R) - the fix is in the HTML, but the stale script is still cached
  under its old URL until then.
- **Changed** target Bludit 3.21; the settings form drops the Bootstrap 5
  `form-select` class, which does nothing in 3.21's Bootstrap 4 admin.
- **Removed** the `de_AT.json` and `de_CH.json` language files.

### 0.2.0

- **Added** optional proof of work. The address is encrypted with a key the
  browser has to find by brute force, so the delay cannot be skipped by calling
  the reveal function directly - without the computation there is no key.
  Difficulty configurable from 8 to 24 bits, clamped server-side. Every render
  mints a fresh salt, secret and ciphertext, so nothing is reusable between page
  loads.
- **Added** a progress bar and a real percentage during the computation, and a
  bundled SHA-256 (`js/sha256.js`, loaded only when proof of work is on) checked
  against `node:crypto` for every message length the block padding could get
  wrong.
- **Added** an *Appearance* setting: text link, or a button carrying the theme's
  own `btn btn-primary`. The plugin's fallback styling moved to `:where()`, so it
  has zero specificity and cannot fight a theme.
- **Added** German translations (`de_DE.json`).

### 0.1.0

- Initial release: `{{contact-email}}` token, sidebar widget, click-to-reveal
  with the address rot13'd, base64'd, split across randomly named attributes and
  accompanied by a decoy.
