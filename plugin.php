<?php defined('BLUDIT') or die('Bludit CMS.');

/**
 * Contact Email -- publish an address without publishing it.
 *
 * Two things stand between the address and a harvester:
 *
 *   1. It is not in the served HTML. What ships is base64(rot13(address)), cut
 *      into pieces spread across randomly-named data- attributes, plus one decoy
 *      piece that is not part of the address at all. No '@' and no readable
 *      domain appear anywhere in the markup, so a harvester that greps the page
 *      -- which is most of them -- finds nothing.
 *   2. Nothing is assembled until a real click. There is no href before the
 *      click, so a harvester that runs the page's JavaScript still has to
 *      synthesize a user gesture on the right element to get anything.
 *
 * Be clear about what layers 1 and 2 are: obfuscation, not encryption. Anyone
 * who reads this file knows how to reverse the encoding, and it is meant to be
 * reversible -- the browser has to do it. The click gate is the actual defence;
 * the encoding is what makes the cheap, high-volume attack miss.
 *
 * Which is why there is an optional third layer, `proofOfWork`:
 *
 *   3. The address is encrypted, and the key is not sent. What ships is a
 *      challenge whose only known solution costs about 2^(bits-1) SHA-256 hashes
 *      to find, and the solution *is* the decryption key. Not a timer, not a
 *      delay a script can skip: without the search there is no key, and without
 *      the key the ciphertext is just bytes. One visitor pays a few seconds
 *      once; a harvester pays the same for every address on every fetch, which
 *      is what makes bulk collection uneconomic.
 */
class pluginContactEmail extends Plugin
{
	/**
	 * What an author writes in page content.
	 *
	 * Fixed rather than configurable: the token is matched against every text
	 * node of the rendered page, and a token the user could set to something
	 * short would start matching prose.
	 */
	const TOKEN = '{{contact-email}}';

	/**
	 * Kept in step with metadata.json, and appended to every asset URL.
	 *
	 * Bludit's own includeJS()/includeCSS() append `?version=BLUDIT_VERSION`
	 * (bl-kernel/abstract/plugin.class.php:83) -- which changes when *Bludit*
	 * is upgraded and never when this plugin is. Upgrading the plugin therefore
	 * left browsers running the previously cached script against freshly
	 * rendered markup: 0.1.0's decoder against 0.2.0's ciphertext produced
	 * either "the address could not be shown" or a line of mojibake, depending
	 * on whether the garbage happened to contain an "@". Hence our own version.
	 */
	const VERSION = '0.2.3';

	/**
	 * The decoy. RFC 6761 reserves `.invalid` and guarantees it never resolves,
	 * so a harvester that does decode the decoy reaches nobody. Deliberately not
	 * configurable -- a decoy pointed at a real address is a way to spam someone
	 * else by accident.
	 */
	const HONEYPOT = 'postmaster@example.invalid';

	/**
	 * Difficulty bounds for the proof of work, in bits.
	 *
	 * A search over 2^bits candidates costs 2^(bits-1) hashes on average and
	 * 2^bits at worst. Measured on a desktop at ~650,000 hashes per second in
	 * a real browser on a real page -- headless Chromium on an idle machine
	 * reports nearer 840,000, which flatters every number that follows -- so 22
	 * bits is ~3 s expected / ~6 s worst, and roughly four times that on a phone.
	 *
	 * The floor is low enough to be effectively free, for someone who wants the
	 * mechanism without the wait. The ceiling is deliberately past what suits a
	 * public page: at 26 bits a desktop averages ~50 s and a phone several
	 * minutes. It exists for a page whose visitors are motivated (an abuse
	 * contact, a disclosure address), not as a setting to reach for by default.
	 * Anything above 24 is a decision about who is prepared to wait, which is
	 * why the tip and the README say so in those terms.
	 */
	const POW_MIN_BITS = 8;
	const POW_MAX_BITS = 26;
	const POW_DEFAULT_BITS = 22;

	public function init()
	{
		// Booleans are stored as bool and posted as the strings "true"/"false";
		// Plugin::post() converts them. A bare checkbox posts nothing when
		// unchecked, so the setting could never be turned off again.
		$this->dbFields = array(
			'email'               => '',
			'linkText'            => '',
			'subject'             => '',
			'cssClass'            => '',
			'displayStyle'        => 'button',
			'proofOfWork'         => true,
			'powBits'             => self::POW_DEFAULT_BITS,
			'enableSidebarWidget' => false,
			'sidebarTitle'        => '',
			'debug'               => false
		);
	}

	/**
	 * Plugin::__construct assigns `$this->db = $Tmp->db`, replacing the defaults
	 * rather than merging into them -- so a plugin installed before a field
	 * existed never sees that field. Merging here is what makes a new setting
	 * appear with its default instead of as NULL (D-033).
	 */
	public function prepare()
	{
		$this->db = array_merge($this->dbFields, $this->db);
	}

	// ------------------------------------------------------------------- admin

	public function form()
	{
		global $L;

		$html  = '<div class="alert alert-primary" role="alert">' . $this->description() . '</div>';

		$html .= $this->formText('email', $L->get('contact-email-address'), $L->get('contact-email-address-tip'), 'you@example.com');
		$html .= $this->formText('linkText', $L->get('contact-email-link-text'), $L->get('contact-email-link-text-tip'), $L->get('contact-email-default-link-text'));
		$html .= $this->formText('subject', $L->get('contact-email-subject'), $L->get('contact-email-subject-tip'), '');
		$html .= $this->formText('cssClass', $L->get('contact-email-css-class'), $L->get('contact-email-css-class-tip'), '');

		$html .= $this->formSelect('displayStyle', $L->get('contact-email-display'), array(
			'link'   => $L->get('contact-email-display-link'),
			'button' => $L->get('contact-email-display-button')
		), $L->get('contact-email-display-tip'));

		$html .= $this->formBool('proofOfWork', $L->get('contact-email-pow'), $L->get('contact-email-pow-tip'));
		$html .= $this->formNumber('powBits', $L->get('contact-email-pow-bits'), $L->get('contact-email-pow-bits-tip'), self::POW_MIN_BITS, self::POW_MAX_BITS);

		$html .= '<div class="alert alert-secondary" role="alert">'
			. $L->get('contact-email-token-help') . ' <code>' . self::TOKEN . '</code>'
			. '</div>';

		$html .= $this->formBool('enableSidebarWidget', $L->get('contact-email-sidebar'), $L->get('contact-email-sidebar-tip'));
		$html .= $this->formText('sidebarTitle', $L->get('contact-email-sidebar-title'), $L->get('contact-email-sidebar-title-tip'), $L->get('contact-email-default-sidebar-title'));

		$html .= '<div class="alert alert-secondary" role="alert">'
			. $L->get('contact-email-debug-warning') . '</div>';
		$html .= $this->formBool('debug', $L->get('contact-email-debug'), $L->get('contact-email-debug-tip'));

		return $html;
	}

	// Rendered to match Bludit's .plugin-form conventions: a block <label>, the
	// control, then a <span class="tip">.
	private function formText($field, $label, $tip = '', $placeholder = '')
	{
		$html  = '<div>';
		$html .= '<label for="' . $field . '">' . $label . '</label>';
		$html .= '<input id="' . $field . '" name="' . $field . '" type="text" class="form-control"'
			. ' placeholder="' . Sanitize::html($placeholder) . '"'
			. ' value="' . $this->getValue($field) . '">';
		if ($tip !== '') {
			$html .= '<span class="tip">' . $tip . '</span>';
		}
		$html .= '</div>';
		return $html;
	}

	private function formNumber($field, $label, $tip, $min, $max)
	{
		$html  = '<div>';
		$html .= '<label for="' . $field . '">' . $label . '</label>';
		$html .= '<input id="' . $field . '" name="' . $field . '" type="number" class="form-control"'
			. ' min="' . (int) $min . '" max="' . (int) $max . '" step="1"'
			. ' value="' . (int) $this->getValue($field) . '">';
		if ($tip !== '') {
			$html .= '<span class="tip">' . $tip . '</span>';
		}
		$html .= '</div>';
		return $html;
	}

	/** @param array<string,string> $options value => label, in display order. */
	private function formSelect($field, $label, array $options, $tip = '')
	{
		$current = (string) $this->getValue($field, false);
		$html  = '<div>';
		$html .= '<label for="' . $field . '">' . $label . '</label>';
		$html .= '<select id="' . $field . '" name="' . $field . '">';
		foreach ($options as $value => $text) {
			$html .= '<option value="' . Sanitize::html($value) . '"'
				. ($current === (string) $value ? ' selected' : '') . '>' . $text . '</option>';
		}
		$html .= '</select>';
		if ($tip !== '') {
			$html .= '<span class="tip">' . $tip . '</span>';
		}
		$html .= '</div>';
		return $html;
	}

	private function formBool($field, $label, $tip = '')
	{
		global $L;
		$value = $this->getValue($field) === true ? 'true' : 'false';
		$html  = '<div>';
		$html .= '<label for="' . $field . '">' . $label . '</label>';
		$html .= '<select id="' . $field . '" name="' . $field . '">';
		$html .= '<option value="true"' . ($value === 'true' ? ' selected' : '') . '>' . $L->get('Enabled') . '</option>';
		$html .= '<option value="false"' . ($value === 'false' ? ' selected' : '') . '>' . $L->get('Disabled') . '</option>';
		$html .= '</select>';
		if ($tip !== '') {
			$html .= '<span class="tip">' . $tip . '</span>';
		}
		$html .= '</div>';
		return $html;
	}

	// -------------------------------------------------------------------- site

	/**
	 * includeCSS()/includeJS(), but cache-busted by *this plugin's* version.
	 * See the VERSION constant for why the core helpers are not enough.
	 */
	private function css($filename)
	{
		return '<link rel="stylesheet" type="text/css" href="' . $this->domainPath()
			. 'css/' . $filename . '?v=' . self::VERSION . '">' . PHP_EOL;
	}

	private function js($filename)
	{
		return '<script charset="utf-8" src="' . $this->domainPath()
			. 'js/' . $filename . '?v=' . self::VERSION . '"></script>' . PHP_EOL;
	}

	public function siteHead()
	{
		if (!$this->configured()) {
			return '';
		}
		return $this->css('contact-email.css');
	}

	/**
	 * The template every token occurrence is cloned from, plus the behaviour.
	 *
	 * A <template> rather than an HTML string in a JSON config: the markup
	 * carries per-render random attribute names, and round-tripping it through
	 * JSON and innerHTML would be two escaping problems for no gain.
	 */
	public function siteBodyEnd()
	{
		if (!$this->configured()) {
			return '';
		}

		$html  = '<template id="jscontactEmailTemplate">' . $this->widget() . '</template>' . PHP_EOL;
		$html .= '<script>window.CONTACT_EMAIL_CONFIG = ' . $this->configJson() . ';</script>' . PHP_EOL;
		// Only when it is needed: a site with the proof of work off should not
		// pay for a hash implementation it never calls.
		if ($this->powEnabled()) {
			$html .= $this->js('sha256.js');
		}
		$html .= $this->js('contact-email.js');
		return $html;
	}

	public function siteSidebar()
	{
		global $L;

		if (!$this->configured() || $this->getValue('enableSidebarWidget') !== true) {
			return '';
		}

		$title = $this->getValue('sidebarTitle');
		if (trim(Sanitize::htmlDecode($title)) === '') {
			$title = $L->get('contact-email-default-sidebar-title');
		}

		return '<div class="plugin plugin-contact-email">'
			. '<h2 class="plugin-label">' . $title . '</h2>'
			. '<div class="plugin-content">' . $this->widget() . '</div>'
			. '</div>';
	}

	// ----------------------------------------------------------------- helpers

	/** An address with an @ in it is the only thing this plugin needs to work. */
	private function configured()
	{
		return strpos($this->address(), '@') !== false;
	}

	// getValue(..., false) so an address stored with HTML entities (Sanitize::html
	// runs on every posted field) is encoded as the user typed it.
	private function address()
	{
		return trim((string) $this->getValue('email', false));
	}

	// Not label(): Plugin declares a public label() and PHP refuses to narrow it.
	private function buttonLabel()
	{
		global $L;
		$text = trim((string) $this->getValue('linkText', false));
		return $text === '' ? $L->get('contact-email-default-link-text') : $text;
	}

	private function configJson()
	{
		global $L;

		$config = array(
			'token'    => self::TOKEN,
			'subject'  => trim((string) $this->getValue('subject', false)),
			'failed'   => $L->get('contact-email-failed'),
			'working'  => $L->get('contact-email-working'),
			'progress' => $L->get('contact-email-progress'),
			// The script compares this against its own constant and complains
			// loudly if they differ. See VERSION: a stale cached script running
			// against fresh markup is the failure this plugin has actually hit
			// in production, and it is silent by nature -- the mismatch produces
			// mojibake, not an error.
			'version'  => self::VERSION
		);

		if ($this->debugEnabled()) {
			$config['debug'] = $this->diagnostics();
		}

		return json_encode($config, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	}

	private function debugEnabled()
	{
		return $this->getValue('debug') === true;
	}

	/**
	 * What the server knows about its own environment and its own output.
	 *
	 * Emitted only with `debug` on, and deliberately verbose: the point is that
	 * one console dump from the failing browser is enough to say which side
	 * diverged, rather than another round of guessing. Everything here is about
	 * *this* render, so a stale copy of it is self-evidently stale.
	 */
	private function diagnostics()
	{
		$address = $this->address();
		$rot = str_rot13($address);
		$puzzle = $this->challenge();
		$cipher = $this->xorCipher($rot, $puzzle['key']);

		return array(
			'pluginVersion'  => self::VERSION,
			'bluditVersion'  => defined('BLUDIT_VERSION') ? BLUDIT_VERSION : 'unknown',
			'phpVersion'     => PHP_VERSION,
			// PHP 8 removed mbstring.func_overload, but on an older host it
			// silently redefines strlen/str_split/substr to be character-based,
			// which would corrupt every binary operation in xorCipher() and
			// encode() while leaving pure-ASCII test data working.
			'mbFuncOverload' => (int) ini_get('mbstring.func_overload'),
			'powEnabled'     => $this->powEnabled(),
			'powBits'        => $this->powBits(),
			// Lengths, not contents: enough to spot truncation in transit.
			'addressLength'  => strlen($address),
			'rot13Length'    => strlen($rot),
			'cipherLength'   => strlen($cipher),
			'base64Length'   => strlen(base64_encode($cipher)),
			// A round trip through the server's own cipher, on this host, with
			// this PHP. If this is false the fault is server-side and no amount
			// of looking at the browser will find it.
			'selfTest'       => $this->selfTest()
		);
	}

	/**
	 * Encrypt and decrypt a known string with the real routine.
	 *
	 * xorCipher() is its own inverse, so this is one call each way. It catches
	 * the class of failure that only appears on someone else's host -- a byte
	 * function that is not byte-based, a locale that changes chr()/ord(), a
	 * mangled sha256 -- without needing the real address.
	 */
	private function selfTest()
	{
		$sample = 'selftest@example.invalid';
		$key = hash('sha256', 'contact-email-self-test');
		$round = $this->xorCipher($this->xorCipher($sample, $key), $key);
		$b64 = base64_encode($this->xorCipher($sample, $key));

		return array(
			'cipherRoundTrip' => $round === $sample,
			'base64RoundTrip' => base64_decode($b64) === $this->xorCipher($sample, $key),
			'rot13RoundTrip'  => str_rot13(str_rot13($sample)) === $sample,
			// The keystream's first block, so the browser can compare its own
			// SHA-256 against the server's on identical input.
			'keystreamProbe'  => bin2hex(substr(hash('sha256', $key . '0', true), 0, 8)),
			'keystreamInput'  => $key . '0'
		);
	}

	private function powEnabled()
	{
		return $this->getValue('proofOfWork') === true;
	}

	/**
	 * The difficulty, clamped on the way out rather than on the way in.
	 *
	 * post() only sees what the form sends; a value edited straight into
	 * db.php, or carried over from a version with different bounds, would
	 * otherwise reach the browser as-is -- and 40 bits is not a slow reveal,
	 * it is a page that never reveals anything.
	 */
	private function powBits()
	{
		$bits = (int) $this->getValue('powBits');
		if ($bits < self::POW_MIN_BITS) {
			return self::POW_MIN_BITS;
		}
		return $bits > self::POW_MAX_BITS ? self::POW_MAX_BITS : $bits;
	}

	/**
	 * A fresh puzzle, and the key that solving it yields.
	 *
	 * The browser is given `salt`, `challenge` and `bits`, and searches n in
	 * [0, 2^bits) for sha256(salt . n) == challenge. Because the secret is drawn
	 * uniformly from that range the search is bounded, not merely probabilistic:
	 * the answer is always found by 2^bits, which is what lets the progress bar
	 * show a real percentage instead of a spinner.
	 *
	 * The key is sha256(n . salt) -- the same two strings, concatenated the other
	 * way round. That matters: were the key the challenge's own preimage, it
	 * would be sitting in the page next to the ciphertext.
	 */
	private function challenge()
	{
		$bits = $this->powBits();
		$salt = bin2hex(random_bytes(8));
		$secret = random_int(0, (1 << $bits) - 1);

		return array(
			'bits'      => $bits,
			'salt'      => $salt,
			'challenge' => hash('sha256', $salt . $secret),
			'key'       => hash('sha256', $secret . $salt)
		);
	}

	/**
	 * XOR `$value` with a keystream derived from `$keyHex`.
	 *
	 * Block i of the keystream is the raw sha256 of `$keyHex . i`. The browser
	 * reproduces it from the hex digest of the same input, so both sides need
	 * nothing but SHA-256 over ASCII -- no WebCrypto, no byte-order questions,
	 * and no key material anywhere in the served page.
	 */
	private function xorCipher($value, $keyHex)
	{
		$length = strlen($value);
		$stream = '';
		for ($i = 0; strlen($stream) < $length; $i++) {
			$stream .= hash('sha256', $keyHex . $i, true);
		}

		$out = '';
		for ($i = 0; $i < $length; $i++) {
			$out .= chr(ord($value[$i]) ^ ord($stream[$i]));
		}
		return $out;
	}

	/**
	 * The classes the revealed <a> should carry.
	 *
	 * Decided here rather than in JavaScript so the two display styles are
	 * described in exactly one place. In button mode the address stays a button:
	 * a control that turns into a differently-shaped control on click is a worse
	 * answer than one that keeps its shape.
	 */
	private function revealClass($buttonClass)
	{
		if ($this->getValue('displayStyle', false) !== 'button') {
			return 'contact-email-link';
		}
		return 'contact-email-link ' . $buttonClass;
	}

	/**
	 * The button's own classes.
	 *
	 * `btn btn-primary` is there for the themes that ship Bootstrap, which is
	 * most Bludit themes -- it makes the button look like every other button on
	 * the site for free. The plugin's fallback styling for the same element is
	 * written with :where(), so it has zero specificity and any theme rule beats
	 * it without needing !important.
	 */
	private function buttonClass()
	{
		$class = 'contact-email-button';
		$class .= $this->getValue('displayStyle', false) === 'button'
			? ' contact-email-button--themed btn btn-primary'
			: ' contact-email-button--link';

		$extra = trim((string) $this->getValue('cssClass', false));
		if ($extra !== '') {
			$class .= ' ' . Sanitize::html($extra);
		}
		return $class;
	}

	/**
	 * One reveal button, with the address cut up across its attributes.
	 *
	 * The <span> around it carries aria-live: replacing the button with a link
	 * is a content change, and a screen reader that does not follow the focus
	 * move still announces the address.
	 */
	private function widget()
	{
		global $L;

		// One name pool for the whole widget, so the decoy can never collide with
		// a real piece and silently break the address.
		$taken = array();

		// With the proof of work on, what gets split up is ciphertext and the key
		// is nowhere on the page; with it off, it is the reversible encoding the
		// plugin has always used.
		$puzzle = $this->powEnabled() ? $this->challenge() : null;
		$payload = str_rot13($this->address());
		if ($puzzle !== null) {
			$payload = $this->xorCipher($payload, $puzzle['key']);
		}
		$parts = $this->encode(base64_encode($payload), $taken);

		// The decoy's name is simply absent from the order list, so it is
		// indistinguishable from a real piece without following that list. It
		// stays cheaply decodable on purpose even when the real address is not:
		// a harvester that skips the work and grabs what it can gets this.
		$attributes = $parts['chunks'];
		$attributes[$this->attributeName($taken)] = base64_encode(str_rot13(self::HONEYPOT));

		// Shuffled so document order carries no information about assembly order.
		$names = array_keys($attributes);
		shuffle($names);

		$class = $this->buttonClass();

		$html = '<span class="contact-email" aria-live="polite">';
		$html .= '<button type="button" class="' . $class . '"';
		$html .= ' data-contact-email="' . implode(' ', $parts['names']) . '"';
		$html .= ' data-ce-reveal-class="' . Sanitize::html($this->revealClass($class)) . '"';
		// Always present, and always cheap. The script refuses to run against a
		// version it does not recognise rather than producing mojibake, which is
		// what a stale cached script did before this existed.
		$html .= ' data-ce-v="' . self::VERSION . '"';
		if ($puzzle !== null) {
			$html .= ' data-ce-salt="' . $puzzle['salt'] . '"';
			$html .= ' data-ce-challenge="' . $puzzle['challenge'] . '"';
			$html .= ' data-ce-bits="' . $puzzle['bits'] . '"';
		}
		if ($this->debugEnabled()) {
			// Enough for the browser to say *which* step went wrong rather than
			// only that the result looks wrong:
			//   verify  -- did the decrypt produce the real plaintext?
			//   b64len  -- did all the pieces survive being put back together?
			//   key     -- if verify fails, was the key wrong or the ciphertext?
			// The key is the whole secret of this render, so debug mode voids
			// the proof of work. That is stated in the settings and the README,
			// and it is why the setting exists rather than a query parameter
			// anyone passing by could add.
			$html .= ' data-ce-verify="' . substr(hash('sha256', $this->address()), 0, 16) . '"';
			$html .= ' data-ce-b64len="' . strlen(base64_encode($payload)) . '"';
			if ($puzzle !== null) {
				$html .= ' data-ce-key="' . $puzzle['key'] . '"';
			}
		}
		foreach ($names as $name) {
			$html .= ' data-' . $name . '="' . $attributes[$name] . '"';
		}
		$html .= '>' . Sanitize::html($this->buttonLabel()) . '</button>';
		// Without JavaScript there is nothing to reveal, and saying so is better
		// than a button that silently does nothing.
		$html .= '<noscript><span class="contact-email-noscript">' . $L->get('contact-email-noscript') . '</span></noscript>';
		$html .= '</span>';

		return $html;
	}

	/**
	 * Cut a base64 payload into three pieces under random attribute names.
	 *
	 * The caller rot13s before base64, and that ordering is the part that
	 * matters: base64 alone is a shape harvesters know to try, and a decoded
	 * `something@domain.tld` would be picked straight back up. rot13'd first, a
	 * successful base64 decode yields `fbzrguvat@qbznva.gyq` -- which no address
	 * regex matches. With the proof of work on the payload is ciphertext and the
	 * question does not arise.
	 *
	 * @return array{names: string[], chunks: array<string,string>} names in
	 *         assembly order; chunks keyed by attribute name.
	 */
	private function encode($payload, array &$taken)
	{
		$count = 3;
		$size = (int) ceil(strlen($payload) / $count);
		$pieces = str_split($payload, max(1, $size));

		$names = array();
		$chunks = array();
		foreach ($pieces as $piece) {
			$name = $this->attributeName($taken);
			$names[] = $name;
			$chunks[$name] = $piece;
		}

		return array('names' => $names, 'chunks' => $chunks);
	}

	/**
	 * A fresh, unused data- attribute name.
	 *
	 * Randomised per render so the same page fetched twice never looks the same,
	 * which defeats a harvester that has been taught this plugin's fixed
	 * attribute names. The leading letter keeps the name a valid HTML attribute
	 * whatever the random bytes are.
	 */
	private function attributeName(array &$taken)
	{
		do {
			$name = 'x' . bin2hex(random_bytes(3));
		} while (in_array($name, $taken, true));
		$taken[] = $name;
		return $name;
	}
}
