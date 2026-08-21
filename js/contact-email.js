/**
 * contact-email -- reassemble the address, but only on a real click.
 *
 * Two jobs:
 *   1. Replace every {{contact-email}} token in the page text with a copy of the
 *      button the server rendered into <template id="jscontactEmailTemplate">.
 *      Bludit has no server-side content filter hook, so this has to happen
 *      client-side -- which is the better outcome anyway: only the token is ever
 *      served, so the address is not in the HTML even in the token case.
 *   2. On click, read the pieces the server scattered across the button's
 *      data- attributes, put them back in the order data-contact-email lists,
 *      base64-decode, un-rot13, and swap the button for a real mailto: link.
 *
 * When the proof of work is switched on there is a step between the two: the
 * pieces are ciphertext, and the key has to be found before they mean anything.
 * See solve() for why that is a search and not a timer.
 *
 * No jQuery: this runs on the public site, where the theme decides what is
 * loaded and nothing can be assumed to be present.
 */
(function (window, document) {
	'use strict';

	var config = window.CONTACT_EMAIL_CONFIG || {};
	var TOKEN = config.token || '{{contact-email}}';

	/**
	 * Kept in step with plugin.php's VERSION constant and metadata.json.
	 *
	 * The server stamps its own version into the config and onto every button.
	 * A mismatch means this file came from the browser cache while the markup
	 * came from an upgraded server -- the exact failure this plugin hit in
	 * production, and one that is otherwise silent: an old decoder against new
	 * ciphertext yields mojibake, not an error. Saying so in the console is the
	 * difference between a five minute fix and a week of guessing.
	 */
	var VERSION = '0.2.3';

	var DEBUG = !!config.debug;

	function log() {
		if (!DEBUG || !window.console || !window.console.log) {
			return;
		}
		var args = Array.prototype.slice.call(arguments);
		args.unshift('[contact-email]');
		window.console.log.apply(window.console, args);
	}

	function warn(message) {
		if (window.console && window.console.error) {
			window.console.error('[contact-email] ' + message);
		}
	}

	/**
	 * Complain once if the script and the markup came from different versions.
	 *
	 * Unconditional, not debug-gated: this is the one diagnostic that pays for
	 * itself on a site nobody is currently debugging.
	 */
	function checkVersion(button) {
		var served = button
			? button.getAttribute('data-ce-v')
			: (config.version || null);
		if (!served || served === VERSION) {
			return true;
		}
		warn('version mismatch: this script is ' + VERSION + ', the page was'
			+ ' rendered by ' + served + '. The script is being served from a'
			+ ' stale browser cache -- reload with Ctrl+Shift+R. The address'
			+ ' cannot be decoded until then.');
		return false;
	}

	// Never descended into when looking for the token: script and style contents
	// are not prose, and the token in a textarea is the user's own text.
	var SKIP = ['SCRIPT', 'STYLE', 'TEXTAREA', 'TEMPLATE', 'NOSCRIPT'];

	function rot13(value) {
		return value.replace(/[a-zA-Z]/g, function (c) {
			var base = c <= 'Z' ? 65 : 97;
			return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
		});
	}

	/**
	 * The address held by one button, or '' if it cannot be reassembled.
	 *
	 * Everything is read at click time. Nothing is cached, and nothing is written
	 * back onto the element, so a harvester that scrapes the DOM after the page
	 * has settled still finds only the pieces.
	 *
	 * `keyHex` is the proof-of-work key, and is what makes that guarantee hold
	 * even against a harvester that calls this function directly: with the proof
	 * of work on, the pieces are ciphertext and no argument-free call to decode()
	 * can produce the address.
	 */
	function decode(button, keyHex) {
		var order = (button.getAttribute('data-contact-email') || '').split(/\s+/);
		var payload = '';

		// A decoder that does not match the markup produces mojibake rather than
		// an error, so refusing is strictly better than trying: the visitor gets
		// the plugin's own "could not be shown" message and the console says why.
		if (!checkVersion(button)) {
			return '';
		}

		if (!keyHex && button.getAttribute('data-ce-challenge')) {
			// Encrypted, and no key offered. Refuse here rather than falling
			// through to the @ check below, which ciphertext passes roughly one
			// time in eleven -- a byte of random plaintext is 0x40 as readily as
			// anything else -- and would then hand back garbage.
			return '';
		}

		for (var i = 0; i < order.length; i++) {
			if (!order[i]) {
				continue;
			}
			var piece = button.getAttribute('data-' + order[i]);
			if (piece === null) {
				// A missing piece means a truncated or rewritten page; better to
				// show the failure than to build a wrong address.
				return '';
			}
			payload += piece;
		}

		if (!payload) {
			return '';
		}

		if (DEBUG) {
			var expected = button.getAttribute('data-ce-b64len');
			log('pieces', order, 'reassembled base64 length', payload.length,
				'server said', expected);
			if (expected !== null && payload.length !== parseInt(expected, 10)) {
				warn('the base64 payload is ' + payload.length + ' characters but'
					+ ' the server wrote ' + expected + '. The data- attributes'
					+ ' were altered between the server and here -- an HTML'
					+ ' minifier, a proxy or a "security" filter is the usual'
					+ ' cause. Nothing downstream of this can succeed.');
			}
			var servedKey = button.getAttribute('data-ce-key');
			if (servedKey && keyHex && servedKey !== keyHex) {
				warn('the key found by the browser does not match the one the'
					+ ' server used. Browser: ' + keyHex + ' server: ' + servedKey
					+ '. The proof of work solved to a different secret, so the'
					+ ' salt or the challenge changed between render and click.');
			} else if (servedKey && keyHex) {
				log('key matches the server exactly');
			}
		}

		try {
			var raw = window.atob(payload);
			if (keyHex) {
				raw = xor(raw, keystream(keyHex, raw.length));
			}
			var address = rot13(raw);

			if (DEBUG) {
				log('decrypted', raw.length, 'bytes, first 8 as hex', hex(raw, 8));
				verify(button, address);
			}

			// The one sanity check worth making: anything without an @ is not an
			// address, and turning it into a mailto: would be worse than failing.
			return address.indexOf('@') === -1 ? '' : address;
		} catch (e) {
			warn('decode failed: ' + (e && e.message ? e.message : e));
			return '';
		}
	}

	/** First `count` bytes of a binary string, as hex. Debug output only. */
	function hex(raw, count) {
		var out = '';
		for (var i = 0; i < Math.min(count, raw.length); i++) {
			out += ('0' + (raw.charCodeAt(i) & 0xff).toString(16)).slice(-2);
		}
		return out;
	}

	/**
	 * Say plainly whether the decrypt produced the real address.
	 *
	 * The server publishes the first 16 hex of sha256(address) with debug on.
	 * That turns "the result looks like garbage" into a fact, and separates the
	 * two failures that look identical from the outside: a wrong key, and a
	 * right key applied to ciphertext that was modified in transit.
	 */
	function verify(button, address) {
		var expected = button.getAttribute('data-ce-verify');
		if (!expected || !window.ContactEmailSha256) {
			return;
		}
		var actual = sha256(address).slice(0, 16);
		if (actual === expected) {
			log('VERIFIED: the decrypted address is exactly what the server holds');
			return;
		}
		warn('the decrypted text is NOT the address. Expected sha256 prefix '
			+ expected + ', got ' + actual + '. Combined with the key check'
			+ ' above: matching key means the ciphertext was altered in transit;'
			+ ' differing key means the puzzle was solved to the wrong secret.');
	}

	// ------------------------------------------------------------ proof of work

	function sha256(text) {
		return window.ContactEmailSha256.hex(text);
	}

	/** The puzzle the server attached to this button, or null if there is none. */
	function puzzle(button) {
		var salt = button.getAttribute('data-ce-salt');
		var challenge = button.getAttribute('data-ce-challenge');
		var bits = parseInt(button.getAttribute('data-ce-bits'), 10);

		if (!salt || !challenge || !(bits > 0) || !window.ContactEmailSha256) {
			return null;
		}
		return { salt: salt, challenge: challenge, bits: bits };
	}

	/** Keystream bytes, matching the server's xorCipher() block for block. */
	function keystream(keyHex, length) {
		var bytes = [];
		for (var i = 0; bytes.length < length; i++) {
			var hex = sha256(keyHex + i);
			for (var j = 0; j < hex.length; j += 2) {
				bytes.push(parseInt(hex.substr(j, 2), 16));
			}
		}
		return bytes;
	}

	function xor(raw, bytes) {
		var out = '';
		for (var i = 0; i < raw.length; i++) {
			out += String.fromCharCode(raw.charCodeAt(i) ^ bytes[i]);
		}
		return out;
	}

	var now = (window.performance && window.performance.now)
		? function () { return window.performance.now(); }
		: function () { return Date.now(); };

	/**
	 * Hand control back to the browser before the next slice of work.
	 *
	 * MessageChannel rather than setTimeout(0): nested timeouts are clamped to
	 * 4 ms after the fifth one, which at ~16 ms of work per slice would throw
	 * away a fifth of the time budget doing nothing.
	 */
	function later(fn) {
		if (typeof window.MessageChannel === 'function') {
			var channel = new window.MessageChannel();
			channel.port1.onmessage = function () {
				channel.port1.onmessage = null;
				fn();
			};
			channel.port2.postMessage(0);
			return;
		}
		window.setTimeout(fn, 0);
	}

	/**
	 * Find n in [0, 2^bits) with sha256(salt + n) == challenge.
	 *
	 * This is the whole mechanism, and it is worth being precise about why it is
	 * a search rather than a five second timer. A timer is advisory: a script
	 * skips it and calls decode(). This is not, because the answer *is* the
	 * decryption key -- there is no address to reveal early, only ciphertext and
	 * a key nobody has yet. The cost is real for everyone, which is exactly the
	 * point: a visitor pays it once, a harvester pays it per address per fetch.
	 *
	 * The server draws its secret uniformly from the same range, so the search
	 * always terminates by 2^bits: the progress bar shows a true fraction of a
	 * known bound, not an estimate. Expect to finish around halfway.
	 *
	 * Proof of Work is done in slices sized to land near 16 ms, so a slow phone
	 * takes smaller bites than a desktop and neither blocks scrolling.
	 *
	 * @param {{salt: string, challenge: string, bits: number}} p
	 * @param {function(number)} onProgress fraction in [0, 1]
	 * @returns {Promise<number|null>} the secret, or null if there is none
	 */
	function solve(p, onProgress) {
		return new Promise(function (resolve) {
			var range = Math.pow(2, p.bits);
			var n = 0;
			var slice = 1024;

			function step() {
				var started = now();
				var end = Math.min(range, n + slice);

				for (; n < end; n++) {
					if (sha256(p.salt + n) === p.challenge) {
						onProgress(1);
						resolve(n);
						return;
					}
				}

				// Elapsed can read as 0 on a coarse clock; treating that as 1 ms
				// makes the next slice bigger, which is the right direction.
				var elapsed = now() - started || 1;
				slice = Math.max(256, Math.min(1 << 21, Math.round(slice * (16 / elapsed))));

				onProgress(n / range);
				if (n >= range) {
					resolve(null);
					return;
				}
				later(step);
			}

			// Started on the next turn so the caller can paint its progress bar
			// before the first slice takes the thread.
			later(step);
		});
	}

	function mailto(address) {
		var href = 'mailto:' + address;
		if (config.subject) {
			href += '?subject=' + encodeURIComponent(config.subject);
		}
		return href;
	}

	/**
	 * Swap the button for the link.
	 *
	 * Replacing rather than revealing alongside: the button has served its
	 * purpose, and leaving it would put a dead control in the tab order. Focus
	 * moves to the new link so a keyboard user lands on the thing that appeared,
	 * and the wrapper's aria-live announces it for anyone whose reader does not
	 * follow the focus move.
	 *
	 * The class comes from the server (data-ce-reveal-class), which is what makes
	 * the address keep the button's shape in button mode and read as a plain link
	 * in link mode, without this file knowing which mode it is in.
	 */
	function finish(button, address) {
		if (!address) {
			button.disabled = true;
			button.textContent = config.failed || 'Address unavailable';
			return;
		}

		var link = document.createElement('a');
		link.href = mailto(address);
		link.textContent = address;
		// nofollow: this is not a link anyone should be crawling. noopener costs
		// nothing and is right for any link a theme might open in a new tab.
		link.rel = 'nofollow noopener';
		link.className = button.getAttribute('data-ce-reveal-class') || 'contact-email-link';

		button.parentNode.replaceChild(link, button);

		// Not fatal if the browser refuses -- the address is on screen either way.
		try {
			link.focus();
		} catch (e) {
			/* ignore */
		}
	}

	/**
	 * The progress bar shown while the work runs.
	 *
	 * aria-hidden, and deliberately: it lives inside the widget's aria-live
	 * region, and a percentage that changes sixty times a second would be read
	 * out sixty times a second. The one thing worth announcing -- that something
	 * is happening -- is said once, by the button's own label changing.
	 */
	function progress(button) {
		var wrap = document.createElement('span');
		wrap.className = 'contact-email-progress';
		wrap.setAttribute('aria-hidden', 'true');

		var track = document.createElement('span');
		track.className = 'contact-email-progress-track';
		var fill = document.createElement('span');
		fill.className = 'contact-email-progress-fill';
		track.appendChild(fill);

		var text = document.createElement('span');
		text.className = 'contact-email-progress-text';

		wrap.appendChild(track);
		wrap.appendChild(text);
		button.parentNode.insertBefore(wrap, button.nextSibling);

		return {
			set: function (ratio) {
				var percent = Math.min(100, Math.round(ratio * 100));
				fill.style.width = percent + '%';
				text.textContent = (config.progress || '%d%').replace('%d', percent);
			},
			remove: function () {
				if (wrap.parentNode) {
					wrap.parentNode.removeChild(wrap);
				}
			}
		};
	}

	/**
	 * Produce the address for one button.
	 *
	 * Synchronous when there is no proof of work, which is what the plugin has
	 * always done and what the whole test suite for the plain mode assumes.
	 */
	function reveal(button) {
		var p = puzzle(button);
		if (!p) {
			finish(button, decode(button, ''));
			return;
		}

		// A second click while the first search is running would start a second
		// search competing for the same thread and halve the speed of both.
		if (button.getAttribute('data-ce-busy') === '1') {
			return;
		}
		button.setAttribute('data-ce-busy', '1');
		button.disabled = true;
		button.textContent = config.working || 'Revealing address…';

		var bar = progress(button);
		bar.set(0);

		var started = now();
		log('solving', { salt: p.salt, challenge: p.challenge, bits: p.bits,
			range: Math.pow(2, p.bits) });

		solve(p, bar.set).then(function (secret) {
			bar.remove();
			button.removeAttribute('data-ce-busy');
			if (secret === null) {
				// The search covers the whole range the server draws from, so
				// running out means the challenge is not the one that was
				// rendered -- rewritten in transit, or a stale cached page whose
				// script has since been replaced. Nothing to reveal either way.
				warn('no solution in [0, 2^' + p.bits + '). The challenge does not'
					+ ' match the ciphertext on this button.');
				finish(button, '');
				return;
			}
			log('solved in', Math.round(now() - started), 'ms, secret', secret,
				'of', Math.pow(2, p.bits));
			finish(button, decode(button, sha256(secret + p.salt)));
		});
	}

	/**
	 * Compare this browser's SHA-256 against the server's on identical input.
	 *
	 * Runs once, with debug on. If these two disagree nothing else can possibly
	 * work, and every downstream symptom is misleading -- so it is worth ruling
	 * out before reading any of them.
	 */
	function selfCheck() {
		var d = config.debug;
		if (!d) {
			return;
		}
		log('server diagnostics', d);
		if (d.selfTest && d.selfTest.cipherRoundTrip === false) {
			warn('the server failed its own cipher round trip. The fault is'
				+ ' server-side; nothing in this browser can be responsible.');
		}
		if (d.mbFuncOverload) {
			warn('mbstring.func_overload is ' + d.mbFuncOverload + ' on the server.'
				+ ' It redefines strlen/substr to count characters instead of'
				+ ' bytes, which corrupts the cipher on any non-ASCII byte.');
		}
		if (!window.ContactEmailSha256 || !d.selfTest || !d.selfTest.keystreamInput) {
			return;
		}
		var mine = sha256(d.selfTest.keystreamInput).slice(0, 16);
		if (mine === d.selfTest.keystreamProbe) {
			log('SHA-256 agrees with the server');
		} else {
			warn('SHA-256 disagrees with the server on identical input. Server: '
				+ d.selfTest.keystreamProbe + ' browser: ' + mine);
		}
	}

	function template() {
		var node = document.getElementById('jscontactEmailTemplate');
		return node && node.content ? node.content.firstElementChild : null;
	}

	/** Every text node under `root` that could hold the token. */
	function textNodes(root) {
		var out = [];
		var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
			acceptNode: function (node) {
				if (!node.nodeValue || node.nodeValue.indexOf(TOKEN) === -1) {
					return NodeFilter.FILTER_REJECT;
				}
				var parent = node.parentNode;
				while (parent && parent.nodeType === 1) {
					if (SKIP.indexOf(parent.nodeName) !== -1) {
						return NodeFilter.FILTER_REJECT;
					}
					parent = parent.parentNode;
				}
				return NodeFilter.FILTER_ACCEPT;
			}
		});
		var node = walker.nextNode();
		while (node) {
			out.push(node);
			node = walker.nextNode();
		}
		return out;
	}

	/** Replace one text node's tokens with buttons. Returns how many it made. */
	function expand(node, widget) {
		var text = node.nodeValue;
		var fragment = document.createDocumentFragment();
		var cursor = 0;
		var made = 0;
		var at = text.indexOf(TOKEN);

		while (at !== -1) {
			if (at > cursor) {
				fragment.appendChild(document.createTextNode(text.slice(cursor, at)));
			}
			fragment.appendChild(widget.cloneNode(true));
			made++;
			cursor = at + TOKEN.length;
			at = text.indexOf(TOKEN, cursor);
		}

		if (cursor < text.length) {
			fragment.appendChild(document.createTextNode(text.slice(cursor)));
		}

		node.parentNode.replaceChild(fragment, node);
		return made;
	}

	function expandTokens() {
		var widget = template();
		if (!widget) {
			return 0;
		}
		var made = 0;
		// Collected first: replacing a node while the TreeWalker is positioned on
		// it invalidates the traversal.
		textNodes(document.body).forEach(function (node) {
			made += expand(node, widget);
		});
		return made;
	}

	function start() {
		log('script version', VERSION, 'page rendered by', config.version || 'unknown');
		checkVersion(null);
		selfCheck();
		expandTokens();

		// Delegated, so buttons expanded from tokens and the sidebar widget the
		// server rendered are both covered by one listener -- and so a theme that
		// injects content later still works.
		document.addEventListener('click', function (event) {
			var button = event.target.closest
				? event.target.closest('button[data-contact-email]')
				: null;
			if (!button) {
				return;
			}
			event.preventDefault();
			reveal(button);
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', start);
	} else {
		start();
	}

	// Exposed for the tests and for support. decode() takes an element and, with
	// the proof of work on, a key that only solve() produces -- so this is not a
	// way to get the address without doing the work the button does.
	window.ContactEmail = {
		VERSION: VERSION,
		config: config,
		rot13: rot13,
		decode: decode,
		puzzle: puzzle,
		solve: solve,
		reveal: reveal,
		expandTokens: expandTokens
	};
})(window, document);
