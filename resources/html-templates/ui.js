(function () {
    'use strict';

    var KEY = 'stalwart-ui';
    var root = document.documentElement;
    var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

    var LOGO = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="95 84 500 90" role="img" aria-label="Stalwart">'
        + '<path class="wordmark" d="M227.8 143.6c.3 4.2 2.1 7.6 5.1 10.1 3.1 2.5 7.1 3.8 12.1 3.8 4.3 0 7.9-.9 10.5-2.8 2.7-1.9 4-4.5 4-7.8 0-2.4-.7-4.3-2.2-5.7-1.5-1.4-3.4-2.5-6-3.2-2.5-.7-6-1.5-10.6-2.3-4.6-.8-8.6-1.9-11.9-3.2-3.3-1.3-6-3.3-8.1-6.1-2.1-2.7-3.1-6.3-3.1-10.7 0-4.1 1.1-7.7 3.2-10.9s5.1-5.7 9-7.4c3.8-1.8 8.2-2.6 13.2-2.6 5.1 0 9.6 1 13.7 2.9 4 1.9 7.2 4.5 9.5 7.8s3.6 7.1 3.8 11.4h-11.5c-.4-3.7-2-6.6-4.8-8.9-2.8-2.2-6.3-3.4-10.6-3.4-4.1 0-7.5.9-9.9 2.7-2.5 1.8-3.7 4.3-3.7 7.6 0 2.3.7 4.1 2.2 5.5 1.5 1.4 3.4 2.4 5.9 3.1 2.4.7 5.9 1.4 10.5 2.2 4.6.8 8.6 1.9 11.9 3.3 3.3 1.4 6 3.4 8.2 6 2.1 2.6 3.2 6.1 3.2 10.5 0 4.2-1.1 8-3.4 11.3-2.2 3.3-5.4 5.9-9.4 7.8-4 1.9-8.6 2.8-13.7 2.8-5.6 0-10.6-1-14.9-3.1-4.3-2-7.6-4.9-10-8.5-2.4-3.6-3.7-7.8-3.7-12.5l11.5.3zM278.5 102.1l11-2.1v14.6h12.6v9.7h-12.6v27.2c0 2 .4 3.5 1.2 4.3.8.9 2.2 1.3 4.2 1.3h8.4v9.7h-10.6c-5 0-8.6-1.2-10.8-3.5-2.2-2.3-3.4-5.9-3.4-10.7v-50.5zM356.8 114.6v52.2h-9.7l-1.2-7.9c-1.8 2.6-4.2 4.7-7 6.2-2.9 1.6-6.2 2.3-10 2.3-4.8 0-9-1.1-12.7-3.2-3.7-2.1-6.7-5.2-8.8-9.3-2.1-4-3.2-8.8-3.2-14.2 0-5.3 1.1-10 3.2-14s5.1-7.2 8.8-9.4c3.7-2.2 7.9-3.3 12.6-3.3 3.9 0 7.2.7 10.1 2.2 2.9 1.5 5.2 3.5 6.9 6.1l1.3-7.6h9.7zm-15.1 38.7c2.8-3.2 4.2-7.3 4.2-12.4 0-5.2-1.4-9.4-4.2-12.6-2.8-3.3-6.5-4.9-11-4.9-4.6 0-8.2 1.6-11 4.8-2.8 3.2-4.2 7.4-4.2 12.5 0 5.2 1.4 9.4 4.2 12.6 2.8 3.2 6.5 4.8 11 4.8s8.2-1.6 11-4.8zM365.5 97.5l11-2.1v71.3h-11V97.5zM380.3 114.6h11.6l11.9 39.9 11.9-39.9h10.1l11.4 39.9 12.3-39.9h11.2l-17.3 52.2h-11.8l-11-35.5-11.4 35.5-11.9.1-17-52.3zM513.7 114.6v52.2H504l-1.2-7.9c-1.8 2.6-4.2 4.7-7 6.2-2.9 1.6-6.2 2.3-10 2.3-4.8 0-9-1.1-12.7-3.2-3.7-2.1-6.7-5.2-8.8-9.3-2.1-4-3.2-8.8-3.2-14.2 0-5.3 1.1-10 3.2-14s5.1-7.2 8.8-9.4c3.7-2.2 7.9-3.3 12.6-3.3 3.9 0 7.2.7 10.1 2.2 2.9 1.5 5.2 3.5 6.9 6.1l1.3-7.6h9.7zm-15.1 38.7c2.8-3.2 4.2-7.3 4.2-12.4 0-5.2-1.4-9.4-4.2-12.6-2.8-3.3-6.5-4.9-11-4.9-4.6 0-8.2 1.6-11 4.8-2.8 3.2-4.2 7.4-4.2 12.5 0 5.2 1.4 9.4 4.2 12.6 2.8 3.2 6.5 4.8 11 4.8 4.6 0 8.2-1.6 11-4.8zM551.3 114.6v10.3h-4.9c-4.6 0-7.8 1.5-9.9 4.4-2 3-3.1 6.7-3.1 11.3v26.2h-11v-52.2h9.8l1.2 7.8c1.5-2.4 3.4-4.4 5.8-5.8 2.4-1.4 5.6-2.1 9.6-2.1h2.5zM556.3 102.1l11-2.1v14.6h12.6v9.7h-12.6v27.2c0 2 .4 3.5 1.2 4.3.8.9 2.2 1.3 4.2 1.3h8.4v9.7h-10.6c-5 0-8.6-1.2-10.8-3.5s-3.4-5.9-3.4-10.7v-50.5z"/>'
        + '<path class="symbol" d="M149.1 84.7h-4.8l-44.8 25.9v8.3l44.8 25.9h4.8l44.8-25.9v-8.3l-44.8-25.9zm32.9 30h-35.3V94.4l35.3 20.3zm-35.3 20.4-35.3-20.4 27-15.6v20.2l6.3 3.6h22.9l-20.9 12.2zM99.5 129.9v11l44.8 25.9h4.8l44.8-25.9v-11l-47.2 27.3zM187.3 166.8l6.6-3.8v-11l-25.7 14.8zM99.5 163l6.6 3.8h19.1L99.5 152z"/>'
        + '</svg>';

    function readStore() {
        try {
            var stored = JSON.parse(window.localStorage.getItem(KEY));
            return stored && typeof stored === 'object' ? stored : null;
        } catch (e) {
            return null;
        }
    }

    function storedTheme() {
        var stored = readStore();
        var theme = stored && stored.state && stored.state.theme;
        return theme === 'dark' || theme === 'light' ? theme : null;
    }

    function applyTheme(theme) {
        root.classList.toggle('dark', theme === 'dark');
        root.classList.toggle('light', theme === 'light');
    }

    function currentTheme() {
        if (root.classList.contains('dark')) return 'dark';
        if (root.classList.contains('light')) return 'light';
        return media && media.matches ? 'dark' : 'light';
    }

    function setTheme(theme) {
        applyTheme(theme);
        var stored = readStore() || { state: {}, version: 0 };
        if (!stored.state || typeof stored.state !== 'object') stored.state = {};
        stored.state.theme = theme;
        try {
            window.localStorage.setItem(KEY, JSON.stringify(stored));
        } catch (e) {
            return;
        }
    }

    function labelToggle(button) {
        button.setAttribute('aria-label', currentTheme() === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    }

    applyTheme(storedTheme());

    var $ = function (id) { return document.getElementById(id); };

    function setText(el, text) { if (el) el.textContent = text == null ? '' : String(text); }
    function show(el) { if (el) el.hidden = false; }
    function hide(el) { if (el) el.hidden = true; }
    function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

    function loadLogo(wrap, target, credentials) {
        function showDefault() { wrap.innerHTML = LOGO; }
        fetch(target, { method: 'GET', credentials: credentials })
            .then(function (res) {
                if (!res.ok) return null;
                var ct = (res.headers.get('content-type') || '').toLowerCase();
                return ct.indexOf('image/') === 0 ? res.blob() : null;
            })
            .then(function (blob) {
                if (!blob) { showDefault(); return; }
                var objectUrl = URL.createObjectURL(blob);
                var img = new Image();
                img.alt = 'Logo';
                img.onload = function () { clear(wrap); wrap.appendChild(img); };
                img.onerror = function () { URL.revokeObjectURL(objectUrl); showDefault(); };
                img.src = objectUrl;
            })
            .catch(function () { showDefault(); });
    }

    function loginPage() {
            var FAILURE = 'Temporary server failure. If the problem persists, contact your administrator.';

            function showError(msg) {
                var a = $('alert');
                a.classList.remove('success');
                setText($('alert-msg'), msg);
                show(a);
            }

            function showSuccess(msg) {
                var a = $('alert');
                a.classList.add('success');
                setText($('alert-msg'), msg);
                show(a);
            }

            function clearAlert() { hide($('alert')); }

            var url = new URL(window.location.href);
            var params = url.searchParams;
            var isDevice = /\/device(\/|$)/.test(url.pathname);
            var query = url.search.charAt(0) === '?' ? url.search.slice(1) : url.search;
            var loginHint = params.get('login_hint');
            var clientInfo = null;
            var deviceCode = null;
            var stage = 'login';
            var inMfa = false;
            var lastCreds = null;
            var allowHandler = null;
            var denyHandler = null;
            var leaving = false;

            if (loginHint) $('username').value = loginHint;

            var BLOCKED_PROTOCOLS = ['javascript:', 'data:', 'vbscript:', 'file:', 'blob:', 'about:'];

            function isSafeLocation(location) {
                try {
                    return BLOCKED_PROTOCOLS.indexOf(new URL(location).protocol.toLowerCase()) === -1;
                } catch (e) {
                    return false;
                }
            }

            function navigate(location) {
                if (typeof location !== 'string' || !location) {
                    showFatal(FAILURE);
                } else if (!isSafeLocation(location)) {
                    showFatal('The application redirect address is not allowed.');
                } else {
                    leaving = true;
                    window.location.assign(location);
                }
            }

            function showFatal(msg) {
                hide($('login-form'));
                hide($('consent'));
                hide($('app-tile'));
                setText($('title'), 'Unable to continue');
                setText($('subtitle'), '');
                showError(msg);
            }

            function hashHue(seed) {
                var h = 0;
                for (var i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
                return h % 360;
            }

            function isSafeLogo(logo) {
                if (typeof logo !== 'string' || !logo) return false;
                if (logo.indexOf('data:image/') === 0) return true;
                try {
                    return new URL(logo, window.location.href).origin === window.location.origin;
                } catch (e) {
                    return false;
                }
            }

            function renderTile(tile, name, logo, seed) {
                clear(tile);
                tile.style.background = '';
                if (isSafeLogo(logo)) {
                    var img = new Image();
                    img.alt = '';
                    img.onerror = function () { renderTile(tile, name, null, seed); };
                    img.src = logo;
                    tile.appendChild(img);
                    return;
                }
                var letter = Array.from((name || '').trim())[0] || '?';
                tile.style.background = 'hsl(' + hashHue(seed || name || '') + ',45%,45%)';
                setText(tile, letter.toUpperCase());
            }

            function renderConsent(info, onAllow, onDeny) {
                var name = typeof info.name === 'string' && info.name ? info.name : 'Unnamed application';
                setText($('client-name'), name);
                if (info.verified) hide($('client-unverified')); else show($('client-unverified'));
                if (typeof info.clientHost === 'string' && info.clientHost) {
                    setText($('client-host'), info.clientHost);
                    show($('client-host'));
                } else {
                    hide($('client-host'));
                }
                renderTile($('client-tile'), name, info.verified ? info.logo : null,
                    info.clientHost || info.redirectHost || name);

                var list = $('client-scopes');
                clear(list);
                var scopes = Array.isArray(info.scopes) ? info.scopes : [];
                if (!scopes.length) scopes = ['Confirm that you have an account on this server'];
                scopes.forEach(function (label) {
                    var li = document.createElement('li');
                    setText(li, label);
                    list.appendChild(li);
                });

                if (typeof info.redirectHost === 'string' && info.redirectHost) {
                    setText($('client-redirect'), 'You will be sent back to ' + info.redirectHost + ' after you sign in.');
                    show($('client-redirect'));
                } else {
                    hide($('client-redirect'));
                }

                hide($('login-form'));
                hide($('app-tile'));
                setText($('title'), isDevice ? 'Authorize device' : 'Authorize access');
                setText($('subtitle'), isDevice
                    ? 'A device is requesting access to your account.'
                    : 'An application is requesting access to your account.');
                allowHandler = onAllow;
                denyHandler = onDeny;
                stage = 'consent';
                show($('consent'));
                setTimeout(function () { $('allow-btn').focus(); }, 0);
            }

            function showLoginForm() {
                stage = 'login';
                hide($('consent'));
                show($('field-username'));
                show($('field-password'));
                hide($('field-device-code'));
                hide($('field-otp'));
                setText($('submit-btn'), 'Sign in');
                var name = clientInfo && typeof clientInfo.name === 'string' ? clientInfo.name : '';
                if (clientInfo && !clientInfo.consentRequired && name) {
                    setText($('title'), 'Sign in to ' + name);
                    if (isSafeLogo(clientInfo.logo)) {
                        renderTile($('app-tile'), name, clientInfo.logo, name);
                        show($('app-tile'));
                    }
                    setText($('subtitle'), 'Enter your credentials to continue');
                } else {
                    setText($('title'), 'Sign in');
                    setText($('subtitle'), name
                        ? 'Enter your credentials to continue to ' + name
                        : 'Enter your credentials to continue');
                }
                show($('login-form'));
                focusFirst();
            }

            function focusFirst() {
                setTimeout(function () {
                    if (stage === 'code') { $('device-code').focus(); return; }
                    if (!$('username').value) { $('username').focus(); return; }
                    if (!$('password').value) { $('password').focus(); return; }
                }, 0);
            }

            function enterMfaMode() {
                inMfa = true;
                hide($('field-username'));
                hide($('field-password'));
                show($('field-otp'));
                setText($('title'), 'Two-factor authentication');
                setText($('subtitle'), 'Enter the 6-digit code from your authenticator app.');
                clearAlert();
                setTimeout(function () { $('otp').focus(); }, 0);
            }

            function leaveMfaMode() {
                inMfa = false;
                $('otp').value = '';
                showLoginForm();
            }

            (function loadCustomLogo() {
                var target = '/logo';
                if (loginHint) {
                    var at = loginHint.lastIndexOf('@');
                    if (at !== -1 && at < loginHint.length - 1) {
                        target = '/logo?domain=' + encodeURIComponent(loginHint.slice(at + 1).toLowerCase());
                    }
                }
                loadLogo($('logo-wrap'), target, 'same-origin');
            })();

            function getJson(target) {
                return fetch(target, {
                    method: 'GET',
                    credentials: 'same-origin',
                    cache: 'no-store',
                    headers: { 'Accept': 'application/json' }
                }).then(function (res) {
                    if (res.status !== 200) throw new Error('http ' + res.status);
                    return res.json();
                });
            }

            function postLogin(body) {
                var btn = $('submit-btn');
                btn.disabled = true;
                return fetch('/api/auth', {
                    method: 'POST',
                    credentials: 'same-origin',
                    cache: 'no-store',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify(body)
                }).then(function (res) {
                    if (res.status !== 200) {
                        return res.text().then(function (txt) {
                            console.log('Login endpoint returned HTTP', res.status, txt);
                            throw new Error('http ' + res.status);
                        });
                    }
                    return res.json();
                }).then(function (json) {
                    handleResponse(json);
                }).catch(function (err) {
                    console.log('Login request failed:', err);
                    showError(FAILURE);
                }).then(function () {
                    btn.disabled = false;
                });
            }

            function handleResponse(resp) {
                if (!resp || typeof resp !== 'object' || typeof resp.type !== 'string') {
                    console.log('Malformed login response:', resp);
                    showError(FAILURE);
                    return;
                }
                switch (resp.type) {
                    case 'authenticated':
                    case 'redirect':
                        navigate(resp.location);
                        return;
                    case 'invalid':
                        showFatal(typeof resp.description === 'string' && resp.description
                            ? resp.description
                            : 'The sign-in request is invalid.');
                        return;
                    case 'verified':
                        hide($('login-form'));
                        hide($('consent'));
                        setText($('title'), 'Device authorized');
                        setText($('subtitle'), 'You have successfully authorized this device. You may now close this window.');
                        showSuccess('Device verified.');
                        return;
                    case 'denied':
                        hide($('login-form'));
                        hide($('consent'));
                        setText($('title'), 'Access denied');
                        setText($('subtitle'), 'The device was not authorized. You may now close this window.');
                        clearAlert();
                        return;
                    case 'mfaRequired':
                        enterMfaMode();
                        return;
                    case 'consentRequired':
                        requestConsent(resp.token);
                        return;
                    case 'expired':
                        if (inMfa) leaveMfaMode();
                        showError('Your password has expired. Change it in the account portal, then sign in again.');
                        return;
                    case 'failure':
                        if (inMfa) leaveMfaMode();
                        showError(isDevice
                            ? 'Invalid username or password, or the device code has expired. Please try again.'
                            : 'Invalid username or password. Please try again.');
                        return;
                    default:
                        console.log('Unknown login response type:', resp);
                        showError(FAILURE);
                }
            }

            function buildRequest(creds, otpValue) {
                var r;
                if (isDevice) {
                    r = {
                        type: 'authDevice',
                        accountName: creds.account_name,
                        accountSecret: creds.account_secret,
                        code: deviceCode,
                        consent: true
                    };
                } else {
                    r = {
                        type: 'authCode',
                        accountName: creds.account_name,
                        accountSecret: creds.account_secret,
                        query: query
                    };
                }
                if (otpValue) r.mfaToken = otpValue;
                return r;
            }

            function requestConsent(token) {
                if (typeof token !== 'string' || !token || !clientInfo) {
                    showFatal(FAILURE);
                    return;
                }
                inMfa = false;
                lastCreds = null;
                $('password').value = '';
                $('otp').value = '';
                hide($('field-otp'));
                var decide = function (allow) {
                    postConsent({ type: 'authConsent', token: token, query: query, consent: allow });
                };
                renderConsent(clientInfo, function () { decide(true); }, function () { decide(false); });
            }

            function postConsent(body) {
                var allow = $('allow-btn');
                var deny = $('deny-btn');
                allow.disabled = true;
                deny.disabled = true;
                postLogin(body).then(function () {
                    if (leaving) return;
                    allow.disabled = false;
                    deny.disabled = false;
                });
            }

            function normalizeCode(value) {
                var code = (value || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
                return code.length === 8 ? code.slice(0, 4) + '-' + code.slice(4) : code;
            }

            function lookupDevice() {
                var code = normalizeCode($('device-code').value);
                if (!code) {
                    showError('Please enter the device code.');
                    return;
                }
                $('device-code').value = code;
                var btn = $('submit-btn');
                btn.disabled = true;
                getJson('/api/auth/client?user_code=' + encodeURIComponent(code)).then(function (info) {
                    if (!info || typeof info !== 'object' || typeof info.error === 'string') {
                        showError('The device code is invalid or has expired.');
                        return;
                    }
                    deviceCode = code;
                    clientInfo = info;
                    renderConsent(info, function () {
                        showLoginForm();
                    }, function () {
                        postLogin({ type: 'authDevice', code: deviceCode, consent: false });
                    });
                }).catch(function (err) {
                    console.log('Device lookup failed:', err);
                    showError(FAILURE);
                }).then(function () {
                    btn.disabled = false;
                });
            }

            function startDevice() {
                stage = 'code';
                hide($('field-username'));
                hide($('field-password'));
                show($('field-device-code'));
                setText($('submit-btn'), 'Continue');
                setText($('title'), 'Authorize device');
                setText($('subtitle'), 'Enter the code shown on your device.');
                var prefillCode = params.get('code');
                if (prefillCode) {
                    $('device-code').value = normalizeCode(prefillCode);
                    lookupDevice();
                } else {
                    focusFirst();
                }
            }

            function startAuthorization() {
                hide($('login-form'));
                if (!query) {
                    setText($('title'), 'Sign in with an app');
                    setText($('subtitle'), 'This page is opened automatically by your mail, calendar or contacts app to authorize access to your account.');
                    showError('This sign-in page cannot be used directly. Please start the sign-in from your app instead.');
                    return;
                }
                setText($('subtitle'), 'Loading...');
                getJson('/api/auth/client?' + query).then(function (info) {
                    if (!info || typeof info !== 'object') throw new Error('malformed response');
                    if (typeof info.error === 'string') {
                        if (info.redirect === true) {
                            navigate(info.location);
                        } else {
                            showFatal(typeof info.description === 'string' && info.description
                                ? info.description
                                : 'The sign-in request is invalid.');
                        }
                        return;
                    }
                    clientInfo = info;
                    showLoginForm();
                }).catch(function (err) {
                    console.log('Client lookup failed:', err);
                    showFatal(FAILURE);
                });
            }

            function submitLogin(e) {
                if (e) e.preventDefault();
                clearAlert();

                if (stage === 'code') {
                    lookupDevice();
                    return;
                } else if (stage !== 'login') {
                    return;
                }

                if (inMfa) {
                    var otp = ($('otp').value || '').trim();
                    if (!otp) { showError('Please enter your one-time code.'); return; }
                    if (!lastCreds) {
                        leaveMfaMode();
                        showError('Session expired. Please sign in again.');
                        return;
                    }
                    postLogin(buildRequest(lastCreds, otp));
                    return;
                }

                var username = ($('username').value || '').trim();
                var password = $('password').value || '';
                if (!username || !password) {
                    showError('Please enter your username and password.');
                    return;
                }
                lastCreds = { account_name: username, account_secret: password };
                postLogin(buildRequest(lastCreds, null));
            }

            $('login-form').addEventListener('submit', submitLogin);
            $('allow-btn').addEventListener('click', function () {
                clearAlert();
                if (allowHandler) allowHandler();
            });
            $('deny-btn').addEventListener('click', function () {
                clearAlert();
                if (denyHandler) denyHandler();
            });

            $('otp').addEventListener('input', function () {
                this.value = this.value.replace(/\D/g, '');
                if (this.value.length === 6) submitLogin();
            });

            if (isDevice) startDevice(); else startAuthorization();
    }

    function rsvpPage() {
            var FALLBACK = {
                invitation: 'Invitation',
                updatedInvitation: 'Updated invitation',
                cancelled: 'Cancelled',
                description: 'Description',
                attendees: 'Attendees',
                organizer: 'Organizer',
                location: 'Location',
                conference: 'Conference',
                when: 'When',
                you: 'you',
                yes: 'Yes',
                maybe: 'Maybe',
                no: 'No',
                replyAs: 'Reply as $name',
                note: 'Note to the organizer (optional)',
                noteHint: 'Add a short message for the organizer.',
                send: 'Send response',
                update: 'Update response',
                change: 'Change my response',
                recorded: 'Your RSVP has been recorded',
                notified: 'The organizer has been notified.',
                accepted: 'Accepted',
                tentative: 'Tentative',
                declined: 'Declined',
                showMore: 'Show more',
                showLess: 'Show less',
                failed: 'RSVP failed',
                invalidLink: 'This RSVP link is not valid.',
                error: 'Temporary server failure. If the problem persists, contact your administrator.'
            };

            var PARTSTATS = ['accepted', 'tentative', 'declined'];
            function isPartStat(value) {
                return PARTSTATS.indexOf(value) !== -1;
            }

            var labels = FALLBACK;
            function applyDirection(resp) {
                if (!resp || !resp.language) return;
                var root = document.documentElement;
                root.lang = resp.language;
                root.dir = resp.dir === 'rtl' ? 'rtl' : 'ltr';
            }

            function t(key, name) {
                var value = (labels && labels[key]) || FALLBACK[key] || key;
                if (name != null) value = value.replace('$name', name);
                return value;
            }

            var url = new URL(window.location.href);
            var token = url.searchParams.get('i') || '';
            var preset = (url.searchParams.get('m') || '').toLowerCase();
            var apiUrl = (function () {
                var path = url.pathname.replace(/\/+$/, '');
                var at = path.lastIndexOf('/calendar/rsvp');
                return (at >= 0 ? path.slice(0, at) : '') + '/api/calendar/rsvp';
            })();

            function post(body) {
                return fetch(apiUrl, {
                    method: 'POST',
                    credentials: 'omit',
                    cache: 'no-store',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                }).then(function (res) {
                    return res.json().catch(function () {
                        return { type: 'error', reason: 'serverError' };
                    });
                });
            }

            var data = null;
            var selected = '';
            var peopleExpanded = false;
            var inFlight = false;

            function clearAlert() { hide($('alert')); }
            function showAlert(msg) { setText($('alert-msg'), msg); show($('alert')); }

            function fail(title, message) {
                hide($('view-loading'));
                hide($('view-event'));
                title = title || t('failed');
                document.title = title;
                setText($('error-title'), title);
                setText($('error-detail'), message || t('error'));
                show($('view-error'));
                $('error-title').focus();
            }

            function renderPeople() {
                var list = (data.attendees || []);
                var box = $('people');
                clear(box);
                if (!list.length) { hide($('section-people')); return; }

                var limit = peopleExpanded ? list.length : Math.min(list.length, 5);
                for (var i = 0; i < limit; i++) {
                    var person = list[i];
                    var row = document.createElement('div');
                    row.className = 'person';

                    var dot = document.createElement('span');
                    dot.className = 'dot ' + String(person.partstat || '').toLowerCase();
                    row.appendChild(dot);

                    var who = document.createElement('span');
                    who.className = 'who';
                    setText(who, person.name || person.email);
                    row.appendChild(who);

                    if (person.isOrganizer) {
                        var tagOrg = document.createElement('span');
                        tagOrg.className = 'chip';
                        setText(tagOrg, t('organizer'));
                        row.appendChild(tagOrg);
                    }
                    if (data.attendee && person.email &&
                        person.email.toLowerCase() === String(data.attendee.email || '').toLowerCase()) {
                        var tagYou = document.createElement('span');
                        tagYou.className = 'chip';
                        setText(tagYou, t('you'));
                        row.appendChild(tagYou);
                    }
                    box.appendChild(row);
                }

                var toggle = $('people-toggle');
                if (list.length > 5) {
                    setText(toggle, peopleExpanded ? t('showLess') : t('showMore'));
                    show(toggle);
                } else {
                    hide(toggle);
                }
                show($('section-people'));
            }

            function select(value) {
                if (inFlight || !isPartStat(value)) return;
                selected = value;
                var nodes = $('choices').querySelectorAll('.choice');
                for (var i = 0; i < nodes.length; i++) {
                    var checked = nodes[i].getAttribute('data-value') === value;
                    nodes[i].setAttribute('aria-checked', checked ? 'true' : 'false');
                    nodes[i].tabIndex = checked ? 0 : -1;
                }
                show($('note-wrap'));
                $('send').disabled = !value;
                clearAlert();
            }

            function renderRecorded(partstat) {
                var badge = $('recorded-badge');
                badge.className = 'badge' + (partstat === 'accepted' ? '' : ' ' + partstat);
                setText($('recorded-title'), t('recorded'));
                setText($('recorded-detail'), t(partstat) + '. ' + t('notified'));
                setText($('change'), t('change'));
                hide($('respond'));
                show($('recorded'));
                $('recorded-title').focus();
            }

            function renderEvent() {
                labels = data.labels || FALLBACK;

                var kind = data.kind || 'invitation';
                var kindEl = $('kind');
                setText(kindEl, kind === 'update' ? t('updatedInvitation')
                    : kind === 'cancel' ? t('cancelled') : t('invitation'));
                if (kind === 'cancel') kindEl.className = 'eyebrow danger';

                setText($('summary'), data.summary || t('invitation'));
                document.title = data.summary || t('invitation');

                var organizer = findOrganizer(data);
                if (organizer) {
                    setText($('byline'), t('organizer') + ': '
                        + (organizer.name || organizer.email));
                    show($('byline'));
                }

                if (data.when) {
                    setText($('when'), data.when);
                    show($('row-when'));
                }
                if (data.recurrence) { setText($('repeat'), data.recurrence); show($('row-repeat')); }
                if (data.location) { setText($('where'), data.location); show($('row-where')); }
                if (data.conference) {
                    var link = $('conference');
                    setText(link, data.conference.value);
                    if (data.conference.url) {
                        link.href = data.conference.url;
                    } else {
                        link.removeAttribute('href');
                    }
                    show($('row-conference'));
                }
                if (!data.when && !data.recurrence && !data.location && !data.conference) {
                    hide($('meta'));
                }

                if (data.description) {
                    setText($('desc-title'), t('description'));
                    setText($('desc'), data.description);
                    show($('section-desc'));
                }

                setText($('people-title'), t('attendees'));
                renderPeople();

                setText($('label-accepted'), t('yes'));
                setText($('label-tentative'), t('maybe'));
                setText($('label-declined'), t('no'));
                setText($('note-label'), t('note'));
                $('note').placeholder = t('noteHint');
                updateCount();

                var me = data.attendee || {};
                setText($('reply-as'), t('replyAs', me.name ? me.name + ' (' + me.email + ')' : me.email));

                var current = String(data.partstat || '').toLowerCase();
                var known = isPartStat(current);
                setText($('send'), known ? t('update') : t('send'));

                hide($('view-loading'));
                show($('view-event'));

                if (data.description) {
                    var desc = $('desc');
                    if (desc.scrollHeight - desc.clientHeight > 4) {
                        setText($('desc-toggle'), t('showMore'));
                        show($('desc-toggle'));
                    }
                }

                if (kind === 'cancel') {
                    hide($('respond'));
                    return;
                }

                if (isPartStat(preset)) {
                    select(preset);
                } else if (known) {
                    select(current);
                }
            }

            function updateCount() {
                var used = $('note').value.length;
                setText($('note-count'), used ? used + ' / 512' : '');
            }

            function send() {
                if (inFlight || !isPartStat(selected)) return;
                var btn = $('send');
                inFlight = true;
                btn.disabled = true;
                clearAlert();

                post({
                    token: token,
                    partstat: selected,
                    comment: $('note').value.trim()
                }).then(function (resp) {
                    if (resp && resp.type === 'recorded') {
                        data.partstat = resp.partstat || selected;
                        renderRecorded(String(data.partstat).toLowerCase());
                        return;
                    }
                    inFlight = false;
                    btn.disabled = false;
                    showAlert((resp && resp.message) || t('error'));
                }).catch(function () {
                    inFlight = false;
                    btn.disabled = false;
                    showAlert(t('error'));
                });
            }

            function loadCustomLogo(domain) {
                var target = apiUrl.replace(/\/api\/calendar\/rsvp$/, '') + '/logo';
                if (domain) target += '?domain=' + encodeURIComponent(domain);
                loadLogo($('logo-wrap'), target, 'omit');
            }

            function findOrganizer(resp) {
                var list = (resp && resp.attendees) || [];
                for (var i = 0; i < list.length; i++) {
                    if (list[i].isOrganizer) return list[i];
                }
                return null;
            }

            function organizerDomain(resp) {
                var organizer = findOrganizer(resp);
                var email = organizer && organizer.email;
                var at = email ? String(email).lastIndexOf('@') : -1;
                return at !== -1 ? String(email).slice(at + 1).toLowerCase() : '';
            }

            $('choices').addEventListener('click', function (ev) {
                var btn = ev.target.closest ? ev.target.closest('.choice') : null;
                if (btn) select(btn.getAttribute('data-value'));
            });
            $('choices').addEventListener('keydown', function (ev) {
                var step = ev.key === 'ArrowRight' || ev.key === 'ArrowDown' ? 1
                    : ev.key === 'ArrowLeft' || ev.key === 'ArrowUp' ? -1 : 0;
                if (!step) return;
                ev.preventDefault();
                var at = PARTSTATS.indexOf(selected);
                var next = PARTSTATS[(at + step + PARTSTATS.length) % PARTSTATS.length];
                select(next);
                var node = $('choices').querySelector('.choice[data-value="' + next + '"]');
                if (node) node.focus();
            });
            $('send').addEventListener('click', send);
            $('note').addEventListener('input', updateCount);
            $('desc-toggle').addEventListener('click', function () {
                var clamped = $('desc').classList.toggle('clamped');
                setText($('desc-toggle'), clamped ? t('showMore') : t('showLess'));
                $('desc-toggle').setAttribute('aria-expanded', clamped ? 'false' : 'true');
            });
            $('people-toggle').addEventListener('click', function () {
                peopleExpanded = !peopleExpanded;
                $('people-toggle').setAttribute('aria-expanded', peopleExpanded ? 'true' : 'false');
                renderPeople();
            });
            $('change').addEventListener('click', function () {
                inFlight = false;
                hide($('recorded'));
                show($('respond'));
                $('send').disabled = !selected;
                setText($('send'), t('update'));
            });

            if (!token) { loadCustomLogo(''); fail(null, FALLBACK.invalidLink); return; }

            post({ token: token }).then(function (resp) {
                loadCustomLogo(organizerDomain(resp));
                applyDirection(resp);
                if (resp && resp.labels) labels = resp.labels;
                if (!resp || resp.type !== 'invitation') {
                    fail(resp && resp.title, resp && resp.message);
                    return;
                }
                data = resp;
                renderEvent();
            }).catch(function () {
                loadCustomLogo('');
                fail();
            });
    }

    document.addEventListener('DOMContentLoaded', function () {
        var button = $('theme-toggle');
        if (button) {
            labelToggle(button);
            button.addEventListener('click', function () {
                setTheme(currentTheme() === 'dark' ? 'light' : 'dark');
                labelToggle(button);
            });
            if (media && media.addEventListener) {
                media.addEventListener('change', function () { labelToggle(button); });
            }
        }
        var page = document.body.getAttribute('data-page');
        if (page === 'login') loginPage();
        else if (page === 'rsvp') rsvpPage();
    });
})();
