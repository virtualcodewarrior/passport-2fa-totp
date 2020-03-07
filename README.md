# passport-2fa-totp

![](https://github.com/virtualcodewarrior/passport-2fa-totp/workflows/passport-2fa-totp-tests/badge.svg)

[Passport](http://passportjs.org/) strategy for Two-factor authenticating with a username, password and TOTP code.

This module lets you authenticate using a username, password and TOTP code in your Node.js applications. By plugging into Passport, 2FA TOTP authentication can be easily and unobtrusively integrated into any application or framework that supports [Connect](http://www.senchalabs.org/connect/)-style middleware, including [Express](http://expressjs.com/). You can use any TOTP code generators to generate one-time passwords, for example [Google Authenticator](https://github.com/google/google-authenticator).

## Install

```bash
$ npm install passport-2fa-totp
```

## Usage

#### Configure Strategy

The 2FA TOTP authentication strategy authenticates a user using a username, password and TOTP value generated by a hardware device or software application (known as a token). The strategy requires a callback to verify a username and password and a callback to setup TOTP generator.

```js
var GoogleAuthenticator = require('passport-2fa-totp').GoogeAuthenticator;
var TwoFAStrategy = require('passport-2fa-totp').Strategy;

...

passport.use(new TwoFAStrategy(function (username, password, done) {
    // 1st step verification: username and password
    
    User.findOne({ username: username }, function (err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false); }
        if (!user.verifyPassword(password)) { return done(null, false); }
        return done(null, user);
    });
}, function (user, done) {
    // 2nd step verification: TOTP code from Google Authenticator
    
    if (!user.secret) {
        done(new Error("Google Authenticator is not setup yet."));
    } else {
        // Google Authenticator uses 30 seconds key period
        // https://github.com/google/google-authenticator/wiki/Key-Uri-Format
        
        var secret = GoogleAuthenticator.decodeSecret(user.secret);
        done(null, secret, 30);
    }
}));
```

`GoogleAuthenticator` object provides utility methods for Google Authenticator

`GoogleAuthenticator.register(username)` - Generate a secret key and render a QR code (SVG) to register an account in Google Authenticator.

`GoogleAuthenticator.decodeSecret(secret)` - Convert BASE 32 encoded string to byte array.

##### Available Options

This strategy takes an optional options hash before the function, e.g. `new TwoFAStartegy({/* options */, verifyUsernameAndPasswordCallback, verifyTotpCodeCallback})`.

The available options are:

* `usernameField` - Optional, defaults to 'username'
* `passwordField` - Optional, defaults to 'password'
* `codeField` - Optional, defaults to 'code'
* `window` - Optional defaults to 6. A window to generate TOTP code.
* `skipTotpVerification` - Optional defaults to false. TOTP code verification is skipped if it is set to be true.
* `passReqToCallback` - Optional defaults to false. Pass `request` object to the callbacks if it is set to be true.

#### Authenticate Requests

Use `passport.authenticate()`, specifying the '2fa-totp' strategy, to authenticate requests.

```js
router.post('/', passport.authenticate('2fa-totp', {
    successRedirect: '/',
    failureRedirect: '/login'
}));
```

## Examples

Developers using the popular [Express](http://expressjs.com/) web framework can refer to an [node-2fa](https://github.com/ilich/node-2fa) as a starting point for their own web applications.

## Tests

```bash
$ npm install
$ npm test
```
