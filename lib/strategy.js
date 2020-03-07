'use strict';

const passport = require('passport-strategy');
const util = require('util');
const totp = require('notp').totp;
const lookup = require('./utils').lookup;

function Strategy(options, verifyUsernameAndPassword, verifyTotpCode) {
    if (typeof options === 'function') {
        verifyTotpCode = verifyUsernameAndPassword;
        verifyUsernameAndPassword = options;
        options = {};
    }

    this._skipTotpVerification = options ? (options.skipTotpVerification || false) : false;

    if (!verifyUsernameAndPassword) {
        throw new TypeError('2FA TOTP Strategy required username and password verification callback');
    }

    if (!this._skipTotpVerification && !verifyTotpCode) {
        throw new TypeError('2FA TOTP Strategy required TOTP code verification callback');
    }

    this._usernameField = options.usernameField || 'username';
    this._passwordField = options.passwordField || 'password';
    this._codeField = options.codeField || 'code';
    this._window = options.window || 6;

    passport.Strategy.call(this);

    this.name = '2fa-totp';
    this._verifyUsernameAndPassword = verifyUsernameAndPassword;
    this._verifyTotpCode = verifyTotpCode;
    this._passReqToCallback = options.passReqToCallback || false;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
    const MISSING_CREDENTIALS = 'Missing credentials';
    const AUTH_FAILED = 'Invalid username or password';
    options = options || {};

    const username = lookup(req.body, this._usernameField) || lookup(req.query, this._usernameField);
    const password = lookup(req.body, this._passwordField) || lookup(req.query, this._passwordField);
    const code = lookup(req.body, this._codeField) || lookup(req.query, this._codeField);

    if (!username || !password) {
        return this.fail(options.badRequestMessage || MISSING_CREDENTIALS);
    }

    const firstStepAuth = new Promise((resolve, reject) => {
        // 1st step: check username and password
        const verify = function (error, user, info) {
            if (error) {
                reject({
                    error: true,
                    message: error
                });
            } else if (!user) {
                reject({
                    error: false,
                    message: info
                });
            } else {
                resolve(user);
            }
        };

        try {
            if (this._passReqToCallback) {
                this._verifyUsernameAndPassword(req, username, password, verify);
            } else {
                this._verifyUsernameAndPassword(username, password, verify);
            }
        } catch (err) {
            reject(err);
        }

    });

    firstStepAuth.then((user) => {
        if (this._skipTotpVerification) {
            // no verification so finish here successfully
            this.success(user);
        } else {
            // 2nd step: code verification using TOTP
            const verify = (error, secret, period) => {
                if (error) {
                    return this.error(error);
                }

                const isValid = totp.verify(code, secret, {
                    window: this._window,
                    time: period
                });

                if (isValid) {
                    this.success(user);
                } else {
                    this.fail(options.badRequestMessage || AUTH_FAILED);
                }
            };

            try {
                if (this._passReqToCallback) {
                    this._verifyTotpCode(req, user, verify);
                } else {
                    this._verifyTotpCode(user, verify);
                }
            } catch (err) {
                this.error(err);
            }
        }
    }).catch((reason) => {
        // 1st step failed. Return an error message to the user.
        if (reason.error) {
            this.error(reason.message || AUTH_FAILED);
        } else {
            this.fail(reason.message || AUTH_FAILED);
        }
    });
};

module.exports = Strategy;
