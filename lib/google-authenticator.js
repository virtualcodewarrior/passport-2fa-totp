'use strict';

const crypto = require('crypto');
const base32 = require('thirty-two');
const qr = require('qr-image');

module.exports = {
    register(username, issuer) {
        if (!username) {
            throw new TypeError("Username is required");
        }

        const secret = base32.encode(crypto.randomBytes(32)).toString().replace(/=/g, ''); // Google Authenticator ignores '='
        const authUrl = `otpauth://totp/${username}?secret=${secret}${(issuer) ? `&issuer=${issuer}` : ''}`;
        const qrCode = qr.imageSync(authUrl, { type: 'svg' });

        return {
            secret: secret,
            qr: qrCode
        };
    },

    decodeSecret(secret) {
        return base32.decode(secret);
    }
};
