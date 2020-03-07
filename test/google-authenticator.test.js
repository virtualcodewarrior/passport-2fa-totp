'use strict';

const expect = require('chai').expect;
const base32 = require('thirty-two');
const GoogleAuthenticator = require('..').GoogeAuthenticator;

describe('Google Authenticator utils', function () {
    it('register', function () {
        const code = GoogleAuthenticator.register('username');

        expect(code).to.be.an('object');
        expect(code.qr).to.be.a('string');
        expect(code.qr).to.have.length.above(0);
        expect(code.secret).to.be.a('string');
        expect(code.secret).to.have.length.above(0);
    });

    it('decodeSecret', function () {
        const code = GoogleAuthenticator.register('username');
        const decodedSecret = GoogleAuthenticator.decodeSecret(code.secret);
        const encodedSecret = base32.encode(decodedSecret).toString().replace(/=/g, ''); // Google Authenticator ignores '='

        expect(encodedSecret).to.be.equal(code.secret);
    });
});
