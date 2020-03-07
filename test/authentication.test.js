'use strict';

const chai = require('chai');
const expect = chai.expect;
const totp = require('notp').totp;
const Strategy = require('..').Strategy;

chai.use(require('chai-passport-strategy'));

const ERROR_USERNAME = 'error';
const USERNAME = 'us3r';
const PASSWORD = 'p4ssw0rd';
const WRONG_PASSWORD = 'w40ng_pwd';
const AUTH_FAILED = 'Invalid username or password';
const ERROR = 'Error';

describe('Authentication using TOTP', function () {

    // Prepare test TOTP code (6 minutes period)
    const secret = '12345678901234567890';
    const totpCode = totp.gen(secret, { window: 6, time: 300 });

    const strategy = new Strategy(function (username, password, done) {
        if (username === USERNAME && password === PASSWORD) {
            done(null, { username: username });
        } else {
            done(null, null, AUTH_FAILED);
        }
    }, function (user, done) {
        done(null, secret, 300);
    });

    describe ('authentication - OK', function () {
        let user;

        before(function (done) {
            chai.passport.use(strategy)
                .success(function (u) {
                    user = u;
                    done();
                })
                .req(function (req) {
                    req.body = {};
                    req.body.username = USERNAME;
                    req.body.password = PASSWORD;
                    req.body.code = totpCode;
                })
                .authenticate();
        });

        it('check username', function () {
            expect(user.username).to.be.equal(USERNAME);
        });
    });

    describe ('authentication - wrong password', function () {
        let info;

        before(function (done) {
            chai.passport.use(strategy)
                .fail(function (i) {
                    info = i;
                    done();
                })
                .req(function (req) {
                    req.body = {};
                    req.body.username = USERNAME;
                    req.body.password = WRONG_PASSWORD;
                    req.body.code = totpCode;
                })
                .authenticate();
        });

        it('check error message', function () {
            expect(info).to.be.equal(AUTH_FAILED);
        });
    });

    describe ('authentication - wrong TOPT code', function () {
        let info;

        before(function (done) {
            chai.passport.use(strategy)
                .fail(function (i) {
                    info = i;
                    done();
                })
                .req(function (req) {
                    req.body = {};
                    req.body.username = USERNAME;
                    req.body.password = PASSWORD;
                    req.body.code = '123';
                })
                .authenticate();
        });

        it('check error message', function () {
            expect(info).to.be.equal(AUTH_FAILED);
        });
    });

});

describe('Authentication without TOTP', function () {

    describe ('pass request to the callbacks', function () {

        const strategy = new Strategy({
            skipTotpVerification: true,
            passReqToCallback: true
        }, function (req, username, password, done) {
            if (username === USERNAME && password === PASSWORD) {
                done(null, { username: username, req: req });
            } else {
                done(null, null, { error: AUTH_FAILED, req: req });
            }
        });

        describe ('authentication - OK', function () {
            let user;

            before(function (done) {
                chai.passport.use(strategy)
                    .success(function (u) {
                        user = u;
                        done();
                    })
                    .req(function (req) {
                        req.body = {};
                        req.body.username = USERNAME;
                        req.body.password = PASSWORD;
                    })
                    .authenticate();
            });

            it('check username', function () {
                expect(user.username).to.be.equal(USERNAME);
                expect(user.req.body.username).to.be.equal(USERNAME);
                expect(user.req.body.password).to.be.equal(PASSWORD);
            });
        });

        describe ('authentication - failed', function () {
            let info;

            before(function (done) {
                chai.passport.use(strategy)
                    .fail(function (i) {
                        info = i;
                        done();
                    })
                    .req(function (req) {
                        req.body = {};
                        req.body.username = USERNAME;
                        req.body.password = WRONG_PASSWORD;
                    })
                    .authenticate();
            });

            it('check error message', function () {
                expect(info.error).to.be.equal(AUTH_FAILED);
                expect(info.req.body.username).to.be.equal(USERNAME);
                expect(info.req.body.password).to.be.equal(WRONG_PASSWORD);
            });
        });

    });

    describe ('do not pass request to the callbacks', function () {

        const strategy = new Strategy({
            skipTotpVerification: true
        }, function (username, password, done) {
            if (username === ERROR_USERNAME) {
                done(ERROR);
            }
            else if (username === USERNAME && password === PASSWORD) {
                done(null, { username: username });
            } else {
                done(null, null, AUTH_FAILED);
            }
        });

        describe ('authentication - OK', function () {
            let user;

            before(function (done) {
                chai.passport.use(strategy)
                    .success(function (u) {
                        user = u;
                        done();
                    })
                    .req(function (req) {
                        req.body = {};
                        req.body.username = USERNAME;
                        req.body.password = PASSWORD;
                    })
                    .authenticate();
            });

            it('check username', function () {
                expect(user.username).to.be.equal(USERNAME);
            });
        });

        describe ('authentication - failed', function () {
            let info;

            before(function (done) {
                chai.passport.use(strategy)
                    .fail(function (i) {
                        info = i;
                        done();
                    })
                    .req(function (req) {
                        req.body = {};
                        req.body.username = USERNAME;
                        req.body.password = WRONG_PASSWORD;
                    })
                    .authenticate();
            });

            it('check error message', function () {
                expect(info).to.be.equal(AUTH_FAILED);
            });
        });

        describe ('authentication - error', function () {
            let error;

            before(function (done) {
                chai.passport.use(strategy)
                    .error(function (e) {
                        error = e;
                        done();
                    })
                    .req(function (req) {
                        req.body = {};
                        req.body.username = ERROR_USERNAME;
                        req.body.password = WRONG_PASSWORD;
                    })
                    .authenticate();
            });

            it('check error message', function () {
                expect(error).to.be.equal(ERROR);
            });
        });

    });

});

describe('Authentication with missign credentials', function () {
    const strategy = new Strategy(function () {}, function () {});

    describe('default error message', function () {
        let info;

        before(function (done) {
            chai.passport.use(strategy)
                .fail(function (message) {
                    info = message;
                    done();
                })
                .authenticate();
        });

        it('should be default missing credentials message', function () {
            expect(info).to.be.equal('Missing credentials');
        });
    });

    describe('custom error message', function () {
        let info;

        before(function (done) {
            chai.passport.use(strategy)
                .fail(function (message) {
                    info = message;
                    done();
                })
                .authenticate({
                    badRequestMessage: 'Failed'
                });
        });

        it('should be default missing credentials message', function () {
            expect(info).to.be.equal('Failed');
        });
    });

});
