/**
 * Created by pfbongio on 11/10/2016.
 */
'use strict';

module.exports = function () {
    var _this = this;

    var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    if (this && this.log && this.log.info) this.log.info('Adding auth seneca services');
    var deserializeUser = options.deserializeUser;

    var _ref = options.app_tokens || require('./app_tokens'),
        userScopeByToken = _ref.userScopeByToken;

    this.add({
        role: 'identity',
        action: 'verify_token'
    }, function (msg, respond) {
        var token = msg.token;

        var response = {};
        userScopeByToken(token).then(function (tokenData) {
            if (!tokenData || !tokenData.scopes || !tokenData.user_id) throw new Error('No valid token data found');
            response.scopes = tokenData.scopes;
            return deserializeUser(tokenData.user_id);
        }).then(function (user) {
            if (!user) throw new Error('User not found');
            Object.assign(response, {
                result: 'ok',
                user: user
            });
            respond(null, response);
        }).catch(function (err) {
            _this.log.warn('Unable to authenticate a app token: ' + err);
            respond(null, {
                result: 'error',
                details: String(err)
            });
        });
    });
    return 'TokenIdentityService';
};