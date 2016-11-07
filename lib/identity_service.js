/**
 * Created by pfbongio on 11/10/2016.
 */
'use strict';

module.exports = function () {
    var _this = this;

    var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    if (this && this.log && this.log.info) this.log.info('Adding auth seneca services');
    var deserializeUser = options.deserializeUser;

    if (!deserializeUser) throw new Error('The deserializeUser option must be defined');
    if (!options.app_tokens && !options.redis_client) throw new Error('The redis_client options must be defined');

    var _ref = options.app_tokens || require('./app_tokens')({ log: this.log, redis_client: options.redis_client }),
        userScopesByToken = _ref.userScopesByToken;

    this.add({
        role: 'identity',
        action: 'verify_token'
    }, function (msg, respond) {
        var token = msg.token;

        var response = {};
        userScopesByToken(token).then(function (tokenData) {
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