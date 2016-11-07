/**
 * Created by pfbongio on 11/10/2016.
 */

'use strict';

function _toConsumableArray(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } else { return Array.from(arr); } }

var crypto = require('crypto');

var APP_TOKEN_EXPIRATION_SECONDS = 3600;

function _token2UserScopeKey(token) {
    return token ? 'TOKEN_2_UID_SCOPE_' + token : null;
}

/**
 * The module epxorts two functions, createAppToken, to create a cryptographically secure random token,
 * that expires by default after an hour, and a function userScopesByToken that retrieves the token
 * if it still exists.
 *
 * The options passed when initializing the module are:
 *
 *
 * @param options is a optional options object which understands:
 *  * redisClient a redis client to be used instead of the default one
 *  * log a bunyan style log object instead of the standard one
 *  * expirationSeconds to change the default expiry of the application token
 *
 * @returns {{createAppToken: (function(*=, *)), userScopesByToken: (function(*=))}}
 */

module.exports = function () {
    var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    var redisClient = options.redis_client;
    var log = options.log;
    var expirationSeconds = options.expiration_seconds || APP_TOKEN_EXPIRATION_SECONDS;

    return {

        createAppToken: function createAppToken(userId, scopes) {
            var p = new Promise(function (resolve, reject) {
                try {
                    (function () {
                        var token = crypto.randomBytes(256).toString('base64');
                        var tokenKey = _token2UserScopeKey(token);
                        if (!tokenKey) throw new Error('Incorrect token key');

                        var tokenData = {
                            token: token,
                            expires_in_s: expirationSeconds
                        };
                        resolve(Promise.all([redisClient.rpush.apply(redisClient, [tokenKey, userId].concat(_toConsumableArray(scopes))), redisClient.expire(tokenKey, expirationSeconds)]).then(function (results) {
                            return tokenData;
                        }));
                    })();
                } catch (err) {
                    log.error(err, 'Unable to create application token');
                    reject('Unable to create application tokent');
                }
            });
            return p;
        },

        userScopesByToken: function userScopesByToken(token) {
            var p = new Promise(function (resolve, reject) {
                try {
                    var tokenKey = _token2UserScopeKey(token);
                    if (!tokenKey) {
                        reject('Incorrect token');
                        return;
                    }
                    var q = redisClient.lrange(tokenKey, 0, -1).then(function (values) {
                        if (!values || values.length < 2) throw new Error('Incorrect values returned');
                        return {
                            user_id: values[0],
                            scopes: values.slice(1)
                        };
                    });
                    resolve(q);
                } catch (err) {
                    log.error(err, 'Error while validating the provided token');
                    reject('Error while validating the provided token');
                }
            });
            return p;
        }
    };
};