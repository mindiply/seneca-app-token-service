/**
 * Created by pfbongio on 11/10/2016.
 */

'use strict'

let crypto = require('crypto')

const APP_TOKEN_EXPIRATION_SECONDS = 3600

function _token2UserScopeKey (token) {
    return token ? 'TOKEN_2_UID_SCOPE_' + token : null
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

module.exports = (options = {}) => {
    let redisClient = options.redis_client
    let log = options.log
    let expirationSeconds = options.expiration_seconds || APP_TOKEN_EXPIRATION_SECONDS

    return {

        createAppToken: (userId, scopes) => {
            let p = new Promise((resolve, reject) => {
                try {
                    let token = crypto.randomBytes(256).toString('base64')
                    let tokenKey = _token2UserScopeKey(token)
                    if (!tokenKey) throw new Error('Incorrect token key')

                    let tokenData = {
                        token,
                        expires_in_s: expirationSeconds
                    }
                    resolve(Promise.all([
                        redisClient.rpush(tokenKey, userId, ...scopes),
                        redisClient.expire(tokenKey, expirationSeconds)
                    ]).then(results => {
                        return tokenData
                    }))
                } catch (err) {
                    log.error(err, 'Unable to create application token')
                    reject('Unable to create application tokent')
                }
            })
            return p
        },

        userScopesByToken: (token) => {
            let p = new Promise((resolve, reject) => {
                try {
                    let tokenKey = _token2UserScopeKey(token)
                    if (!tokenKey) {
                        reject('Incorrect token')
                        return
                    }
                    let q = redisClient.lrange(tokenKey, 0, -1)
                        .then(values => {
                            if (!values || values.length < 2) throw new Error('Incorrect values returned')
                            return {
                                user_id: values[0],
                                scopes: values.slice(1)
                            }
                        })
                    resolve(q)
                } catch (err) {
                    log.error(err, 'Error while validating the provided token')
                    reject('Error while validating the provided token')
                }
            })
            return p
        }
    }
}
