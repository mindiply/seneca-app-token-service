/**
 * Created by pfbongio on 11/10/2016.
 */
'use strict'

module.exports = function (options = {}) {
    if (this && this.log && this.log.info) this.log.info('Adding auth seneca services')
    let {deserializeUser} = options
    if (!deserializeUser) throw new Error('The deserializeUser option must be defined')
    if (!options.app_tokens && !options.redis_client) throw new Error('The redis_client options must be defined')
    let {userScopesByToken} = options.app_tokens || (require('./app_tokens')({log: this.log, redis_client: options.redis_client}))

    this.add({
        role: 'identity',
        action: 'verify_token'
    }, (msg, respond) => {
        let { token } = msg
        let response = {}
        userScopesByToken(token)
            .then(tokenData => {
                if (!tokenData || !tokenData.scopes || !tokenData.user_id) throw new Error('No valid token data found')
                response.scopes = tokenData.scopes
                return deserializeUser(tokenData.user_id)
            })
            .then(user => {
                if (!user) throw new Error('User not found')
                Object.assign(response, {
                    result: 'ok',
                    user: user
                })
                respond(null, response)
            })
            .catch(err => {
                this.log.warn('Unable to authenticate a app token: ' + err)
                respond(null, {
                    result: 'error',
                    details: String(err)
                })
            })
    })
    return 'TokenIdentityService'
}
