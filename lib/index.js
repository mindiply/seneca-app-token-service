'use strict';

/**
 * Created by pfbongio on 25/10/2016.
 */

var senecaIdentityService = require('./identity_service');
var appTokens = require('./app_tokens');

module.exports = {
  senecaIdentityService: senecaIdentityService,
  appTokens: appTokens
};