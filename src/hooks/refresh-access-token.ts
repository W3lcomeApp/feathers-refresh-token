import { NotAuthenticated, BadRequest } from '@feathersjs/errors';
import { Hook, HookContext, Service } from '@feathersjs/feathers';
import Debug from 'debug';

import { lookupRefreshToken, loadConfig } from './common';
import { Application } from '../declarations';
import { RefreshTokenData } from './core';

const debug = Debug('feathers-refresh-token');

/* Before create hook refresh token service to refresh access token
 * data: post data with userId and refresh token
 * this hook must be un-protected because when client call refresh-access-token API existing
 * access-token already expired.
 */
export const refreshAccessToken = () => {
  return async (context: HookContext) => {
    const { data, app, type, params, method } = context;
    const config = loadConfig(app as Application);

    if (method !== 'create') {
      throw new Error(
        'refreshAccessToken hook must be used with create method!'
      );
    }
    //refresh Token only valid for before token and called from external
    if (type !== 'before') {
      throw new Error('refreshAccessToken hook must be used with before hook');
    }

    // for internal call, simply return context
    if (!params.provider) {
      debug('Internal API call for refresh token, simply return context');
      return context;
    }

    const { entity, userEntityId, authService } = config;
    //! validating user input
    [entity, userEntityId].forEach((p) => {
      if (p in data) return;
      throw new BadRequest(`${p} is missing from request`);
    });

    const {
      existingToken,
      verifyResult: tokenVerifyResult
    } = await lookupRefreshToken(context, config, {
      userId: data[userEntityId],
      refreshToken: data[entity]
    });

    debug('Find existing refresh token result', existingToken);

    // Refresh token not exists
    if (!existingToken) {
      throw new NotAuthenticated();
    }

    // Input data[userIdFiled] must match the sub in Refresh Token
    if (`${tokenVerifyResult.sub}` !== `${data[userEntityId]}`) {
      console.log(params);
      throw new Error(`Invalid token`);
    }

    debug('Creating new access token');

    // ! create new access token with default jwtOptions and secret
    const accessToken = await app!.service(authService)?.createAccessToken({
      sub: data[userEntityId]
    });

    debug('Issued new access token', accessToken);

    // return new access token
    context.result = {
      accessToken
    };
    return context;
  };
};
