import { NotAuthenticated, BadRequest } from '@feathersjs/errors';
import { Hook, HookContext, Service } from '@feathersjs/feathers';
import Debug from 'debug';

import { lookupRefreshTokenId, loadConfig } from './common';
import { Application } from '../declarations';
import { RefreshTokenData } from './core';

const debug = Debug('feathers-refresh-token');

/*
 * Revoke refresh-token by set isValid to false, it must be a protected route
 * params.user must be populated with user entity
 */
export const revokeRefreshToken = () => {
  return async (context: HookContext) => {
    const { data, app, method, type, params } = context;
    const config = loadConfig(app as Application);

    if (method !== 'patch') {
      throw new Error(
        `revokeRefreshToken hook must be used with patch method!`
      );
    }
    // for internal call, simply return context
    if (!params.provider) {
      debug('Internal API call for refresh token, simply return context');
      return context;
    }

    //revoke refresh Token only valid for before token and called from external
    if (type !== 'before') {
      throw new Error(
        'Revoke refresh token hook must be used with before token'
      );
    }

    // ! user must be authenticated
    const { entity, userEntityId } = config;
    const { user } = params;

    debug('Revoke refresh-token for user', user);

    if (!user?.[userEntityId]) {
      throw new Error(`Invalid query strings or user is not authenticated!`);
    }

    //! validating user input
    [entity].forEach((p) => {
      if (p in data) return;
      throw new BadRequest(`${p} is missing from request`);
    });

    const existingTokenId = await lookupRefreshTokenId(context, config, {
      userId: `${user[userEntityId]}`,
      refreshToken: data[entity]
    });

    debug('Find existing refresh token result', existingTokenId);
    // Refresh token exists
    if (existingTokenId === null) {
      throw new NotAuthenticated();
    }

    context.id = existingTokenId;
    context.data = { isValid: false };
    return context;
  };
};
