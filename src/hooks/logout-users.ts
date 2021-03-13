import { NotAuthenticated, BadRequest } from '@feathersjs/errors';
import { Hook, HookContext, Service } from '@feathersjs/feathers';
import { lookupRefreshTokenId, loadConfig } from './common';
import Debug from 'debug';
import { Application } from '../declarations';

const debug = Debug('feathers-refresh-token');

/*
 * Logout user by deleting the refresh-token, it must be a protected route
 * params.user must be populated with user entity
 */
export const logoutUser = () => {
  return async (context: HookContext) => {
    const { app, type, method, params } = context;
    const config = loadConfig(app);
    const { entity, authService, userEntityId } = config;

    if (method !== 'remove') {
      throw new Error(`logoutUser hook must be used with remove method!`);
    }
    //refresh Token only valid for before token and called from external
    if (type === 'after') {
      debug('Logout user after delete refresh token', params);

      // ! important, have to reset the query or won't be able to find users ID
      params.query = {};
      const user = await app.service(authService).remove(null, params);
      debug('Logout user after delete refresh token', user, context.result);

      // return the result to user
      context.result = { status: 'Logout successfully' };
      return context;
    }

    const { query, user } = params;

    debug('Logout hook id and params', query, user);

    if (!query || !user?.[userEntityId]) {
      throw new Error(`Invalid query strings or user is not authenticated!`);
    }

    // ! must provide current refreshToken in query and user Id to logout
    if (!query[entity]) throw new BadRequest(`Bad request`);

    const existingTokenId = await lookupRefreshTokenId(context, config, {
      userId: user[userEntityId],
      refreshToken: query[entity]
    });

    debug('Find existing refresh token result', existingTokenId);

    if (existingTokenId === null) {
      throw new NotAuthenticated();
    }
    // set context ID to refresh token ID to delete it from DB
    context.id = existingTokenId;
    return context;
  };
};
