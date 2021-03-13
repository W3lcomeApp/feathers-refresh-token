import { HookContext } from '@feathersjs/feathers';
import { lookupRefreshToken, loadConfig } from './common';
import Debug from 'debug';
import { Application } from '../declarations';
import { RefreshTokenData } from './core';

const debug = Debug('feathers-refresh-token');

// After hook with authentication service
// result - authResult which will return to user, contains access token, sub and strategy

export const issueRefreshToken = () => {
  return async (context: HookContext) => {
    const { app, data, result, method } = context;
    const config = loadConfig(app as Application);

    if (method !== 'create') {
      throw new Error(
        'refreshAccessToken hook must be used with create method!'
      );
    }

    debug(`Issue Refresh token with auth result`, result);

    const {
      entity,
      service,
      userEntity,
      userEntityId,
      authService,
      jwtOptions,
      secret
    } = config;

    let userId: string;
    let user = result[userEntity];

    if (user) {
      userId = user[userEntityId];
    } else if (userEntityId in result) {
      userId = result[userEntityId];
    } else {
      // userIdField must be presented in result
      debug(`${userEntityId} doesn't exist in auth result`, result);
      throw new Error(`Could not find userId`);
    }

    // ! get the deviceId from client
    const { deviceId } = data;
    let query: Partial<RefreshTokenData> = {
      userId
    };
    if (deviceId) {
      query = { ...query, deviceId };
    }
    const { existingToken } = await lookupRefreshToken(context, config, query);

    debug(`existing token`, existingToken);

    // ! if refresh token already exists, simply return
    if (existingToken) {
      Object.assign(result, { [entity]: existingToken['refreshToken'] });
      return context;
    }

    // ! no refresh-token created yet, need to generate a new refresh-token for this login
    // Use authentication service to generate the refresh token with user ID
    const refreshToken = await app.service(authService).createAccessToken(
      {
        sub: `${userId}` // refresh token subject is set to user ID
      },
      jwtOptions, // refresh token options
      secret // refresh token secret, should be different than access token
    );

    let refreshTokenData: RefreshTokenData = {
      refreshToken,
      userId: `${userId}`,
      isValid: true
    };

    // ! get the deviceId from client
    if (data?.deviceId) {
      refreshTokenData = {
        ...refreshTokenData,
        deviceId: data.deviceId
      };
    }
    // save the refresh token ID
    const token = await app.service(service).create(refreshTokenData);

    debug(`Token ID and refresh token`, token, refreshToken);

    // return refresh token in result
    Object.assign(result, { [entity]: refreshToken });

    return context;
  };
};
