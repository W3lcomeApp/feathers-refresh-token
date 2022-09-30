import { HookContext, Application } from '@feathersjs/feathers';
import Debug from 'debug';
import { defaultOptions, RefreshTokenOptions, RefreshTokenData } from './core';

const debug = Debug('feathers-refresh-token');
let refreshTokenOptions: RefreshTokenOptions | null = null;

/*
 * Return refresh-tokens all depending options
 */
export const loadConfig = (app: Application) => {
  // refresn token options already loaded, simply return
  if (refreshTokenOptions) {
    return refreshTokenOptions;
  }
  // get default authentication key
  const defaultAuthKey = app.get('defaultAuthentication');
  const {
    entity: userEntity, // The name of the field that will contain the entity after successful authentication
    entityId: userEntityId, //T he id property of an entity object
    service: userService, // The path of the entity service
    'refresh-token': config
  } = app.get(defaultAuthKey);

  if (!userEntity || !defaultAuthKey || !app.service(userService)) {
    throw new Error(`Invalid authentication service configuration!`);
  }

  debug(
    `Default authentication key and config:`,
    defaultAuthKey,
    app.get(defaultAuthKey)
  );

  // merge default options and options loaded from config
  const finalOptions: RefreshTokenOptions = {
    ...defaultOptions,
    authService: defaultAuthKey, // authentication service
    userEntityId: userEntityId ? userEntityId : app.service(userService).id, // user entity ID
    userEntity, // user entity
    ...config
  };

  debug(`Returning final options for refresh token`, finalOptions);

  if (!app.service(finalOptions.service)) {
    throw new Error(
      `Missing refresh-token entity service. Make sure refresh-tokens servie is configured properly.`
    );
  }

  refreshTokenOptions = finalOptions;

  return finalOptions;
};

/*
 *
 * Return an existing refresh-token
 * context: Hook context
 * config: Refresh-token config options
 * params: query conditions
 */
export const lookupRefreshTokenId = async (
  context: HookContext,
  config: RefreshTokenOptions,
  params: Partial<RefreshTokenData>
): Promise<string | null> => {
  const { existingToken } = await lookupRefreshToken(context, config, params);

  if (!existingToken) {
    return null;
  }

  debug('Find existing refresh token result', existingToken);

  const { entityId, service } = config;
  // ! this is refresh token ID in database, not user ID
  const tokenEntityId: 'id' | '_id' = entityId
    ? entityId
    : context.app.service(service).id;

  debug(`tokenEntityId: ${tokenEntityId}`);

  const { [tokenEntityId]: tokenId } = existingToken;

  // tokenId could be 0
  if (tokenId === null || tokenId === undefined) {
    throw new Error('Invalid refresh token!');
  }
  debug('refresh-token Id', tokenId);

  // set context ID to refresh token ID to delete it from DB
  return tokenId;
};

/*
 *
 * Return an valid existing refresh-token
 * context: Hook context
 * config: Refresh-token config options
 * params: query conditions
 */
export const lookupRefreshToken = async (
  context: HookContext,
  config: RefreshTokenOptions,
  params: Partial<RefreshTokenData>
): Promise<{ existingToken: RefreshTokenData | null; verifyResult: any }> => {
  const { app } = context;

  const { userId, deviceId, isValid, refreshToken } = params;

  if (!userId) {
    throw new Error(`userId is mandatory for querying refresh-token`);
  }

  const { service, authService, jwtOptions, secret } = config;

  let query: Partial<RefreshTokenData> = {
    userId: `${userId}`,
    isValid: isValid ? isValid : true
  };

  if (refreshToken) {
    query = {
      ...query,
      refreshToken
    };
  }

  if (deviceId) {
    query = {
      ...query,
      deviceId
    };
  }
  const existingToken = await app.service(service).find({
    query
  });
  debug(`Refresh token lookup result: `, existingToken);

  let data: RefreshTokenData | null = null;
  if (Array.isArray(existingToken) && existingToken.length > 0) {
    data = existingToken[0];
  } else if (existingToken && existingToken.total > 0 && existingToken.data) {
    data = existingToken.data[0];
  } else {
    data = existingToken;
  }

  if (!data || !data.refreshToken) {
    return { existingToken: null, verifyResult: null };
  }
  // ! verify refresh-token before returning
  try {
    const verifyResult = await app.service(authService).verifyAccessToken(
      data.refreshToken,
      jwtOptions, // refresh token options
      secret // refresh token secret, should be different than access token
    );
    
    if (!verifyResult) {
      throw new Error('Invalid refresh-token!');
    }

    return { existingToken: data, verifyResult };
  } catch (error) {
    // refresh token is invalid
    await app.service(service).patch(data.id, {
      isValid: false
    });
    return { existingToken: null, verifyResult: null };
  }
};
