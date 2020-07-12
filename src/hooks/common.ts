import { HookContext, Application } from '@feathersjs/feathers';
import Debug from 'debug';
const debug = Debug('autohomekeeper');

const defaultOptions = {
  service: 'refresh-tokens',
  authService: 'authentication',
  entity: 'refreshToken',
  userIdField: '_id',
  subField: 'sub',
  secret: 'super secret',
  options: {
    header: {
      typ: 'refresh',
    },
    audience: 'https://example.com',
    issuer: 'example',
    algorithm: 'HS256',
  },
};

export const loadConfig = (app: Application) => {
  const { 'refresh-token': config } = app.get('authentication');

  debug(`Refresh token config from config file`, config);
  // merge default options and options loaded from config
  const finalOptions = {
    ...defaultOptions,
    ...config,
  };

  debug(`Returning final options for refresh token`, finalOptions);
  return finalOptions;
};

// used this hook with authentication service
export const lookupRefreshToken = async (
  context: HookContext,
  userId: string,
  refreshToken?: string
) => {
  const { app } = context;
  const config = loadConfig(app);
  const { entity, userIdField } = config;
  const entityService = app.service(config.service);

  let query = {
    [userIdField]: userId,
    isValid: true,
  };
  if (refreshToken) {
    query = {
      ...query,
      [entity]: refreshToken,
    };
  }

  const existingToken = await entityService.find({
    query,
  });

  debug(`Refresh token lookup result %O`, existingToken);

  if (existingToken.total > 0) {
    const data = existingToken.data[0];
    return data;
  }
  return null;
};
