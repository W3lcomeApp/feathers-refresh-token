import assert from 'assert';
import jwt from 'jsonwebtoken';
import feathers, { Application, Service } from '@feathersjs/feathers';
// @ts-ignore
import memory from 'feathers-memory';
import {
  AuthenticationService,
  AuthenticationResult,
  hooks
} from '@feathersjs/authentication';
import { Strategy1 } from './fixtures';

import {
  issueRefreshToken,
  refreshAccessToken,
  revokeRefreshToken,
  logoutUser
} from '../src';

const { authenticate } = hooks;

describe('refresh-token-hooks', () => {
  // refresh-token is stateful service, needs to keep the state and follow certain order for testing
  let refreshToken: string;
  let accessToken: string;
  let userId: string;
  let params: any;

  let app: Application<{
    authentication: AuthenticationService & Service<AuthenticationResult>;
    users: Service<any>;
    'refresh-tokens': Service<any>;
  }>;

  // init the state of refresh-token
  before(() => {
    app = feathers();
    app.use(
      '/authentication',
      new AuthenticationService(app, 'authentication', {
        entity: 'user',
        service: 'users',
        secret: 'supersecret',
        authStrategies: ['first'],
        'refresh-token': {
          secret: 'super secret',
          service: 'refresh-tokens',
          entity: 'refreshToken',
          jwtOptions: {
            header: { typ: 'refresh' }, // default type: refresh
            audience: 'https://yourdomain.com', // The resource server where the token is processed
            issuer: 'feathers', // The issuing server, application or resource
            algorithm: 'HS256',
            expiresIn: '360d' // default expiration settings after 360 days
          }
        }
      })
    );
    app.use(
      '/users',
      memory({
        multi: true
      })
    );
    app.use(
      '/refresh-tokens',
      memory({
        multi: true
      })
    );
    app.service('refresh-tokens').hooks({
      before: {
        create: [refreshAccessToken()],
        update: [refreshAccessToken(), revokeRefreshToken(), logoutUser()],
        patch: [authenticate('first'), revokeRefreshToken()],
        remove: [authenticate('first'), logoutUser()]
      },

      after: {
        remove: [logoutUser()]
      }
    });

    app.service('authentication').register('first', new Strategy1());
    app.service('authentication').hooks({
      after: {
        create: [issueRefreshToken()]
      }
    });
  });

  describe('create refresh-token', () => {
    it('creates a valid accessToken and refreshToken', async () => {
      const service = app.service('authentication');
      const result = await service.create({
        strategy: 'first',
        username: 'David',
        deviceId: 'device1'
      });

      params = { ...result, provider: 'rest' };

      const refreshTokenSettings =
        service.configuration['refresh-token'].jwtOptions;
      const refreshTokenDecoded = jwt.decode(result.refreshToken);

      if (typeof refreshTokenDecoded === 'string') {
        throw new Error('Unexpected decoded refresh-token JWT type');
      }

      refreshToken = result?.refreshToken;
      accessToken = result?.accessToken;
      userId = result?.user?.id;

      assert.ok(result.refreshToken);
      assert.strictEqual(
        refreshTokenDecoded!.aud,
        refreshTokenSettings.audience
      );
      assert.strictEqual(refreshTokenDecoded!.iss, refreshTokenSettings.issuer);
    });

    it('creates a valid accessToken and refreshToken', async () => {
      const service = app.service('authentication');
      const result = await service.create({
        strategy: 'first',
        username: 'Jacky',
        deviceId: 'device2'
      });

      const refreshTokenSettings =
        service.configuration['refresh-token'].jwtOptions;
      const refreshTokenDecoded = jwt.decode(result.refreshToken);

      if (typeof refreshTokenDecoded === 'string') {
        throw new Error('Unexpected decoded refresh-token JWT type');
      }

      assert.ok(result.refreshToken);
      assert.strictEqual(
        refreshTokenDecoded!.aud,
        refreshTokenSettings.audience
      );
      assert.strictEqual(refreshTokenDecoded!.iss, refreshTokenSettings.issuer);
    });

    it('authentication with invalid username', async () => {
      try {
        const service = app.service('authentication');
        await service.create({
          strategy: 'first',
          username: 'other'
        });
        assert.fail('Should never get here');
      } catch (error) {
        assert.strictEqual(error.message, 'Could not find userId');
      }
    });
  });

  describe('create refresh-token with same user', () => {
    it('issue same refreshToken and a different accessToken', async () => {
      const service = app.service('authentication');
      const result = await service.create({
        strategy: 'first',
        username: 'David',
        deviceId: 'device1'
      });

      const refreshTokenDecoded = jwt.decode(result.refreshToken);

      if (typeof refreshTokenDecoded === 'string') {
        throw new Error('Unexpected decoded refresh-token JWT type');
      }

      assert.ok(result.refreshToken);
      assert.strictEqual(result.refreshToken, refreshToken);
      assert.strictEqual(result.user.id, userId);
      assert.notEqual(result.accessToken, accessToken);
    });
  });

  describe('create refresh-token on second device with same user', () => {
    it('issue different refreshToken on different device', async () => {
      const service = app.service('authentication');
      const result = await service.create({
        strategy: 'first',
        username: 'David',
        deviceId: 'device2'
      });

      const refreshTokenDecoded = jwt.decode(result.refreshToken);

      if (typeof refreshTokenDecoded === 'string') {
        throw new Error('Unexpected decoded refresh-token JWT type');
      }

      assert.ok(result.refreshToken);
      assert.strictEqual(result.user.id, userId);
      assert.notStrictEqual(result.refreshToken, refreshToken);
      assert.notStrictEqual(result.accessToken, accessToken);
    });
  });

  describe('refresh access-token', () => {
    it('cannot refresh access-token with invalid refresh-token', async () => {
      try {
        const result = await app.service('refresh-tokens').create(
          {
            id: userId,
            refreshToken: 'somevalue'
          },
          params
        );
        assert.fail('Should never get here');
      } catch (error) {
        assert.strictEqual(error.message, 'Error');
      }
    });

    it('can refresh access-token with valid refresh-token', async () => {
      const authResult = await app.service('refresh-tokens').create(
        {
          id: userId,
          refreshToken
        },
        params
      );
      assert.notStrictEqual(authResult.accessToken, accessToken);
    });
  });

  describe('revoke refresh-token', () => {
    it('cannot revoke invalid refresh-token', async () => {
      try {
        const result = await app.service('refresh-tokens').patch(
          null,
          {
            refreshToken: 'somevalue'
          },
          params
        );
        assert.fail('Should never get here');
      } catch (error) {
        assert.strictEqual(error.message, 'Error');
      }
    });

    it('can revoke a valid refresh-token', async () => {
      const authResult: any = await app.service('refresh-tokens').patch(
        null,
        {
          refreshToken
        },
        params
      );
      assert.strictEqual(authResult?.isValid, false);
    });
  });

  describe('logout user by removing refresh-token', () => {
    it('getting another valid refreshToken', async () => {
      const service = app.service('authentication');
      const result = await service.create({
        strategy: 'first',
        username: 'David'
      });

      params = { ...result, provider: 'rest' };

      const refreshTokenSettings =
        service.configuration['refresh-token'].jwtOptions;
      const refreshTokenDecoded = jwt.decode(result.refreshToken);

      if (typeof refreshTokenDecoded === 'string') {
        throw new Error('Unexpected decoded refresh-token JWT type');
      }

      refreshToken = result?.refreshToken;
      accessToken = result?.accessToken;
      userId = result?.user?.id;

      assert.ok(result.refreshToken);
      assert.strictEqual(
        refreshTokenDecoded!.aud,
        refreshTokenSettings.audience
      );
      assert.strictEqual(refreshTokenDecoded!.iss, refreshTokenSettings.issuer);
    });

    it('can logout user successfully', async () => {
      params.query = {
        refreshToken
      };
      const authResult = await app.service('refresh-tokens').remove(userId, {
        query: { refreshToken },
        authentication: {
          strategy: 'first',
          username: 'David'
        }
      });

      assert.deepStrictEqual(authResult, {
        status: 'Logout successfully'
      });
    });
  });

  describe('refresh access-token with deleted refresh-token', () => {
    it('cannot refresh access-token with deleted refresh-token', async () => {
      try {
        await app.service('refresh-tokens').remove(userId, {
          query: { refreshToken },
          authentication: {
            strategy: 'first',
            username: 'David'
          }
        });
        assert.fail('Should never get here');
      } catch (error) {
        assert.strictEqual(error.message, 'Error');
      }
    });
  });
});
