import { test } from 'tap';
import AssertionRequestOptionsBuilder from '../../src/assertion/requestOptionsBuilder';
import crypto from 'crypto';
import str2ab from 'str2ab';
import FslValidationError from '../../src/error/validationError';

test('# AssertionRequestOptionsBuilder', (t) => {
  t.test('## constructor', (t) => {
    t.test('### constructor', (t) => {
      const arob = new AssertionRequestOptionsBuilder({
        challenge: str2ab.buffer2arraybuffer(crypto.randomBytes(32)),
        timeout: 60000,
        rpId: 'fido2.example.com',
        allowCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(crypto.randomBytes(8)),
            transports: ['usb'],
          },
        ],
        userVerification: 'required',
        extensions: {
          uvm: true,
        },
      });

      t.notSame(arob, null);
      t.end();
    });

    t.end();
  });

  t.test('## build', (t) => {
    t.test('### build', (t) => {
      const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(32));
      const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
      const arob = new AssertionRequestOptionsBuilder({
        challenge,
        timeout: 120000,
        rpId: 'fido2.example.com',
        allowCredentials: [
          {
            type: 'public-key',
            id: allowCredentialsId,
            transports: ['usb'],
          },
        ],
        userVerification: 'required',
        extensions: {
          uvm: true,
        },
      });

      const options = arob.build();

      t.equal(options.challenge, challenge);
      t.equal(options.timeout, 120000);
      t.equal(options.rpId, 'fido2.example.com');
      t.same(options.allowCredentials, [
        {
          type: 'public-key',
          id: allowCredentialsId,
          transports: ['usb'],
        },
      ]);
      t.equal(options.userVerification, 'required');
      t.same(options.extensions, {
        uvm: true,
      });
      t.end();
    });

    t.end();
  });

  t.test('## buildEncode', (t) => {
    t.test('### buildEncode', (t) => {
      const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(32));
      const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
      const arob = new AssertionRequestOptionsBuilder({
        challenge,
        timeout: 120000,
        rpId: 'fido2.example.com',
        allowCredentials: [
          {
            type: 'public-key',
            id: allowCredentialsId,
            transports: ['usb'],
          },
        ],
        userVerification: 'required',
        extensions: {
          uvm: true,
        },
      });

      const options = arob.buildEncode();

      t.equal(options.challenge, str2ab.arraybuffer2base64url(challenge));
      t.equal(options.timeout, 120000);
      t.equal(options.rpId, 'fido2.example.com');
      t.same(options.allowCredentials, [
        {
          type: 'public-key',
          id: str2ab.arraybuffer2base64url(allowCredentialsId),
          transports: ['usb'],
        },
      ]);
      t.equal(options.userVerification, 'required');
      t.same(options.extensions, {
        uvm: true,
      });
      t.end();
    });

    t.end();
  });

  t.test('## easyCreate', (t) => {
    t.test('### Simple', (t) => {
      const arob = AssertionRequestOptionsBuilder.easyCreate({});
      const options = arob.build();

      t.notSame(arob, null);
      t.equal(options.challenge.byteLength, 64);
      t.equal(options.timeout, 60000);
      t.equal(options.rpId, 'localhost');
      t.same(options.allowCredentials, undefined);
      t.equal(options.userVerification, undefined);
      t.same(options.extensions, undefined);
      t.end();
    });

    t.test('### Full', (t) => {
      const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(32));
      const arob = AssertionRequestOptionsBuilder.easyCreate({
        challenge,
        timeout: 120000,
        rpId: 'fido2.example.com',
        userVerification: 'required',
      });
      const options = arob.build();

      t.notSame(arob, null);
      t.equal(options.challenge, challenge);
      t.equal(options.timeout, 120000);
      t.equal(options.rpId, 'fido2.example.com');
      t.same(options.allowCredentials, undefined);
      t.equal(options.userVerification, 'required');
      t.same(options.extensions, undefined);
      t.end();
    });

    t.end();
  });

  t.test('## timeout', (t) => {
    t.test('### timeout', (t) => {
      const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(32));
      const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
      const arob = new AssertionRequestOptionsBuilder({
        challenge,
        timeout: 120000,
        rpId: 'fido2.example.com',
        allowCredentials: [
          {
            type: 'public-key',
            id: allowCredentialsId,
            transports: ['usb'],
          },
        ],
        userVerification: 'required',
        extensions: {
          uvm: true,
        },
      });
      const options = arob.timeout(100).build();

      t.equal(options.challenge, challenge);
      t.equal(options.timeout, 100);
      t.equal(options.rpId, 'fido2.example.com');
      t.same(options.allowCredentials, [
        {
          type: 'public-key',
          id: allowCredentialsId,
          transports: ['usb'],
        },
      ]);
      t.equal(options.userVerification, 'required');
      t.same(options.extensions, {
        uvm: true,
      });

      t.end();
    });

    t.end();
  });

  t.test('## rpId', (t) => {
    t.test('### rpId', (t) => {
      const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(32));
      const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
      const arob = new AssertionRequestOptionsBuilder({
        challenge,
        timeout: 120000,
        rpId: 'fido2.example.com',
        allowCredentials: [
          {
            type: 'public-key',
            id: allowCredentialsId,
            transports: ['usb'],
          },
        ],
        userVerification: 'required',
        extensions: {
          uvm: true,
        },
      });
      const options = arob.rpId('new.example.co.jp').build();

      t.equal(options.challenge, challenge);
      t.equal(options.timeout, 120000);
      t.equal(options.rpId, 'new.example.co.jp');
      t.same(options.allowCredentials, [
        {
          type: 'public-key',
          id: allowCredentialsId,
          transports: ['usb'],
        },
      ]);
      t.equal(options.userVerification, 'required');
      t.same(options.extensions, {
        uvm: true,
      });
      t.end();
    });

    t.end();
  });

  t.test('## allowCredentials', (t) => {
    t.test('### allowCredentials', (t) => {
      const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(32));
      const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
      const newAllowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
      const arob = new AssertionRequestOptionsBuilder({
        challenge,
        timeout: 120000,
        rpId: 'fido2.example.com',
        allowCredentials: [
          {
            type: 'public-key',
            id: allowCredentialsId,
            transports: ['usb'],
          },
        ],
        userVerification: 'required',
        extensions: {
          uvm: true,
        },
      });
      const options = arob
        .allowCredentials([
          {
            type: 'public-key',
            id: newAllowCredentialsId,
            transports: ['internal'],
          },
        ])
        .build();

      t.equal(options.challenge, challenge);
      t.equal(options.timeout, 120000);
      t.equal(options.rpId, 'fido2.example.com');
      t.same(options.allowCredentials, [
        {
          type: 'public-key',
          id: newAllowCredentialsId,
          transports: ['internal'],
        },
      ]);
      t.equal(options.userVerification, 'required');
      t.same(options.extensions, {
        uvm: true,
      });
      t.end();
    });
    t.end();
  });

  t.test('## userVerification', (t) => {
    t.test('### userVerification', (t) => {
      const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(32));
      const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
      const arob = new AssertionRequestOptionsBuilder({
        challenge,
        timeout: 120000,
        rpId: 'fido2.example.com',
        allowCredentials: [
          {
            type: 'public-key',
            id: allowCredentialsId,
            transports: ['usb'],
          },
        ],
        userVerification: 'required',
        extensions: {
          uvm: true,
        },
      });
      const options = arob.userVerification('discouraged').build();

      t.equal(options.challenge, challenge);
      t.equal(options.timeout, 120000);
      t.equal(options.rpId, 'fido2.example.com');
      t.same(options.allowCredentials, [
        {
          type: 'public-key',
          id: allowCredentialsId,
          transports: ['usb'],
        },
      ]);
      t.equal(options.userVerification, 'discouraged');
      t.same(options.extensions, {
        uvm: true,
      });
      t.end();
    });
    t.end();
  });

  t.test('## extensions', (t) => {
    t.test('### extensions', (t) => {
      const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(32));
      const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
      const arob = new AssertionRequestOptionsBuilder({
        challenge,
        timeout: 120000,
        rpId: 'fido2.example.com',
        allowCredentials: [
          {
            type: 'public-key',
            id: allowCredentialsId,
            transports: ['usb'],
          },
        ],
        userVerification: 'required',
        extensions: {
          uvm: true,
        },
      });
      const options = arob
        .extensions({
          uvm: false,
        })
        .build();

      t.equal(options.challenge, challenge);
      t.equal(options.timeout, 120000);
      t.equal(options.rpId, 'fido2.example.com');
      t.same(options.allowCredentials, [
        {
          type: 'public-key',
          id: allowCredentialsId,
          transports: ['usb'],
        },
      ]);
      t.equal(options.userVerification, 'required');
      t.same(options.extensions, {
        uvm: false,
      });
      t.end();
    });
    t.end();
  });

  t.test('## validate', (t) => {
    t.test('### valid', (t) => {
      const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(16));
      const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
      const arob = new AssertionRequestOptionsBuilder({
        challenge,
        timeout: 1,
        rpId: 'fido2.example.com',
        allowCredentials: [
          {
            type: 'public-key',
            id: allowCredentialsId,
          },
        ],
        userVerification: 'discouraged',
        extensions: {
          uvm: true,
        },
      });
      const isValid = arob.validate();
      t.ok(isValid);
      t.end();
    });

    t.test('### valid', (t) => {
      const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(16));
      const arob = new AssertionRequestOptionsBuilder({
        challenge,
        allowCredentials: [],
        extensions: {},
      });
      const isValid = arob.validate();
      t.ok(isValid);
      t.end();
    });

    t.test('### timeout is negative number', (t) => {
      t.throws(
        () => {
          const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(16));
          const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
          const arob = new AssertionRequestOptionsBuilder({
            challenge,
            timeout: -1,
            rpId: 'fido2.example.com',
            allowCredentials: [
              {
                type: 'public-key',
                id: allowCredentialsId,
                transports: ['usb'],
              },
            ],
            userVerification: 'required',
            extensions: {
              uvm: true,
            },
          });
          arob.validate();
        },
        FslValidationError,
        'PublicKeyCredentialRequestOptions.timeout should be more than 0.'
      );
      t.end();
    });

    t.test('### challenge is less than 16 bytes', (t) => {
      t.throws(
        () => {
          const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(15));
          const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
          const arob = new AssertionRequestOptionsBuilder({
            challenge,
            timeout: 60000,
            rpId: 'fido2.example.com',
            allowCredentials: [
              {
                type: 'public-key',
                id: allowCredentialsId,
                transports: ['usb'],
              },
            ],
            userVerification: 'required',
            extensions: {
              uvm: true,
            },
          });
          arob.validate();
        },
        FslValidationError,
        'PublicKeyCredentialRequestOptions.challenge should be least 16 bytes.'
      );
      t.end();
    });

    t.test('### allowCredentials does not have type', (t) => {
      t.throws(
        () => {
          const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(16));
          const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
          const arob = new AssertionRequestOptionsBuilder({
            challenge,
            timeout: 60000,
            rpId: 'fido2.example.com',
            allowCredentials: [
              {
                id: allowCredentialsId,
                transports: ['usb'],
              } as any,
            ],
            userVerification: 'required',
            extensions: {
              uvm: true,
            },
          });
          arob.validate();
        },
        FslValidationError,
        'PublicKeyCredentialRequestOptions.allowCredentials is not valid.'
      );
      t.end();
    });

    t.test('### allowCredentials type is empty', (t) => {
      t.throws(
        () => {
          const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(16));
          const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
          const arob = new AssertionRequestOptionsBuilder({
            challenge,
            timeout: 60000,
            rpId: 'fido2.example.com',
            allowCredentials: [
              {
                type: '',
                id: allowCredentialsId,
                transports: ['usb'],
              } as any,
            ],
            userVerification: 'required',
            extensions: {
              uvm: true,
            },
          });
          arob.validate();
        },
        FslValidationError,
        'PublicKeyCredentialRequestOptions.allowCredentials is not valid.'
      );
      t.end();
    });

    t.test('### allowCredentials type is not public-key', (t) => {
      t.throws(
        () => {
          const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(16));
          const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
          const arob = new AssertionRequestOptionsBuilder({
            challenge,
            timeout: 60000,
            rpId: 'fido2.example.com',
            allowCredentials: [
              {
                type: 'wow',
                id: allowCredentialsId,
                transports: ['usb'],
              } as any,
            ],
            userVerification: 'required',
            extensions: {
              uvm: true,
            },
          });
          arob.validate();
        },
        FslValidationError,
        'PublicKeyCredentialRequestOptions.allowCredentials is not valid.'
      );
      t.end();
    });

    t.test('### allowCredentials does not have id', (t) => {
      t.throws(
        () => {
          const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(16));
          const arob = new AssertionRequestOptionsBuilder({
            challenge,
            timeout: 60000,
            rpId: 'fido2.example.com',
            allowCredentials: [
              {
                type: 'public-key',
                transports: ['usb'],
              } as any,
            ],
            userVerification: 'required',
            extensions: {
              uvm: true,
            },
          });
          arob.validate();
        },
        FslValidationError,
        'PublicKeyCredentialRequestOptions.allowCredentials is not valid.'
      );
      t.end();
    });

    t.test('### allowCredentials id is empty', (t) => {
      t.throws(
        () => {
          const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(16));
          const allowCredentialsId = str2ab.buffer2arraybuffer(Buffer.from([]));
          const arob = new AssertionRequestOptionsBuilder({
            challenge,
            timeout: 60000,
            rpId: 'fido2.example.com',
            allowCredentials: [
              {
                type: 'wow',
                id: allowCredentialsId,
                transports: ['usb'],
              } as any,
            ],
            userVerification: 'required',
            extensions: {
              uvm: true,
            },
          });
          arob.validate();
        },
        FslValidationError,
        'PublicKeyCredentialRequestOptions.allowCredentials is not valid.'
      );
      t.end();
    });

    t.test('### extension uvm is not boolean', (t) => {
      t.throws(
        () => {
          const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(16));
          const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
          const arob = new AssertionRequestOptionsBuilder({
            challenge,
            timeout: 1,
            rpId: 'fido2.example.com',
            allowCredentials: [
              {
                type: 'public-key',
                id: allowCredentialsId,
                transports: ['usb'],
              },
            ],
            userVerification: 'required',
            extensions: {
              uvm: 'true',
            } as any,
          });
          arob.validate();
        },
        FslValidationError,
        'PublicKeyCredentialRequestOptions.extensions is not valid: uvm is not boolean: true'
      );
      t.end();
    });

    t.test('### many errors (timeout, challenge, allowCredentials, extensions)', (t) => {
      t.throws(
        () => {
          const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(15));
          const allowCredentialsId = str2ab.buffer2arraybuffer(crypto.randomBytes(8));
          const arob = new AssertionRequestOptionsBuilder({
            challenge,
            timeout: -1,
            rpId: 'fido2.example.com',
            allowCredentials: [
              {
                type: 'pppp' as any,
                id: allowCredentialsId,
                transports: ['usb'],
              },
            ],
            userVerification: 'required',
            extensions: {
              uvm: 'false' as any,
            },
          });
          arob.validate();
        },
        FslValidationError,
        'PublicKeyCredentialRequestOptions.timeout should be more than 0. & PublicKeyCredentialRequestOptions.challenge should be least 16 bytes. & PublicKeyCredentialRequestOptions.allowCredentials is not valid. & '
      );
      t.end();
    });

    t.end();
  });

  t.end();
});
