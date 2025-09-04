import '@shgysk8zer0/polyfills';

import { generateSecretKey } from '@shgysk8zer0/aes-gcm';
import { useSecretStore } from './secret-store.js';
import { test, describe } from 'node:test';
import { strictEqual, deepEqual, throws, rejects, doesNotReject, ok, notStrictEqual } from 'node:assert';

describe('Test encrypted storage', async () => {
	test('Check the things', async () => {
		const { resolve, promise, reject } = Promise.withResolvers();
		const data = {};
		const key = await generateSecretKey();
		const [store, set] = useSecretStore(key, { num: '42' });
		const [proxy, setter] = useSecretStore(key, data, {
			get(target, prop) {
				return data[prop];
			}
		});

		await set('foo', 'bar');
		await setter('test', 'works');
		proxy.foo = 'bar';
		// Cannot call setter asyncronously, so...
		setTimeout(async () => {
			try {
				strictEqual(await proxy.foo, 'bar');
				notStrictEqual(data.foo, 'bar');
				resolve();
			} catch(err) {
				reject(err);
			}
		}, 100);

		rejects(() => store.num, 'Should throw for unencrypted data.');
		rejects(() => set('invalid', Symbol('Not allowed')), 'Should throw when setting invalid data.');
		ok('foo' in store, 'Store should have `foo` property set.');
		deepEqual(Object.keys(store), ['num', 'foo'], 'Should have keys set correctly.');
		strictEqual(await store.dne, null, 'Missing properties should return null.');
		strictEqual(await store.foo, 'bar', 'Data should encrypt & decrypt correctly.');
		strictEqual(await proxy.test, 'works');
		await promise;
	});

	test('Check for things that should error.', async () => {
		const encryptKey = await generateSecretKey({ usages: ['encrypt'] });
		const decryptKey = await generateSecretKey({ usages: ['decrypt'] });
		const key = await generateSecretKey();
		const [store, set] = useSecretStore(decryptKey);

		throws(() => useSecretStore({}, {}), 'Should throw when key is not a `CryptoKey`.');
		throws (() => useSecretStore(encryptKey, {}), 'Should required a key with decrypt usages.');
		throws(() => useSecretStore(key, false), 'Should require an object as data source.');
		await doesNotReject(() => store.foo, 'Should not reject when key only supports decryption.');
		await rejects(Promise.try(set, 'fail', 'Does not support encryption.'), 'Should reject on setting when key does not support encryption.');
	});
});
