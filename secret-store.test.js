import '@shgysk8zer0/polyfills';

import { generateSecretKey } from '@shgysk8zer0/aes-gcm';
import { useSecretStore, openSecretStoreFile } from './secret-store.js';
import { test, describe } from 'node:test';
import { strictEqual, deepEqual, throws, rejects, doesNotReject, ok, notStrictEqual } from 'node:assert';
import { readFile } from 'node:fs/promises';

async function getKey({ signal } = {}) {
	const keyData = await readFile('key.jwk', { encoding: 'utf8', signal });
	return await crypto.subtle.importKey('jwk', JSON.parse(keyData), 'AES-GCM', false, ['decrypt', 'encrypt']);
}

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

	test('Check file version of secret store', async () => {
		const key = await getKey();
		const [store] = await openSecretStoreFile(key, 'secrets.json');
		strictEqual(await store.msg, 'Hello, World!', 'Should open secrets file and decrypt correctly.');

		rejects(() => openSecretStoreFile([]), 'Should reject when not given a `CryptoKey`.');
		rejects(() => openSecretStoreFile(key, []), 'Should reject when not given a string for a file path.');
		rejects(() => openSecretStoreFile(key, 'secrets.json', { signal: AbortSignal.abort('Make me fail!')}), 'Should reject when given an aborted `AbortSignal`.');
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
