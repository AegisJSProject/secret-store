import { generateSecretKey } from '@shgysk8zer0/aes-gcm';
import { useSecretStore, openSecretStoreFile, openWritableSecretStoreFile } from './secret-store.js';
import { test, describe } from 'node:test';
import { strictEqual, deepEqual, throws, rejects, doesNotReject, ok, notStrictEqual } from 'node:assert';

async function getKey() {
	const keyData = await import('./key.jwk.json', { with: { type: 'json' }});
	return await crypto.subtle.importKey('jwk', keyData.default, 'AES-GCM', false, ['decrypt', 'encrypt']);
}

describe('Test encrypted storage', async () => {
	test('Check the things', async () => {
		const data = {};
		const key = await generateSecretKey();
		const [store, set] = useSecretStore(key, { num: '42' });
		const [proxy, setter, { whenWritten }] = useSecretStore(key, data, {
			get(target, prop) {
				return data[prop];
			}
		});

		await set('foo', 'bar');
		await setter('test', 'works');
		proxy.foo = 'bar';
		await whenWritten('foo');
		// Cannot call setter asyncronously, so...
		strictEqual(await proxy.foo, 'bar');
		notStrictEqual(data.foo, 'bar');

		rejects(() => store.num, 'Should throw for unencrypted data.');
		rejects(() => set('invalid', Symbol('Not allowed')), 'Should throw when setting invalid data.');
		ok('foo' in store, 'Store should have `foo` property set.');
		deepEqual(Object.keys(proxy), Object.keys(data), 'Should have keys set correctly.');
		strictEqual(await store.dne, null, 'Missing properties should return null.');
		strictEqual(await store.foo, 'bar', 'Data should encrypt & decrypt correctly.');
		strictEqual(await proxy.test, 'works');
	});

	test('Check file version of secret store', async () => {
		const key = await getKey();
		const stack = new DisposableStack();
		const [store, setter, { save, isRevoked }] = await openWritableSecretStoreFile(key, 'secrets.json', { stack });
		strictEqual(await store.msg, 'Hello, World!', 'Should open secrets file and decrypt correctly.');
		const uuid = crypto.randomUUID();
		ok(await setter('uuid', uuid), 'Successfully setting should return true.');
		await save();

		strictEqual(await store.uuid, uuid, 'Should match generated UUID.');
		stack.dispose();

		ok(isRevoked(), 'Disposing stack should revoke the proxy.');
		await rejects(async () => await store.msg, 'Revoked proxy should throw.');
		await rejects(async () => await setter('msg', 'Invalid'), 'Revoked proxy should throw.');
		await rejects(() => openSecretStoreFile([]), 'Should reject when not given a `CryptoKey`.');
		await rejects(() => openSecretStoreFile(key, []), 'Should reject when not given a string for a file path.');
		await rejects(() => openSecretStoreFile(key, 'secrets.json', { signal: AbortSignal.abort('Make me fail!')}), 'Should reject when given an aborted `AbortSignal`.');
	});

	test('Check race conditions.', async () => {
		const key = await getKey();
		const [store, setter, { whenWritten }] = useSecretStore(key, {});
		const val = crypto.randomUUID();
		store.foo = 'bar';
		const first = whenWritten('foo');
		store.foo = val;
		const second = whenWritten('foo');
		rejects(first, 'Writes should abort upon subsequent writes');
		doesNotReject(second, 'Second write should not throw.');
		strictEqual(await store.foo, val, 'Most recent setter should set values.');
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
