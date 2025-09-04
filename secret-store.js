import { decrypt, encrypt, TEXT, BASE64 } from '@shgysk8zer0/aes-gcm';

/**
 * Creates a cryptographic wrapper around an object via a `Proxy` and setter.
 *
 * @param {CryptoKey} key
 * @param {object} targetObject
 * @param {ProxyHandler} [handler=Reflect]
 * @returns {[Proxy, (prop, val) => Promise<boolean>]}
 * @throws {TypeError} If `key` is not a `CryptoKey` with `"decrypt"` usage.
 */
export function useSecretStore(key, targetObject = globalThis.process?.env ?? {}, handler = Reflect) {
	if (! (key instanceof CryptoKey && key.usages.includes('decrypt'))) {
		throw new TypeError('Key must be a `CryptoKey` with usages that include `"decrypt"`.');
	} else {
		const proxy = new Proxy(targetObject, {
			...handler,
			set(target, prop, newValue) {
				encrypt(key, newValue, { output: BASE64 }).then(
					encrypted => handler.set instanceof Function
						? handler.set(target, prop, encrypted)
						: Reflect.set(target, prop, encrypted),
				);

				return true;
			},
			get(target, property) {
				return Promise.try(handler.get ?? Reflect.get, target, property).then(
					result => typeof result === 'string'
						? decrypt(key, result, { output: TEXT, input: BASE64 })
						: null,
				);
			},
		});

		const setter = key.usages.includes('encrypt')
			? async (property, value) => {
				const encrypted = await encrypt(key, value, { output: BASE64 });

				return Reflect.set(targetObject, property, encrypted);
			}
			: (property) => {
				throw new TypeError(`Could not set ${property}. Provided key does not support encryption.`);
			};

		return Object.freeze([proxy, setter]);
	}
}

/**
 * Opens a secret store from a JSON file. (Node only)
 *
 * @param {CryptoKey} key
 * @param {string} path
 * @param {object} config
 * @param {string} [config.encoding="utf8"]
 * @param {ProxyHandler} [config.handler=Reflect]
 * @param {AbortSignal} [config.signal]
 * @returns {Promise<[Proxy, (prop, val) => Promise<boolean>]>}
 * @throws {*} Any `signal.reason` and an aborted `AbortSignal`.
 * @throws {TypeError} If `key` is not a `CryptoKey`.
 * @throws {TypeError} If `path` is not a string/path.
 * @throws {Error} Any error from `readFile` or `JSON.parse` or `useSecretStore`.
 */
export async function openSecretStoreFile(key, path, { encoding = 'utf8', handler = Reflect, signal  } = {}) {
	if (signal instanceof AbortSignal && signal.aborted) {
		throw signal.reason;
	} else if (! (key instanceof CryptoKey)) {
		throw new TypeError('Key must be a `CryptoKey`.');
	} else if (typeof path !== 'string') {
		throw new TypeError('Path must be a string.');
	} else {
		// Using this to keep the rest of the module compatible in other environments
		const { readFile } = await import('node:fs/promises');
		const text = await readFile(path, { encoding, signal });
		const data = JSON.parse(text);

		return useSecretStore(key, data, handler);
	}
}
