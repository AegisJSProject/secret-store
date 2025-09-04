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
