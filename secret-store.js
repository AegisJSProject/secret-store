import { decrypt, encrypt, TEXT, BASE64 } from '@shgysk8zer0/aes-gcm';

/**
 * @typedef {Readonly<{
 * 	revoke: () => void,
 * 	isWriting: (property?: string) => boolean,
 * 	whenWritten: (property: string) => Promise<void>,
 * 	allWritten: () => Promise<void>,
 * 	isRevoked: () => boolean
 * }>} ProxControls
 */

/**
 * @typedef {ProxControls & Readonly<{ save: () => Promise<void> }>} WritableProxControls
 */

/**
 * @typedef {Readonly<[proxy: ProxyConstructor, setter: (property: string, value: any) => Promise<boolean>, ProxControls]>} ProxyTuple
 */

/**
 * @typedef {Readonly<[proxy: ProxyConstructor, setter: (property: string, value: any) => Promise<boolean>, WritableProxControls]>} WritableProxyTuple
 */

/**
 * Creates a cryptographic wrapper around an object via a `Proxy` and setter.
 *
 * @param {CryptoKey} key
 * @param {object} targetObject
 * @param {object} config
 * @param {ProxyHandler} [config.handler=Reflect]
 * @param {DisposableStack|AsyncDisposableStack} [config.stack]
 * @param {AbortSignal} [config.signal]
 * @returns {ProxyTuple}
 * @throws {TypeError} If `key` is not a `CryptoKey` with `"decrypt"` usage.
 */
export function useSecretStore(key, targetObject = globalThis.process?.env ?? {}, {
	handler = Reflect,
	signal,
	stack,
} = {}) {
	if (! (key instanceof CryptoKey && key.usages.includes('decrypt'))) {
		throw new TypeError('Key must be a `CryptoKey` with usages that include `"decrypt"`.');
	} else if (signal?.aborted) {
		throw signal.reason;
	} else if (stack?.disposed) {
		throw new TypeError('Stack has already been disposed.');
	} else {
		const writing = new Map();
		const hasStack = stack instanceof DisposableStack || stack instanceof AsyncDisposableStack;
		const hasSignal = signal instanceof AbortSignal;
		const isWriting = (property) => typeof property === 'string' ? writing.has(property) : writing.size !== 0;
		const whenWritten = prop => writing.has(prop) ? writing.get(prop).promise.finally(() => undefined) : Promise.resolve();
		const allWritten = () => Promise.allSettled(Array.from(writing.values(), task => task.promise)).finally(() => undefined);
		const controller = hasStack
			? stack.adopt(new AbortController(), controller => controller.abort(new DOMException('Stack disposed', 'AbortError')))
			: new AbortController();

		const sig = hasSignal ? AbortSignal.any([signal, controller.signal]) : controller.signal;

		const { proxy, revoke } = Proxy.revocable(targetObject, {
			...handler,
			set(target, property, newValue) {
				const writeStack = new DisposableStack();
				const { promise, resolve, reject } = writeStack.adopt(
					Promise.withResolvers(),
					({ reject }) => reject(new DOMException('Write aborted', 'AbortError'))
				);

				if (sig.aborted) {
					reject(sig.reason);
					return false;
				} else {
					if (writing.has(property)) {
						writing.get(property).stack.dispose();
					}

					writing.set(property, { promise, stack: writeStack });

					encrypt(key, newValue, { output: BASE64 }).then(async encrypted => {
						sig.throwIfAborted();

						if (writeStack.disposed) {
							throw new DOMException('Write cancelled', 'AbortError');
						} else if (typeof handler.set === 'function') {
							await Promise.try(() => handler.set(target, property, encrypted));
						} else {
							Reflect.set(target, property, encrypted);
						}
					}).then(() => resolve())
						.catch(reject)
						.finally(() => writing.get(property)?.stack === writeStack && writing.delete(property));

					return true;
				}
			},
			get(target, property, receiver) {
				if (writing.has(property)) {
					return writing.get(property).promise.then(() => Promise.try(handler.get ?? Reflect.get, target, property, receiver).then(
						result => typeof result === 'string'
							? decrypt(key, result, { output: TEXT, input: BASE64 })
							: null,
					));
				} else {
					return Promise.try(handler.get ?? Reflect.get, target, property, receiver).then(
						result => typeof result === 'string'
							? decrypt(key, result, { output: TEXT, input: BASE64 })
							: null,
					);
				}
			},
		});

		const setter = key.usages.includes('encrypt')
			? async (property, value) => {
				const writeStack = new DisposableStack();
				const { promise, resolve, reject } = writeStack.adopt(
					Promise.withResolvers(),
					({ reject }) => reject(new DOMException('Write aborted', 'AbortError'))
				);

				if (sig.aborted) {
					reject(new TypeError('illegal operation attempted on a revoked proxy', { cause: sig.reason }));
				} else {
					if (writing.has(property)) {
						writing.get(property).stack.dispose();
					}

					writing.set(property, { promise, stack: writeStack });

					encrypt(key, value, { output: BASE64 }).then(async encrypted => {
						sig.throwIfAborted();

						if (writeStack.disposed) {
							throw new DOMException('Write cancelled', 'AbortError');
						} else if (typeof handler.set === 'function') {
							await Promise.try(() => handler.set(targetObject, property, encrypted));
						} else {
							Reflect.set(targetObject, property, encrypted);
						}
					}).then(() => resolve(true))
						.catch(reject)
						.finally(() => writing.get(property)?.stack === writeStack && writing.delete(property));
				}

				return promise;
			}
			: (property) => {
				throw new TypeError(`Could not set ${property}. Provided key does not support encryption.`);
			};

		const rev = () => {
			if (! sig.aborted) {
				revoke();
				controller.abort(new DOMException('Revoked', 'AbortError'));
			}
		};

		if (hasStack) {
			stack.defer(rev);
		}

		if (hasSignal) {
			signal.addEventListener('abort', rev, { signal: controller.signal });
		}

		return Object.freeze([proxy, setter, Object.freeze({ revoke: rev, isWriting, whenWritten, allWritten, isRevoked: () => sig.aborted })]);
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
 * @returns {Promise<ProxyTuple>}
 * @throws {*} Any `signal.reason` and an aborted `AbortSignal`.
 * @throws {TypeError} If `key` is not a `CryptoKey`.
 * @throws {TypeError} If `path` is not a string/path.
 * @throws {Error} Any error from `readFile` or `JSON.parse` or `useSecretStore`.
 */
export async function openSecretStoreFile(key, path, { encoding = 'utf8', handler = Reflect, signal, stack } = {}) {
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

		return useSecretStore(key, data, { handler, stack, signal });
	}
}

/**
 * Opens a secret store from a JSON file with a `save()` method to save changes back to the file. (Node only)
 *
 * @param {CryptoKey} key
 * @param {string} path
 * @param {object} config
 * @param {string} [config.encoding="utf8"]
 * @param {ProxyHandler} [config.handler=Reflect]
 * @param {AbortSignal} [config.signal]
 * @param {number} [config.space=2]
 * @returns {Promise<WritableProxyTuple>}
 * @throws {*} Any `signal.reason` and an aborted `AbortSignal`.
 * @throws {TypeError} If `key` is not a `CryptoKey`.
 * @throws {TypeError} If `path` is not a string/path.
 * @throws {Error} Any error from `readFile` or `JSON.parse` or `useSecretStore`.
 */
export async function openWritableSecretStoreFile(key, path, {
	encoding = 'utf8',
	handler = Reflect,
	signal,
	stack,
	space = 2,
} = {}) {
	if (signal instanceof AbortSignal && signal.aborted) {
		throw signal.reason;
	} else if (! (key instanceof CryptoKey)) {
		throw new TypeError('Key must be a `CryptoKey`.');
	} else if (typeof path !== 'string') {
		throw new TypeError('Path must be a string.');
	} else {
		// Using this to keep the rest of the module compatible in other environments
		const { readFile, writeFile } = await import('node:fs/promises');
		const text = await readFile(path, { encoding, signal });
		const data = JSON.parse(text);

		const [proxy, setter, controls] = useSecretStore(key, data, { handler, stack, signal });
		const save = async () => {
			if (signal?.aborted) {
				throw signal.reason;
			} else {
				await controls.allWritten();
				await writeFile(path, JSON.stringify(data, null, space), { signal });
			}
		};

		return Object.freeze([proxy, setter, Object.freeze({ ...controls, save })]);
	}
}
