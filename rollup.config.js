import terser from '@rollup/plugin-terser';
const externalPackages = ['@shgysk8zer0/aes-gcm'];

export default {
	input: 'secret-store.js',
	output: [{
		file: 'secret-store.cjs',
		format: 'cjs',
	}, {
		file: 'secret-store.min.js',
		format: 'esm',
		plugins: [terser()],
		sourcemap: true,
	}],
	external: id => externalPackages.some(pkg => id.startsWith(pkg)),
};

