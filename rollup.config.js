import nodeResolve from '@rollup/plugin-node-resolve';

const externalPackages = ['@aegisjsproject/'];

export default {
	input: 'hello-world.js',
	output: {
		file: 'hello-world.cjs',
		format: 'cjs',
	},
	plugins: [nodeResolve()],
	external: id => externalPackages.some(pkg => id.startsWith(pkg)),
};

