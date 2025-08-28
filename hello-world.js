import { AegisComponent } from '@aegisjsproject/component/base.js';
import { SYMBOLS, TRIGGERS } from '@aegisjsproject/component/consts.js';

class HTMLHelloWorldElement extends AegisComponent {
	constructor() {
		super({
			template: '<h1><slot name="content">Loading...</slot></h1>',
		});
	}

	async [SYMBOLS.render](type) {
		if (type === TRIGGERS.connected) {
			const el = document.createElement('span');
			el.textContent = 'Hello, World!';
			el.slot = 'content';
			this.append(el);
		}
	}
}

HTMLHelloWorldElement.register('hello-world');
