import { AegisComponent } from '@aegisjsproject/component/base.js';
import { SYMBOLS } from '@aegisjsproject/component/consts.js';
import { EVENTS } from '@aegisjsproject/core/events.js';
import { registerCallback } from '@aegisjsproject/core/callbackRegistry.js';
import { componentBorder } from '@aegisjsproject/styles/theme.js';
import { html } from '@aegisjsproject/core/parsers/html.js';
import { svg } from '@aegisjsproject/core/parsers/svg.js';

const update = registerCallback('svg-test:update', ({ target }) => target.getRootNode().host.triggerUpdate('img:swap'));

class SVGTestElement extends AegisComponent {
	constructor() {
		super({
			template: html`<div part="container">
				${SVGTestElement.getRandomSVG()}
				<button type="button" class="btn btn-primary" ${EVENTS.onClick}="${update}">Update</button>
			<div>`,
			styles: [componentBorder],
		});
	}

	async [SYMBOLS.render](type, { shadow }) {
		switch(type) {
			case 'img:swap':
				shadow.querySelector('svg').replaceWith(svg`${SVGTestElement.getRandomSVG()}`);
				break;
		}
	}

	static getRandomSVG() {
		return `<svg viewBox="0 0 10 10" xmlns="http://www.w3.org/2000/svg" height="256" width="256">
			<rect x="0" y="0" height="10" width="10" rx="1" ry="1" fill="#${crypto.getRandomValues(new Uint8Array(3)).toHex()}"></rect>
		</svg>`;
	}
}

SVGTestElement.register('svg-test');
