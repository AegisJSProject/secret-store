import { html } from '@aegisjsproject/core/parsers/html.js';
import { EVENTS } from '@aegisjsproject/core/events.js';
import { registerCallback } from '@aegisjsproject/core/callbackRegistry.js';
import { updateIcon } from './icons.js';

const update = registerCallback('dad-joke:update', ({ currentTarget }) => {
	currentTarget.disabled = true;
	currentTarget.getRootNode().host.update().finally(() => currentTarget.disabled = false);
});

export const template = html`<div part="container">
	<div part="joke">
		<slot name="joke">Loading...</slot>
	</div>
	<button type="button" id="update-btn" ${EVENTS.onClick}="${update}" class="btn btn-primary" part="btn" accesskey="r" autofocus="">
		<span>Get new Dad Joke</span>
		${updateIcon}
	</button>
</div>`;
