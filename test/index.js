import '@aegisjsproject/template';
import './dad-joke.js';
import './svg-test.js';
import { properties, baseTheme, lightTheme, darkTheme, btn, btnPrimary, btnSuccess, btnDanger, displays, positions, bootstrap } from '@aegisjsproject/styles';
import { html } from '@aegisjsproject/core/parsers/html.js';
import { css } from '@aegisjsproject/core/parsers/css.js';

const styles = css`body {
	grid-template-areas: "header header header"
		"nav nav nav"
		"main main main"
		"footer footer footer";
	grid-template-rows: calc(100dvh - 3rem) 3rem 35em 450px;
}

#header {
	grid-area: header;
}

#nav {
	grid-area: nav;
	background-color: ${bootstrap.secondary};
}

#main {
	grid-area: main;
}

#footer {
	grid-area: footer;
	background-color: ${bootstrap.gray[8]};
	color: ${bootstrap.light};
}`;

document.adoptedStyleSheets = [properties, baseTheme, lightTheme, darkTheme, btn, btnPrimary, btnSuccess, btnDanger, displays, positions, displays, styles];

document.body.append(html`
	<header id="header">
		<hello-world></hello-world>
	</header>
	<nav id="nav" class="flex sticky top"></nav>
	<main id="main">
		<dad-joke></dad-joke>
		<svg-test class="inline-block"></svg-test>
	</main>
	<footer id="footer">
		&copy; ${new Date().getFullYear().toString()}
	</footer>
`);
