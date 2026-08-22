'use strict';

/* eslint-disable import/no-extraneous-dependencies, node/no-unpublished-require */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const compiler = require('vue-template-compiler');

const root = path.resolve(__dirname, '..');
const indexPath = path.join(root, 'www', 'index.html');
const outputPath = path.join(root, 'www', 'js', 'app-template.generated.js');
const runtimePath = path.join(root, 'www', 'js', 'vendor', 'vue.runtime.min.js');
const vueVersion = require('vue/package.json').version;
const compilerVersion = require('vue-template-compiler/package.json').version;

if (vueVersion !== compilerVersion) {
  throw new Error(`Vue/compiler mismatch: ${vueVersion} != ${compilerVersion}`);
}

const html = fs.readFileSync(indexPath, 'utf8');
const startMarker = '<!-- vue-app-template:start -->';
const endMarker = '<!-- vue-app-template:end -->';
const start = html.indexOf(startMarker);
const end = html.indexOf(endMarker);
if (start < 0 || end <= start) throw new Error('Vue template markers not found in index.html');

const template = html.slice(start + startMarker.length, end).trim();
const compiled = compiler.compile(template, { outputSourceRange: true });
if (compiled.errors.length) {
  const messages = compiled.errors.map((error) => (typeof error === 'string' ? error : error.msg));
  throw new Error(messages.join('\n'));
}

const asFunction = (body) => `function () { ${body} }`;
const generated = [
  '/* eslint-disable */',
  `/* Generated with Vue ${vueVersion}; do not edit directly. */`,
  'window.WgEasyAppTemplate = {',
  `  render: ${asFunction(compiled.render)},`,
  '  staticRenderFns: [',
  compiled.staticRenderFns.map((body) => `    ${asFunction(body)}`).join(',\n'),
  '  ],',
  '};',
  '',
].join('\n');
const revision = crypto.createHash('sha256').update(generated).digest('hex').slice(0, 12);
const scriptPattern = /(<script src="\.\/js\/app-template\.generated\.js\?v=)[^"]+("><\/script>)/;
if (!scriptPattern.test(html)) throw new Error('Generated template script tag not found');
const expectedHtml = html.replace(scriptPattern, `$1${revision}$2`);
const runtime = fs.readFileSync(require.resolve('vue/dist/vue.runtime.min.js'), 'utf8')
  .replace(/\n?\/\/# sourceMappingURL=.*$/, '\n');
const isCurrent = (filename, expected) => fs.existsSync(filename)
  && fs.readFileSync(filename, 'utf8') === expected;
const stale = !isCurrent(outputPath, generated)
  || !isCurrent(runtimePath, runtime)
  || expectedHtml !== html;

if (process.argv.includes('--check')) {
  if (stale) {
    // eslint-disable-next-line no-console
    console.error('The precompiled Vue template is stale. Run npm run build:www-template.');
    process.exitCode = 1;
  }
} else {
  fs.writeFileSync(outputPath, generated);
  fs.writeFileSync(runtimePath, runtime);
  fs.writeFileSync(indexPath, expectedHtml);
}
