import pathlib, html
root = pathlib.Path(__file__).parent
core = (root / 'core.js').read_text()
page = (root / 'src-page.html').read_text()
assert '</script' not in core.lower()
out = page.replace('/*CORE_SRC*/', core, 1).replace('/*CORE_JS*/', core, 1)

(root / 'index.html').write_text(out)
print('wrote', len(out), 'bytes')
