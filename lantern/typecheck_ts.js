// Where the TypeScript compiler says a call goes (lantern/typecheck.py starts this; opt-in, `lantern analyze --typecheck`).
//
// It reads files and runs nothing of the project. The compiler is the one Lantern was told of, never a copy that came
// with the project. The program is made here, from the files Lantern read and options written below: the project's
// own tsconfig is not opened, so no `plugins`, `extends` or `typeRoots` of its can name code or folders. Every read
// goes through `inside`: a file is read only when its real place is in the project's folder or in the compiler's own
// library folder, so a link that leads out of the project is not followed.
//
// stdin:  {root, typescript, files: [rel], sites: [{file, line, col}], imports: {rel: {specifier: rel}}, seconds}
//         `col` counts bytes from 1 and names the call's opening parenthesis (lantern/calls.py).
// stdout: {version, files, stopped, results: [{decl: {...} | null, why, direct}]}, one result per site, in order
'use strict'
const fs = require('fs')
const path = require('path')

const input = JSON.parse(fs.readFileSync(0, 'utf8'))
const ts = require(input.typescript)
const root = fs.realpathSync(input.root)
const libDir = fs.realpathSync(path.dirname(ts.getDefaultLibFilePath({})))
const deadline = Date.now() + Math.max(1, Number(input.seconds) || 120) * 1000
const sep = path.sep

function real (file) {
  try { return fs.realpathSync(file) } catch (e) { return null }
}

function inside (file) {
  const at = real(file)
  return at !== null && (at === root || at.startsWith(root + sep) || at.startsWith(libDir + sep))
}

const nodeTypes = inside(path.join(root, 'node_modules', '@types', 'node', 'index.d.ts'))
const options = {
  allowJs: true,
  checkJs: false,
  noEmit: true,
  skipLibCheck: true,
  strict: false,
  jsx: ts.JsxEmit.Preserve,
  target: ts.ScriptTarget.ESNext,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  types: nodeTypes ? ['node'] : [],
  resolveJsonModule: false,
  allowImportingTsExtensions: true,
  maxNodeModuleJsDepth: 0
}

const host = ts.createCompilerHost(options, true)
const readFile = host.readFile.bind(host)
const fileExists = host.fileExists.bind(host)
const dirExists = host.directoryExists ? host.directoryExists.bind(host) : () => true
host.readFile = (f) => (inside(f) ? readFile(f) : undefined)
host.fileExists = (f) => inside(f) && fileExists(f)
host.directoryExists = (d) => inside(d) && dirExists(d)
host.getDirectories = (d) => (inside(d) ? ts.sys.getDirectories(d) : [])
host.readDirectory = () => []
host.realpath = (f) => f
host.getCurrentDirectory = () => root
host.writeFile = () => {}

// An import Lantern already followed (a path alias, a workspace package) is answered the way Lantern read it;
// anything else is left to the compiler's own rules, which look only where `inside` lets them.
const imports = input.imports && typeof input.imports === 'object' ? input.imports : {}
const known = ['.d.ts', '.d.mts', '.d.cts', '.tsx', '.ts', '.mts', '.cts', '.jsx', '.js', '.mjs', '.cjs']
const cache = ts.createModuleResolutionCache(root, (x) => x, options)
host.resolveModuleNameLiterals = (literals, containingFile, redirected, opts, sourceFile) => {
  const from = path.relative(root, containingFile).split(sep).join('/')
  const mine = Object.prototype.hasOwnProperty.call(imports, from) ? imports[from] : null
  return literals.map((lit) => {
    const to = mine && Object.prototype.hasOwnProperty.call(mine, lit.text) ? mine[lit.text] : null
    if (typeof to === 'string') {
      const file = path.join(root, to)
      const extension = known.find((e) => file.endsWith(e))
      if (extension && inside(file) && fileExists(file)) {
        return { resolvedModule: { resolvedFileName: file, extension, isExternalLibraryImport: false } }
      }
    }
    const mode = sourceFile && ts.getModeForUsageLocation ? ts.getModeForUsageLocation(sourceFile, lit, opts) : undefined
    return ts.resolveModuleName(lit.text, containingFile, opts, host, cache, redirected, mode)
  })
}

const rootNames = (Array.isArray(input.files) ? input.files : [])
  .filter((f) => typeof f === 'string').map((f) => path.join(root, f)).filter(inside)
const program = ts.createProgram({ rootNames, options, host })
const checker = program.getTypeChecker()

const opened = new Map() // file -> Map(position of "(" -> the call written there)
function callsOf (sf) {
  let got = opened.get(sf.fileName)
  if (got) return got
  got = new Map()
  const visit = (node) => {
    if ((ts.isCallExpression(node) || ts.isNewExpression(node)) && node.arguments) {
      got.set(node.arguments.pos - 1, node)
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  opened.set(sf.fileName, got)
  return got
}

function lineOf (node) {
  const sf = node.getSourceFile()
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
}

function nameOf (node) {
  const n = node && node.name
  return n && (ts.isIdentifier(n) || ts.isPrivateIdentifier(n) || ts.isStringLiteral(n)) ? String(n.text).slice(0, 120) : null
}

function packageOf (file) {
  const parts = file.split(sep)
  const at = parts.lastIndexOf('node_modules')
  if (at < 0 || at + 1 >= parts.length) return null
  let name = parts[at + 1]
  if (name.startsWith('@') && at + 2 < parts.length) name = name + '/' + parts[at + 2]
  if (name.startsWith('@types/')) {
    name = name.slice(7)
    if (name.includes('__')) name = '@' + name.replace('__', '/')
  }
  return name.slice(0, 120)
}

// the function with a body behind a declaration that has none (one of several written signatures of a function)
function written (decl) {
  if (decl.body || !(ts.isFunctionDeclaration(decl) || ts.isMethodDeclaration(decl) || ts.isConstructorDeclaration(decl))) return decl
  const sym = decl.symbol
  const all = sym && sym.declarations ? sym.declarations : []
  return all.find((d) => d.body && d.kind === decl.kind) || decl
}

function describe (found) {
  let decl = written(found)
  let what = 'function'
  if (ts.isConstructorDeclaration(decl) && decl.parent) { decl = decl.parent; what = 'class' }
  if (ts.isClassDeclaration(decl) || ts.isClassExpression(decl)) what = 'class'
  const sf = decl.getSourceFile()
  const lines = [lineOf(decl)]
  let name = nameOf(decl)
  // const f = () => ..., f: function () {}, export default wrap(function () {})
  for (let i = 0, p = decl.parent; p && i < 4; i++, p = p.parent) {
    if (ts.isVariableDeclaration(p) || ts.isPropertyAssignment(p) || ts.isPropertyDeclaration(p) ||
        ts.isVariableStatement(p) || ts.isExportAssignment(p)) {
      lines.push(lineOf(p))
      if (!name) name = nameOf(p)
    } else if (!ts.isParenthesizedExpression(p) && !ts.isCallExpression(p) && !ts.isAsExpression(p) &&
               !ts.isVariableDeclarationList(p) && !ts.isSatisfiesExpression(p)) break
  }
  let container = null
  for (let p = decl.parent; p; p = p.parent) {
    if (ts.isInterfaceDeclaration(p) || ts.isClassDeclaration(p) || ts.isModuleDeclaration(p) || ts.isTypeAliasDeclaration(p)) {
      container = nameOf(p)
      break
    }
  }
  const at = real(sf.fileName) || sf.fileName
  const lib = at.startsWith(libDir + sep) ? 'builtin'
    : at.split(sep).includes('node_modules') ? 'library' : sf.isDeclarationFile ? 'declared' : null
  return {
    file: path.relative(root, at).split(sep).join('/'),
    lines: [...new Set(lines)].slice(0, 6),
    name,
    container,
    kind: ts.SyntaxKind[decl.kind],
    what,
    body: !!decl.body || what === 'class',
    lib,
    pkg: lib === 'library' ? packageOf(at) : null
  }
}

// does the name written at the call name this function itself (through imports only), not a value of its type?
function namesIt (callee, decl) {
  if (!ts.isIdentifier(callee)) return false
  let sym = checker.getSymbolAtLocation(callee)
  if (sym && (sym.flags & ts.SymbolFlags.Alias)) sym = checker.getAliasedSymbol(sym)
  const d = sym && sym.valueDeclaration
  if (!d) return false
  if (d === decl || written(d) === written(decl)) return true
  let init = ts.isVariableDeclaration(d) ? d.initializer : null
  while (init && (ts.isParenthesizedExpression(init) || ts.isAsExpression(init) || ts.isSatisfiesExpression(init))) init = init.expression
  return !!init && init === decl
}

const results = []
let stopped = null
for (const site of Array.isArray(input.sites) ? input.sites : []) {
  const out = { decl: null, why: null, direct: false }
  results.push(out)
  if (stopped || Date.now() > deadline) { stopped = 'time'; out.why = 'time'; continue }
  if (!site || typeof site.file !== 'string') { out.why = 'no-file'; continue }
  const abs = path.join(root, site.file)
  const sf = inside(abs) ? program.getSourceFile(abs) : undefined
  if (!sf) { out.why = 'no-file'; continue }
  const starts = sf.getLineStarts()
  if (!(site.line >= 1 && site.line <= starts.length)) { out.why = 'no-line'; continue }
  const lineStart = starts[site.line - 1]
  const lineEnd = site.line < starts.length ? starts[site.line] : sf.text.length
  const lineText = sf.text.slice(lineStart, lineEnd)
  // the column counts bytes: find the place that many bytes into the line
  let units = 0
  for (let bytes = 0; units < lineText.length && bytes < site.col - 1; units++) {
    const cp = lineText.codePointAt(units)
    bytes += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4
    if (cp >= 0x10000) units++
  }
  const node = callsOf(sf).get(lineStart + units)
  if (!node) { out.why = 'no-call'; continue }
  try {
    const sig = checker.getResolvedSignature(node)
    let decl = sig && sig.declaration
    if (!decl || ts.isJSDocSignature(decl)) { out.why = 'no-declaration'; continue }
    if (ts.isNewExpression(node) && !ts.isConstructorDeclaration(decl) && decl.parent && ts.isClassLike(decl.parent)) decl = decl.parent
    out.decl = describe(decl)
    out.direct = namesIt(node.expression, decl)
  } catch (e) {
    out.why = 'error'
  }
}
process.stdout.write(JSON.stringify({ version: String(ts.version).slice(0, 40), files: program.getSourceFiles().length, stopped, results }))
