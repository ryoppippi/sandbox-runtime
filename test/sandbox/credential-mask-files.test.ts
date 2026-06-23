import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  MaskedFileStore,
  buildMaskedFileBinds,
  MASKED_FILE_STORE_PREFIX,
} from '../../src/sandbox/credential-mask-files.js'
import {
  SentinelRegistry,
  SENTINEL_PREFIX,
} from '../../src/sandbox/credential-sentinel.js'

/**
 * Unit tests for the fake-file store and bind builder. Platform-agnostic;
 * these touch only the host filesystem and the sentinel registry.
 */

const FIXTURE_DIR = join(tmpdir(), 'srt-credmask-fixture-' + Date.now())
const TOKEN_FILE = join(FIXTURE_DIR, 'gh-token')
const TOKEN_CONTENT = 'ghp_realsecret_abcdef0123456789'
const SUBDIR = join(FIXTURE_DIR, 'aws-dir')

beforeAll(() => {
  mkdirSync(SUBDIR, { recursive: true })
  writeFileSync(TOKEN_FILE, TOKEN_CONTENT)
})

afterAll(() => {
  rmSync(FIXTURE_DIR, { recursive: true, force: true })
})

describe('MaskedFileStore', () => {
  test('lazily creates a temp dir under os.tmpdir()', () => {
    const store = new MaskedFileStore()
    expect(store.dirPath).toBeUndefined()
    const fake = store.write('k', 'sentinel')
    expect(store.dirPath).toBeDefined()
    expect(store.dirPath!.startsWith(tmpdir())).toBe(true)
    expect(store.dirPath!).toContain(MASKED_FILE_STORE_PREFIX)
    expect(readFileSync(fake, 'utf8')).toBe('sentinel')
    store.dispose()
  })

  test('store dir is outside the default sandbox-writable temp', () => {
    // The default writable temp inside the sandbox is /tmp/claude (see
    // getDefaultWritePaths). The fake dir must NOT be under it, or the
    // sandboxed process could tamper with the sentinel source.
    const store = new MaskedFileStore()
    store.write('k', 'x')
    expect(store.dirPath!.startsWith('/tmp/claude/')).toBe(false)
    expect(store.dirPath!.startsWith('/private/tmp/claude/')).toBe(false)
    store.dispose()
  })

  test('write is idempotent on key — same fake path, content overwritten', () => {
    const store = new MaskedFileStore()
    const a = store.write('file:/x', 'first')
    const b = store.write('file:/x', 'second')
    expect(b).toBe(a)
    expect(readFileSync(a, 'utf8')).toBe('second')
    expect(readdirSync(store.dirPath!)).toHaveLength(1)
    store.dispose()
  })

  test('dispose removes the temp dir and is idempotent', () => {
    const store = new MaskedFileStore()
    store.write('k', 'x')
    const dir = store.dirPath!
    expect(existsSync(dir)).toBe(true)
    store.dispose()
    expect(existsSync(dir)).toBe(false)
    expect(store.dirPath).toBeUndefined()
    store.dispose() // no-op, no throw
  })
})

describe('buildMaskedFileBinds', () => {
  test('registers a sentinel keyed on file path and writes it to a fake', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const binds = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'mask' }],
      ['api.github.com'],
      reg,
      store,
    )
    expect(binds).toHaveLength(1)
    expect(binds[0]!.realPath).toBe(TOKEN_FILE)
    const fakeContent = readFileSync(binds[0]!.fakePath, 'utf8')
    expect(fakeContent.startsWith(SENTINEL_PREFIX)).toBe(true)
    // The fake holds the sentinel, never the real bytes.
    expect(fakeContent).not.toContain(TOKEN_CONTENT)
    // The registry maps that sentinel back to the real file content.
    expect(reg.lookupReal(fakeContent)).toBe(TOKEN_CONTENT)
    store.dispose()
  })

  test('a file sentinel only substitutes at its own injectHosts', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const binds = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'mask', injectHosts: ['api.github.com'] }],
      ['api.github.com', 'evil.example.com'],
      reg,
      store,
    )
    const sentinel = readFileSync(binds[0]!.fakePath, 'utf8')
    const eq = (h: string, p: string) => h === p

    const toGh = { authorization: `Bearer ${sentinel}` }
    reg.substituteInHeaders(toGh, 'api.github.com', eq)
    expect(toGh.authorization).toBe(`Bearer ${TOKEN_CONTENT}`)

    const toEvil = { authorization: `Bearer ${sentinel}` }
    reg.substituteInHeaders(toEvil, 'evil.example.com', eq)
    expect(toEvil.authorization).toBe(`Bearer ${sentinel}`)
    store.dispose()
  })

  test('absent injectHosts → defaults to allowedDomains', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const binds = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'mask' }],
      ['fallback.example.com'],
      reg,
      store,
    )
    const sentinel = readFileSync(binds[0]!.fakePath, 'utf8')
    const eq = (h: string, p: string) => h === p
    const headers = { authorization: sentinel }
    reg.substituteInHeaders(headers, 'fallback.example.com', eq)
    expect(headers.authorization).toBe(TOKEN_CONTENT)
    store.dispose()
  })

  test('skips a masked file that does not exist on the host', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const binds = buildMaskedFileBinds(
      [{ path: join(FIXTURE_DIR, 'no-such-file'), mode: 'mask' }],
      [],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    expect(reg.size).toBe(0)
    // No fake was written → store dir was never created.
    expect(store.dirPath).toBeUndefined()
    store.dispose()
  })

  test('skips a masked entry that resolves to a directory', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const binds = buildMaskedFileBinds(
      [{ path: SUBDIR, mode: 'mask' }],
      [],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    expect(reg.size).toBe(0)
    store.dispose()
  })

  test('ignores deny-mode entries', () => {
    const reg = new SentinelRegistry()
    const store = new MaskedFileStore()
    const binds = buildMaskedFileBinds(
      [{ path: TOKEN_FILE, mode: 'deny' }],
      [],
      reg,
      store,
    )
    expect(binds).toHaveLength(0)
    store.dispose()
  })
})
