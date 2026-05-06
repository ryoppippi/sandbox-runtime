/**
 * MITM CA loader for the in-process TLS-terminating proxy.
 *
 * Loads a user-provided CA cert + key from disk. The CA is supplied via
 * `network.tlsTerminate.{caCertPath,caKeyPath}` (see sandbox-config.ts).
 * SRT does not generate the CA itself — TLS termination is opt-in and
 * requires the caller to provide both paths.
 */

import forge from 'node-forge'
import { readFileSync } from 'node:fs'
import { logForDebugging } from '../utils/debug.js'
import { resetLeafCache } from './mitm-leaf.js'

const { pki } = forge

export type MitmCA = {
  certPath: string
  keyPath: string
  certPem: string
  keyPem: string
  /** Parsed CA certificate (issuer for minted leaf certs). */
  cert: forge.pki.Certificate
  /** Parsed CA private key. RSA only. */
  key: forge.pki.rsa.PrivateKey
}

let ca: MitmCA | undefined

/**
 * Load and parse the MITM CA from the given paths. Throws if either file is
 * missing, unreadable, not PEM, fails to parse, or the key is not RSA — TLS
 * termination is explicit opt-in, so a bad config is a hard error (same
 * posture as checkDependencies()).
 *
 * Idempotent: subsequent calls return the cached CA.
 */
export function loadMitmCA(opts: {
  caCertPath: string
  caKeyPath: string
}): MitmCA {
  if (ca) return ca

  const { caCertPath: certPath, caKeyPath: keyPath } = opts

  const certPem = readPem(certPath, 'CERTIFICATE', 'tlsTerminate.caCertPath')
  const keyPem = readPem(keyPath, 'PRIVATE KEY', 'tlsTerminate.caKeyPath')

  let cert: forge.pki.Certificate
  let key: forge.pki.PrivateKey
  try {
    cert = pki.certificateFromPem(certPem)
    key = pki.privateKeyFromPem(keyPem)
  } catch (err) {
    throw new Error(
      `tlsTerminate: failed to parse CA from ${certPath}: ` +
        (err as Error).message,
    )
  }
  if (!('n' in key) || !('d' in key)) {
    // node-forge can only sign with RSA private keys.
    throw new Error(`tlsTerminate.caKeyPath: CA key at ${keyPath} must be RSA`)
  }

  ca = {
    certPath,
    keyPath,
    certPem,
    keyPem,
    cert,
    key: key as forge.pki.rsa.PrivateKey,
  }
  logForDebugging(`[mitm-ca] loaded CA from ${certPath}`)
  return ca
}

/** Return the cached CA, or undefined if tlsTerminate was not configured. */
export function getMitmCA(): MitmCA | undefined {
  return ca
}

/** Clear the cached CA and any minted leaf certs — for tests / config reload. */
export function resetMitmCA(): void {
  ca = undefined
  resetLeafCache()
}

function readPem(path: string, label: string, field: string): string {
  let pem: string
  try {
    pem = readFileSync(path, 'utf8')
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? String(err)
    throw new Error(`${field}: cannot read ${path} (${code})`)
  }
  // Accept either the exact label or a prefixed variant (e.g. "RSA PRIVATE KEY",
  // "EC PRIVATE KEY") for the key case.
  if (!new RegExp(`-----BEGIN [A-Z ]*${label}-----`).test(pem)) {
    throw new Error(`${field}: ${path} is not a PEM ${label}`)
  }
  return pem
}
