#!/usr/bin/env node
import { readFile, writeFile, mkdir, readdir, cp } from 'node:fs/promises'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.join(__dirname, '..')
const OUT_DIR = path.join(ROOT, '_site')
const SHELL_PATH = path.join(__dirname, 'shell.html')
const PASSWORD = process.env.ENCRYPT_PASSWORD

const SKIP = new Set(['.git', '.github', 'scripts', '_site', 'node_modules'])

if (!PASSWORD) {
  console.error('ENCRYPT_PASSWORD is not set')
  process.exit(1)
}

// Matches scripts/shell.html's Web Crypto decryption: the embedded SALT
// string is used as-is (UTF-8 encoded), not base64-decoded, as the PBKDF2
// salt. AES-256-GCM with the auth tag appended to the ciphertext.
function encryptHtml(html, password) {
  const saltString = crypto.randomBytes(16).toString('base64')
  const iv = crypto.randomBytes(12)
  const key = crypto.pbkdf2Sync(password, Buffer.from(saltString, 'utf8'), 100000, 32, 'sha256')
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([cipher.update(html, 'utf8'), cipher.final()])
  const ct = Buffer.concat([encrypted, cipher.getAuthTag()])
  return {
    salt: saltString,
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
  }
}

async function encryptPage(srcPath, destPath, shellTemplate) {
  const html = await readFile(srcPath, 'utf8')
  const { salt, iv, ct } = encryptHtml(html, PASSWORD)
  const out = shellTemplate
    .replace('__SALT__', salt)
    .replace('__IV__', iv)
    .replace('__CT__', ct)
  await mkdir(path.dirname(destPath), { recursive: true })
  await writeFile(destPath, out, 'utf8')
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true })
  const shellTemplate = await readFile(SHELL_PATH, 'utf8')
  const entries = await readdir(ROOT, { withFileTypes: true })

  for (const entry of entries) {
    if (SKIP.has(entry.name)) continue
    const srcPath = path.join(ROOT, entry.name)
    const destPath = path.join(OUT_DIR, entry.name)

    if (entry.isDirectory()) {
      await cp(srcPath, destPath, { recursive: true })
    } else if (entry.name.endsWith('.html')) {
      await encryptPage(srcPath, destPath, shellTemplate)
    } else {
      await cp(srcPath, destPath)
    }
  }

  console.log(`Built encrypted site into ${OUT_DIR}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
