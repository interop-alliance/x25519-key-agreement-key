import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

// Absolute path to the browser (tweetnacl-based) crypto implementation.
const cryptoBrowser = fileURLToPath(
  new URL('./src/crypto-browser.ts', import.meta.url)
)

export default defineConfig(({ mode }) => ({
  // In the browser dev server (used by the Playwright suite) swap the
  // Node-native `./crypto.js` for the tweetnacl `./crypto-browser.js`, the same
  // substitution the published package performs via its package.json `browser`
  // field. Under vitest (`mode === 'test'`) we leave the native path in place
  // so the Node test run exercises Node's WebCrypto-backed implementation.
  resolve: {
    alias:
      mode === 'test'
        ? []
        : [{ find: /^\.\/crypto\.js$/, replacement: cryptoBrowser }]
  },
  test: {
    include: ['test/node/**/*.test.ts', 'src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts']
    }
  }
}))
