import { readdir, rm } from 'node:fs/promises'
import { join } from 'node:path'

const distDir = new URL('../dist', import.meta.url)

try {
  const entries = await readdir(distDir, { withFileTypes: true })
  await Promise.all(
    entries
      .filter((entry) => entry.name !== '.gitkeep')
      .map((entry) => rm(join(distDir.pathname, entry.name), { recursive: true, force: true })),
  )
} catch (error) {
  if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
    process.exit(0)
  }
  throw error
}
