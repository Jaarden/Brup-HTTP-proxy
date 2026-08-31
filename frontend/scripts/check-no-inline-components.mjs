/**
 * Build-time guard against React components defined inside other components.
 *
 * Such a component gets a fresh identity on every render, so React unmounts and
 * remounts its subtree rather than updating it. A remounted <input> loses focus,
 * which showed up as typing dropping out after every keystroke in the settings
 * form. Cheap to check, easy to reintroduce, so it is checked mechanically.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = 'src'
const offenders = []

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry)
    if (statSync(path).isDirectory()) walk(path)
    else if (path.endsWith('.tsx')) inspect(path)
  }
}

function inspect(path) {
  const lines = readFileSync(path, 'utf8').split('\n')
  lines.forEach((line, index) => {
    // An indented capitalised function or arrow function.
    const match = line.match(
      /^(\s+)(?:const\s+([A-Z]\w*)\s*=\s*(?:\(|function)|function\s+([A-Z]\w*)\s*\()/,
    )
    if (!match || match[1].length === 0) return
    const name = match[2] ?? match[3]
    // Only flag it when the body actually returns JSX; a nested plain helper
    // that happens to be capitalised is not a component.
    const body = lines.slice(index, index + 25).join('\n')
    if (!/=>\s*\(?\s*</.test(body) && !/return\s*\(?\s*</.test(body)) return
    offenders.push(`${path}:${index + 1}  ${name}`)
  })
}

walk(ROOT)

if (offenders.length > 0) {
  console.error(
    '\nComponents defined inside another component (they remount on every\n'
    + 'render, which loses input focus). Move them to module level:\n',
  )
  for (const offender of offenders) console.error(`  ${offender}`)
  console.error(
    '\nIf the nested function is genuinely not a component, rename it so it\n'
    + 'does not start with a capital letter.\n',
  )
  process.exit(1)
}
console.log('component check: no nested component definitions')
