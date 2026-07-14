import { readFile } from "node:fs/promises";

const packageJson = JSON.parse(
  await readFile(new URL("../package.json", import.meta.url), "utf8"),
);
const tag = process.env.GITHUB_REF_NAME;
const expected = `sdk-v${packageJson.version}`;
if (tag !== expected) {
  throw new Error(`Release tag ${tag ?? "<missing>"} must equal ${expected}`);
}
console.log(`Verified npm release ${packageJson.name}@${packageJson.version}`);
