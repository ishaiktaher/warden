import {copyFileSync} from "node:fs";
import {fileURLToPath} from "node:url";

copyFileSync(
  fileURLToPath(new URL("../dist/esm/index.js", import.meta.url)),
  fileURLToPath(new URL("../../ui/warden-sdk.js", import.meta.url)),
);
