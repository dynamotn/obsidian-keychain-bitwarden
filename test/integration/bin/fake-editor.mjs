#!/usr/bin/env node
// Stand-in for $EDITOR used by `rbw add`: writes $BW_IT_EDITOR_CONTENT to the file.
import { writeFileSync } from "node:fs";

writeFileSync(process.argv[process.argv.length - 1], process.env.BW_IT_EDITOR_CONTENT ?? "");
