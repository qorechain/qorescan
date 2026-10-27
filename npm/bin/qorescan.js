#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
"use strict";

const { spawnSync } = require("node:child_process");
const { ensureBinary } = require("../lib/install.js");

ensureBinary()
  .then((binary) => {
    const r = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
    if (r.error) {
      console.error(`qorescan: ${r.error.message}`);
      process.exit(1);
    }
    process.exit(r.status === null ? 1 : r.status);
  })
  .catch((err) => {
    console.error(`qorescan: ${err.message}`);
    process.exit(1);
  });
