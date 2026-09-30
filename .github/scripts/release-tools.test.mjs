import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";

import {
  fingerprintDirectory,
  fingerprintTarball,
} from "./artifact-fingerprint.mjs";
import {
  classifyPackage,
  parsePublishedVersions,
  readPublishedVersions,
} from "./classify-packages.mjs";
import { changedPackageVersions } from "./detect-version-change.mjs";
import {
  distTagMismatch,
  parseDistTagListing,
  readDistTags,
  verifyDistTags,
} from "./dist-tags.mjs";
import {
  defaultRegistry,
  loadReleaseConfig,
  parseReleaseLine,
  releaseConfigPath,
  releaseLineDistTag,
  validateReleaseConfig,
} from "./release-config.mjs";
import { validateReleaseSource } from "./release-source.mjs";
import {
  resolveSubmoduleRepository,
  runContextRepository,
} from "./repository-identity.mjs";
import { planPackageTag, remoteTagCommit } from "./remote-tag.mjs";

// Every organization this fork has answered to. The release machinery derives
// the owner from the run rather than naming it, and this pattern is what holds
// it to that: the name has already changed twice, and each change found a
// hard-coded copy that nothing else reported. Fixtures below use `@acme` and
// `@example` precisely because neither is a name anyone could mistake for ours.
const ownerNamePattern = /astermesh|simthat|simthis/i;

const validConfig = {
  schemaVersion: 1,
  releaseLine: "simbox/v0.3",
  distTag: "line-0-3",
  upstreamWrapperCommit: "4555814e2b0beac8af5d5d760907040b7b8f61df",
  packages: [
    {
      directory: "packages/pglite",
      name: "@acme/pglite",
      upstreamName: "@electric-sql/pglite",
      postgresLicense: true,
    },
    {
      directory: "packages/pglite-react",
      name: "@acme/pglite-react",
      upstreamName: "@electric-sql/pglite-react",
    },
  ],
};

function fakeDistTagRegistry(initialTags) {
  const calls = [];
  const tagsByPackage = new Map(
    Object.entries(initialTags).map(([name, tags]) => [
      name,
      new Map(Object.entries(tags)),
    ]),
  );

  function runNpm(args) {
    calls.push(args);
    const [command, action, specOrName, tag] = args;
    assert.equal(command, "dist-tag");

    if (action === "ls") {
      const tags = tagsByPackage.get(specOrName);
      assert.ok(tags, `unexpected package: ${specOrName}`);
      return [...tags]
        .map(([name, version]) => `${name}: ${version}`)
        .join("\n");
    }

    if (action === "add") {
      const separator = specOrName.lastIndexOf("@");
      const packageName = specOrName.slice(0, separator);
      const version = specOrName.slice(separator + 1);
      const tags = tagsByPackage.get(packageName);
      assert.ok(tags, `unexpected package: ${packageName}`);
      tags.set(tag, version);
      return "";
    }

    if (action === "rm") {
      const tags = tagsByPackage.get(specOrName);
      assert.ok(tags, `unexpected package: ${specOrName}`);
      tags.delete(tag);
      return "";
    }

    throw new Error(`unexpected npm command: ${args.join(" ")}`);
  }

  return { calls, runNpm, tagsByPackage };
}

function section(source, start, end) {
  const startIndex = source.indexOf(start);
  assert.notEqual(startIndex, -1, `missing workflow section: ${start.trim()}`);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.notEqual(endIndex, -1, `missing workflow section: ${end.trim()}`);
  return source.slice(startIndex, endIndex);
}

test("verification mode cannot reach release write capabilities", () => {
  const workflow = readFileSync(
    new URL("../workflows/build.yml", import.meta.url),
    "utf8",
  );
  const permissions = section(workflow, "permissions:\n", "\non:\n");
  const dispatch = section(
    workflow,
    "  workflow_dispatch:\n",
    "  workflow_call:\n",
  );
  const call = section(workflow, "  workflow_call:\n", "\nconcurrency:\n");
  const build = section(workflow, "\n  build:\n", "\n  verify:\n");
  const verify = section(workflow, "\n  verify:\n", "\n  approval:\n");
  const approval = section(workflow, "\n  approval:\n", "\n  publish:\n");
  const beforePublish = workflow.slice(0, workflow.indexOf("\n  publish:\n"));
  const publish = section(workflow, "\n  publish:\n", "\n  finalize:\n");
  const finalize = workflow.slice(workflow.indexOf("\n  finalize:\n"));

  assert.equal(permissions, "permissions:\n  contents: read\n");
  assert.match(dispatch, /publish:[\s\S]*default: false[\s\S]*type: boolean/);
  assert.match(dispatch, /source_ref:[\s\S]*default: ""[\s\S]*type: string/);
  assert.match(call, /publish:[\s\S]*required: true[\s\S]*type: boolean/);
  assert.match(call, /source_ref:[\s\S]*default: ""[\s\S]*type: string/);
  assert.match(
    workflow,
    /SOURCE_REF: \$\{\{ inputs\.source_ref \|\| inputs\.ref \}\}/,
  );
  assert.match(
    workflow,
    /SOURCE_OVERRIDE: \$\{\{ inputs\.source_ref != '' \}\}/,
  );
  assert.match(workflow, /PUBLISH_MODE: \$\{\{ inputs\.publish \}\}/);
  assert.ok(
    build.indexOf("Upload package family") <
      build.indexOf("Classify package versions"),
    "package artifacts must be uploaded before registry classification",
  );

  assert.doesNotMatch(
    beforePublish,
    /^\s+(artifact-metadata|attestations|id-token|packages): write$/m,
  );
  assert.match(verify, /permissions:\n      contents: read\n    strategy:/);
  assert.doesNotMatch(
    verify,
    /artifact-metadata: write|attestations: write|id-token: write|packages: write/,
  );
  assert.match(verify, /Upload verified fork lineage/);
  assert.match(verify, /npm publish "\$TARBALL" \\\n            --dry-run/);

  assert.match(approval, /inputs\.publish/);
  assert.match(approval, /- build/);
  assert.match(approval, /- verify/);
  assert.match(approval, /environment: packages-production/);
  assert.match(approval, /permissions: \{\}/);
  assert.match(
    approval,
    /run_attempt: \$\{\{ steps\.approved\.outputs\.run_attempt \}\}/,
  );
  assert.match(approval, /run_attempt=\$GITHUB_RUN_ATTEMPT/);

  assert.match(publish, /inputs\.publish/);
  assert.match(publish, /- verify/);
  assert.match(publish, /- approval/);
  assert.match(
    publish,
    /needs\.approval\.outputs\.run_attempt == github\.run_attempt/,
  );
  assert.match(publish, /Download verified fork lineage/);
  assert.doesNotMatch(publish, /write-lineage\.mjs/);
  assert.match(
    publish,
    /predicate-path: \$\{\{ runner\.temp \}\}\/lineage\/fork-lineage\.json/,
  );
  assert.match(publish, /artifact-metadata: write/);
  assert.match(publish, /attestations: write/);
  assert.match(publish, /id-token: write/);
  // The lane publishes to npm by proving who it is, so it needs no write
  // access to GitHub Packages — and the family resolves nothing from there.
  assert.doesNotMatch(workflow, /packages: (read|write)/);
  assert.doesNotMatch(publish, /environment:/);

  assert.match(finalize, /inputs\.publish/);
  assert.match(finalize, /- verify/);
  assert.match(finalize, /- approval/);
  assert.match(finalize, /- publish/);
  assert.match(
    finalize,
    /needs\.approval\.outputs\.run_attempt == github\.run_attempt/,
  );
  assert.doesNotMatch(finalize, /environment:/);
});

test("verification runs never share the release concurrency group", () => {
  const workflow = readFileSync(
    new URL("../workflows/build.yml", import.meta.url),
    "utf8",
  );
  const concurrency = section(workflow, "\nconcurrency:\n", "\nenv:\n");

  assert.match(concurrency, /\$\{\{ inputs\.publish/);
  assert.match(
    concurrency,
    /&& format\('pglite-release-\{0\}', inputs\.line \|\| inputs\.ref\)/,
  );
  assert.match(
    concurrency,
    /\|\| format\('pglite-verify-\{0\}', github\.run_id\)/,
  );
  assert.equal(
    concurrency.match(/pglite-release-/g).length,
    1,
    "the serialized release group must exist only on the publish branch",
  );
  assert.match(concurrency, /cancel-in-progress: false/);
});

test("the workflow names no registry of its own", () => {
  const workflow = readFileSync(
    new URL("../workflows/build.yml", import.meta.url),
    "utf8",
  );

  assert.equal(
    workflow.split("registry-url: ${{ needs.resolve.outputs.registry }}")
      .length - 1,
    4,
    "build, verify, publish and finalize each set up npm for the line",
  );
  assert.match(workflow, /--registry="\$REGISTRY"/);
  assert.doesNotMatch(workflow, /npm\.pkg\.github\.com/);

  // One public-registry mention survives, and it is not the family's: npx
  // fetches the schema validator from npmjs wherever the family is published.
  assert.deepEqual(workflow.match(/registry\.npmjs\.org/g), [
    "registry.npmjs.org",
  ]);
  assert.match(workflow, /NPM_CONFIG_REGISTRY: https:\/\/registry\.npmjs\.org/);
});

test("the run publishes under the line tag and moves no tag afterwards", () => {
  const workflow = readFileSync(
    new URL("../workflows/build.yml", import.meta.url),
    "utf8",
  );

  // The tag is applied by the publish itself, which is the only registry write
  // the run's own identity can authenticate. Staging a package under a
  // temporary tag would mean moving a tag afterwards, and moving a tag needs a
  // credential stored somewhere — which is the thing this lane exists without.
  assert.match(workflow, /npm publish "\$TARBALL" \\\n            --tag "\$DIST_TAG"/);
  assert.match(
    workflow,
    /DIST_TAG: \$\{\{ needs\.resolve\.outputs\.dist_tag \}\}/,
  );
  assert.doesNotMatch(workflow, /staging/i);
  // `latest` is promoted by a person with npm access, so the workflow offers no
  // input that claims otherwise.
  assert.doesNotMatch(workflow, /promote_latest|PROMOTE_LATEST/);
});

test("publication proves the run's identity instead of carrying a credential", () => {
  const workflow = readFileSync(
    new URL("../workflows/build.yml", import.meta.url),
    "utf8",
  );
  const publish = section(workflow, "\n  publish:\n", "\n  finalize:\n");

  // The OIDC exchange has a runtime floor of Node 22.14 and npm CLI 11.5.1.
  // Only the publishing job is raised to meet it; the rest build and test the
  // workspace, and their runtime answers to the workspace.
  assert.match(publish, /node-version: 22\n/);
  assert.match(publish, /npm install --global npm@(1[2-9]|[2-9][0-9])/);
  assert.match(publish, /id-token: write/);
  // Public access is declared by each manifest and checked when the release is
  // resolved, so the publish command does not repeat it. Two places to state
  // one fact is how they end up disagreeing.
  assert.doesNotMatch(publish, /--access/);
  assert.match(
    readFileSync(new URL("./resolve-release.mjs", import.meta.url), "utf8"),
    /publishConfig\?\.access !== "public"/,
  );

  // Nothing in the lane carries a registry credential. A GitHub token is not a
  // stored secret, but it authenticates to GitHub Packages and means nothing
  // where the family is published now — leaving it would only disguise which
  // step is trusted and why.
  assert.doesNotMatch(workflow, /NODE_AUTH_TOKEN/);
  assert.equal(
    workflow.match(/secrets\.GITHUB_TOKEN/g).length,
    1,
    "the only remaining GitHub token verifies attestations against GitHub",
  );
  assert.match(workflow, /GH_TOKEN: \$\{\{ secrets\.GITHUB_TOKEN \}\}/);
});

test("release-tooling CI verifies the live package query read-only", () => {
  const workflow = readFileSync(
    new URL("../workflows/test-release-tooling.yml", import.meta.url),
    "utf8",
  );

  // The family is public on the npm registry, so the probe reads it anonymously:
  // no package permission, no registry credentials, no token.
  assert.match(workflow, /permissions:\n  contents: read\n\n/);
  assert.doesNotMatch(workflow, /packages: (read|write)/);
  assert.doesNotMatch(workflow, /registry-url:/);
  assert.doesNotMatch(workflow, /NODE_AUTH_TOKEN|secrets\.GITHUB_TOKEN/);
  // The probe names no owner of its own: the scope is the repository owner, so
  // a written-down scope breaks the moment the repository moves.
  assert.match(
    workflow,
    /PUBLISHED_PACKAGE: "@\$\{\{ github\.repository_owner \}\}\/pglite"/,
  );
  assert.doesNotMatch(workflow, /PUBLISHED_PACKAGE: "@[a-z0-9][a-z0-9-]*\//);
  assert.match(
    workflow,
    /npm view "\$PUBLISHED_PACKAGE@>=0\.0\.0" version --json/,
  );
  assert.match(workflow, /REGISTRY: https:\/\/registry\.npmjs\.org\n/);
  assert.match(workflow, /--registry="\$REGISTRY" 2> "\$RUNNER_TEMP\/npm-view\.err"/);
  assert.match(
    workflow,
    /parsePublishedVersions\(process\.argv\[1\], process\.argv\[2\]\)/,
  );
  assert.doesNotMatch(workflow, /packages: write/);
});

test("the live package query judges a 404 against a declared state", () => {
  const workflow = readFileSync(
    new URL("../workflows/test-release-tooling.yml", import.meta.url),
    "utf8",
  );

  // The probe never concludes anything from a 404 alone: it judges one only
  // against the state the workflow declares.
  assert.match(workflow, /PUBLISHED_STATE: present/);
  assert.match(
    workflow,
    /\[ "\$PUBLISHED_STATE" = "absent" \] && grep -q 'E404'/,
  );
  // A positive control runs first, so a 404 cannot stand in for a broken
  // connection or the wrong registry host.
  assert.match(workflow, /npm ping --registry="\$REGISTRY"\n/);
  // Both disagreements with the declared state fail.
  assert.match(workflow, /is declared absent, but the registry returned a record/);
  assert.match(workflow, /cat "\$RUNNER_TEMP\/npm-view\.err" >&2\n\s*exit 1/);
});

test("release source overrides are verification-only line descendants", () => {
  const base = {
    sourceCommit: "a".repeat(40),
    releaseLine: "simbox/v0.3",
  };

  assert.equal(
    validateReleaseSource({
      ...base,
      publish: true,
      sourceOverride: false,
      sourceIsOnLine: true,
      sourceExtendsLine: false,
    }),
    "landed",
  );
  assert.equal(
    validateReleaseSource({
      ...base,
      publish: false,
      sourceOverride: true,
      sourceIsOnLine: false,
      sourceExtendsLine: true,
    }),
    "candidate",
  );
  assert.throws(
    () =>
      validateReleaseSource({
        ...base,
        publish: true,
        sourceOverride: true,
        sourceIsOnLine: true,
        sourceExtendsLine: true,
      }),
    /source_ref is allowed only when publish is false/,
  );
  assert.throws(
    () =>
      validateReleaseSource({
        ...base,
        publish: false,
        sourceOverride: false,
        sourceIsOnLine: false,
        sourceExtendsLine: true,
      }),
    /not an allowed source/,
  );
  assert.throws(
    () =>
      validateReleaseSource({
        ...base,
        publish: false,
        sourceOverride: true,
        sourceIsOnLine: false,
        sourceExtendsLine: false,
      }),
    /not an allowed source/,
  );
  assert.throws(
    () =>
      validateReleaseSource({
        ...base,
        publish: true,
        sourceOverride: false,
        sourceIsOnLine: false,
        sourceExtendsLine: true,
      }),
    /not an allowed source/,
  );
});

test("release config owns and validates the complete package list", () => {
  assert.deepEqual(validateReleaseConfig(validConfig), {
    ...validConfig,
    scope: "acme",
    rootPackage: "@acme/pglite",
    registry: defaultRegistry,
    packages: [
      validConfig.packages[0],
      { ...validConfig.packages[1], postgresLicense: false },
    ],
  });
  assert.throws(
    () =>
      validateReleaseConfig({
        ...validConfig,
        packages: [validConfig.packages[0], validConfig.packages[0]],
      }),
    /duplicate directory/,
  );
  assert.throws(
    () => validateReleaseConfig({ ...validConfig, distTag: "latest" }),
    /must use dist tag/,
  );
  assert.throws(
    () =>
      validateReleaseConfig({
        ...validConfig,
        upstreamWrapperCommit: "main",
      }),
    /invalid upstream wrapper commit/,
  );
});

test("artifact fingerprint ignores filesystem metadata but detects content", () => {
  const first = mkdtempSync(resolve(tmpdir(), "fingerprint-first-"));
  const second = mkdtempSync(resolve(tmpdir(), "fingerprint-second-"));
  try {
    for (const root of [first, second]) {
      mkdirSync(resolve(root, "dist"));
      writeFileSync(resolve(root, "package.json"), '{"name":"example"}\n');
      writeFileSync(resolve(root, "dist/index.js"), "export default 1\n");
      chmodSync(resolve(root, "dist/index.js"), 0o755);
    }
    assert.equal(fingerprintDirectory(first), fingerprintDirectory(second));
    writeFileSync(resolve(second, "dist/index.js"), "export default 2\n");
    assert.notEqual(fingerprintDirectory(first), fingerprintDirectory(second));
  } finally {
    rmSync(first, { recursive: true, force: true });
    rmSync(second, { recursive: true, force: true });
  }
});

test("tarball fingerprint ignores archive metadata", () => {
  const root = mkdtempSync(resolve(tmpdir(), "fingerprint-tarballs-"));
  try {
    for (const name of ["first", "second"]) {
      const packageRoot = resolve(root, name, "package");
      mkdirSync(packageRoot, { recursive: true });
      writeFileSync(
        resolve(packageRoot, "package.json"),
        '{"name":"example"}\n',
      );
      execFileSync("tar", [
        "-czf",
        resolve(root, `${name}.tgz`),
        "-C",
        resolve(root, name),
        "package",
      ]);
    }
    assert.equal(
      fingerprintTarball(resolve(root, "first.tgz")),
      fingerprintTarball(resolve(root, "second.tgz")),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("tarball fingerprint normalizes nested archive metadata", () => {
  const root = mkdtempSync(resolve(tmpdir(), "nested-fingerprint-"));
  const makePackage = (name, timestamp, content) => {
    const packageRoot = resolve(root, name, "package");
    const extensionRoot = resolve(root, `${name}-extension`);
    mkdirSync(resolve(packageRoot, "dist"), { recursive: true });
    mkdirSync(resolve(extensionRoot, "lib"), { recursive: true });
    const library = resolve(extensionRoot, "lib/extension.so");
    writeFileSync(library, content);
    chmodSync(library, 0o755);
    utimesSync(library, timestamp, timestamp);
    const nested = resolve(packageRoot, "dist/extension.tar.gz");
    execFileSync("tar", ["-czf", nested, "-C", extensionRoot, "."]);
    const outer = resolve(root, `${name}.tgz`);
    execFileSync("tar", [
      "-czf",
      outer,
      "-C",
      resolve(root, name),
      "package",
    ]);
    return { nested, outer };
  };

  try {
    const first = makePackage("first", new Date(0), "same content\n");
    const second = makePackage(
      "second",
      new Date("2026-07-28T01:06:00Z"),
      "same content\n",
    );
    const changed = makePackage(
      "changed",
      new Date("2026-07-28T01:06:00Z"),
      "changed content\n",
    );

    assert.notDeepEqual(readFileSync(first.nested), readFileSync(second.nested));
    assert.equal(
      fingerprintTarball(first.outer),
      fingerprintTarball(second.outer),
    );
    assert.notEqual(
      fingerprintTarball(first.outer),
      fingerprintTarball(changed.outer),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("registry versions use a stable range and fail closed", () => {
  const calls = [];
  const versions = readPublishedVersions(
    (args) => {
      calls.push(args);
      return '["0.3.16","0.3.17"]\n';
    },
    "@acme/pglite",
  );

  assert.deepEqual(calls, [
    [
      "view",
      "@acme/pglite@>=0.0.0",
      "version",
      "--json",
    ],
  ]);
  assert.deepEqual(versions, ["0.3.16", "0.3.17"]);
  assert.deepEqual(
    parsePublishedVersions('"0.3.17"\n', "@acme/pglite"),
    ["0.3.17"],
  );
  assert.deepEqual(
    readPublishedVersions(() => undefined, "@acme/pglite"),
    [],
  );
  assert.throws(
    () => parsePublishedVersions("", "@acme/pglite"),
    /empty published versions response/,
  );
  assert.throws(
    () => parsePublishedVersions("{", "@acme/pglite"),
    /invalid published versions response/,
  );
  assert.throws(
    () => parsePublishedVersions('{"version":"0.3.17"}', "@acme/pglite"),
    /invalid published version/,
  );
  assert.throws(
    () =>
      parsePublishedVersions(
        '["0.3.17","0.3.17"]',
        "@acme/pglite",
      ),
    /duplicate published version/,
  );
});

test("registry classification rejects reused and regressed versions", () => {
  const pkg = {
    name: "@acme/pglite",
    version: "0.3.17",
    fingerprint: "sha256:local",
  };
  assert.equal(classifyPackage(pkg, ["0.3.18-beta.1"], undefined), "publish");
  assert.equal(classifyPackage(pkg, ["0.3.17"], "sha256:local"), "existing");
  assert.throws(
    () => classifyPackage(pkg, ["0.3.17"], "sha256:remote"),
    /different contents \(built sha256:local, published sha256:remote\)/,
  );
  assert.throws(() => classifyPackage(pkg, ["0.3.18"], undefined), /not newer/);
});

test("registry dist-tags use the documented listing command and format", () => {
  const calls = [];
  const tags = readDistTags(
    (args) => {
      calls.push(args);
      return [
        "line-0-3: 0.3.17",
        "staging-30300319510: 0.3.17",
        "",
      ].join("\n");
    },
    "@acme/pglite",
  );
  assert.deepEqual(calls, [["dist-tag", "ls", "@acme/pglite"]]);
  assert.deepEqual(
    tags,
    new Map([
      ["line-0-3", "0.3.17"],
      ["staging-30300319510", "0.3.17"],
    ]),
  );
  assert.deepEqual(
    parseDistTagListing(
      [
        "line-0-3: 0.3.17",
        "staging-30300319510: 0.3.17",
        "",
      ].join("\n"),
      "@acme/pglite",
    ),
    new Map([
      ["line-0-3", "0.3.17"],
      ["staging-30300319510", "0.3.17"],
    ]),
  );
  assert.deepEqual(
    parseDistTagListing("", "@acme/pglite"),
    new Map(),
  );
  assert.throws(
    () => parseDistTagListing("not a tag record", "@acme/pglite"),
    /invalid dist-tag record/,
  );
  assert.throws(
    () =>
      parseDistTagListing(
        "line-0-3: 0.3.17\nline-0-3: 0.3.18\n",
        "@acme/pglite",
      ),
    /duplicate dist-tag/,
  );
});

test("dist-tag verification names what the line points at, and at nothing else", () => {
  const common = { version: "0.3.17", distTag: "line-0-3" };

  assert.equal(
    distTagMismatch({
      ...common,
      packageName: "@acme/pglite",
      tags: new Map([["line-0-3", "0.3.17"]]),
    }),
    undefined,
  );
  assert.equal(
    distTagMismatch({
      ...common,
      packageName: "@acme/pglite",
      tags: new Map([["line-0-3", "0.3.16"]]),
    }),
    "@acme/pglite dist-tag line-0-3 names 0.3.16, not 0.3.17",
  );
  // A package the run never reached and one it left behind are different
  // failures, and they are worth telling apart in the message: the first says
  // the publish step died, the second says it published the wrong thing.
  assert.equal(
    distTagMismatch({
      ...common,
      packageName: "@acme/pglite",
      tags: new Map(),
    }),
    "@acme/pglite dist-tag line-0-3 names nothing, not 0.3.17",
  );
  // `latest` is moved by a person, not by a run, so where it points is not this
  // check's business.
  assert.equal(
    distTagMismatch({
      ...common,
      packageName: "@acme/pglite",
      tags: new Map([
        ["line-0-3", "0.3.17"],
        ["latest", "0.2.9"],
      ]),
    }),
    undefined,
  );
});

test("the release verification reads every package and writes none", () => {
  const registry = fakeDistTagRegistry({
    "@acme/pglite": { "line-0-3": "0.3.17", latest: "0.3.16" },
    "@acme/pglite-react": { "line-0-3": "0.2.34" },
    "@acme/pglite-vue": { "line-0-3": "0.2.34" },
  });

  verifyDistTags({
    packages: [
      { name: "@acme/pglite", version: "0.3.17" },
      { name: "@acme/pglite-react", version: "0.2.34" },
      { name: "@acme/pglite-vue", version: "0.2.34" },
    ],
    distTag: "line-0-3",
    runNpm: registry.runNpm,
  });

  assert.deepEqual(registry.calls, [
    ["dist-tag", "ls", "@acme/pglite"],
    ["dist-tag", "ls", "@acme/pglite-react"],
    ["dist-tag", "ls", "@acme/pglite-vue"],
  ]);
  // The run holds no credential that could write one. If a write ever appears
  // here, the lane has quietly acquired a stored token again.
  assert.deepEqual(
    registry.calls.filter(([, action]) => action !== "ls"),
    [],
  );
  assert.deepEqual(
    Object.fromEntries(registry.tagsByPackage.get("@acme/pglite")),
    { "line-0-3": "0.3.17", latest: "0.3.16" },
  );
});

test("a half-published family is reported whole, not one package at a time", () => {
  const registry = fakeDistTagRegistry({
    "@acme/pglite": { "line-0-3": "0.3.17" },
    "@acme/pglite-react": { "line-0-3": "0.2.33" },
    "@acme/pglite-vue": {},
  });

  assert.throws(
    () =>
      verifyDistTags({
        packages: [
          { name: "@acme/pglite", version: "0.3.17" },
          { name: "@acme/pglite-react", version: "0.2.34" },
          { name: "@acme/pglite-vue", version: "0.2.34" },
        ],
        distTag: "line-0-3",
        runNpm: registry.runNpm,
      }),
    (error) => {
      assert.match(error.message, /line-0-3 does not name this release/);
      assert.match(
        error.message,
        /@acme\/pglite-react dist-tag line-0-3 names 0\.2\.33, not 0\.2\.34/,
      );
      assert.match(
        error.message,
        /@acme\/pglite-vue dist-tag line-0-3 names nothing, not 0\.2\.34/,
      );
      // The package that is correct is not in the list: the operator reruns
      // what failed, and a list that names everything names nothing.
      assert.equal(/@acme\/pglite dist-tag/.test(error.message), false);
      return true;
    },
  );
  assert.equal(registry.calls.length, 3, "every package must still be read");
});

test("an unreadable listing fails the release rather than passing it", () => {
  const runNpm = (args) => {
    const [, action, packageName] = args;
    assert.equal(action, "ls");
    return packageName === "@acme/pglite"
      ? "line-0-3: 0.3.17\n"
      : "not a dist-tag record\n";
  };

  assert.throws(
    () =>
      verifyDistTags({
        packages: [
          { name: "@acme/pglite", version: "0.3.17" },
          { name: "@acme/pglite-react", version: "0.2.34" },
        ],
        distTag: "line-0-3",
        runNpm,
      }),
    /invalid dist-tag record for @acme\/pglite-react/,
  );
});

test("remote package tags resolve to their commit targets", () => {
  const tag = "@acme/pglite@0.3.17";
  const tagObject = "a".repeat(40);
  const commit = "b".repeat(40);

  assert.equal(remoteTagCommit("", tag), undefined);
  assert.equal(remoteTagCommit(`${commit}\trefs/tags/${tag}\n`, tag), commit);
  assert.equal(
    remoteTagCommit(
      [
        `${tagObject}\trefs/tags/${tag}`,
        `${commit}\trefs/tags/${tag}^{}`,
        "",
      ].join("\n"),
      tag,
    ),
    commit,
  );
  assert.throws(
    () => remoteTagCommit(`invalid\trefs/tags/${tag}\n`, tag),
    /invalid remote tag record/,
  );
});

test("existing package tags retain their original matching release commit", () => {
  const originalCommit = "a".repeat(40);
  assert.deepEqual(
    planPackageTag({
      tag: "@acme/pglite@0.3.17",
      remoteCommit: originalCommit,
      currentCommit: "b".repeat(40),
      packageName: "@acme/pglite",
      packageVersion: "0.3.17",
      manifest: {
        name: "@acme/pglite",
        version: "0.3.17",
      },
    }),
    { action: "keep", commit: originalCommit },
  );
});

test("missing package tags are created for the current release", () => {
  const currentCommit = "b".repeat(40);
  assert.deepEqual(
    planPackageTag({
      tag: "@acme/pglite-socket@0.0.23",
      remoteCommit: undefined,
      currentCommit,
      packageName: "@acme/pglite-socket",
      packageVersion: "0.0.23",
      manifest: undefined,
    }),
    { action: "create", commit: currentCommit },
  );
});

test("existing package tag targets must declare the tagged identity", () => {
  const common = {
    tag: "@acme/pglite@0.3.17",
    remoteCommit: "a".repeat(40),
    currentCommit: "b".repeat(40),
    packageName: "@acme/pglite",
    packageVersion: "0.3.17",
  };

  assert.throws(
    () =>
      planPackageTag({
        ...common,
        manifest: {
          name: "@acme/pglite",
          version: "0.3.16",
        },
      }),
    /does not declare @acme\/pglite@0\.3\.17/,
  );
  assert.throws(
    () =>
      planPackageTag({
        ...common,
        manifest: {
          name: "@acme/pglite-react",
          version: "0.3.17",
        },
      }),
    /does not declare @acme\/pglite@0\.3\.17/,
  );
  assert.throws(
    () => planPackageTag({ ...common, manifest: undefined }),
    /does not declare @acme\/pglite@0\.3\.17/,
  );
});

test("no Git tag is pushed before the published family is verified", () => {
  const finalizer = readFileSync(
    new URL("./finalize-release.mjs", import.meta.url),
    "utf8",
  );
  const preflight = finalizer.indexOf("const gitTagPlans");
  const verification = finalizer.indexOf("verifyDistTags({");
  const push = finalizer.indexOf('git(["tag"');

  assert.notEqual(preflight, -1);
  assert.notEqual(verification, -1);
  assert.notEqual(push, -1);
  // The preflight only reads the remote, so it may run first. The push is the
  // step that makes a claim, and a Git tag must not outlive a registry state
  // that contradicts it.
  assert.ok(preflight < verification);
  assert.ok(verification < push);
});

test("automatic publication reacts only to package version changes", () => {
  const packages = validConfig.packages;
  const current = new Map([
    [
      "packages/pglite/package.json",
      { name: "@acme/pglite", version: "0.3.17", description: "new" },
    ],
    [
      "packages/pglite-react/package.json",
      { name: "@acme/pglite-react", version: "0.2.34" },
    ],
  ]);
  const unchangedVersions = new Map([
    [
      "packages/pglite/package.json",
      { name: "@acme/pglite", version: "0.3.17", description: "old" },
    ],
    [
      "packages/pglite-react/package.json",
      { name: "@acme/pglite-react", version: "0.2.34" },
    ],
  ]);
  assert.deepEqual(
    changedPackageVersions(
      packages,
      (path) => unchangedVersions.get(path),
      (path) => current.get(path),
    ),
    [],
  );

  unchangedVersions.get("packages/pglite/package.json").version = "0.3.16";
  assert.deepEqual(
    changedPackageVersions(
      packages,
      (path) => unchangedVersions.get(path),
      (path) => current.get(path),
    ),
    [
      {
        name: "@acme/pglite",
        before: "0.3.16",
        after: "0.3.17",
      },
    ],
  );
});

test("release lines name a platform, a version, and an optional variant", () => {
  assert.deepEqual(parseReleaseLine("simbox/v0.3"), {
    platform: "simbox",
    major: 0,
    minor: 3,
    variant: undefined,
  });
  assert.deepEqual(parseReleaseLine("simbox/v0.3-postgis"), {
    platform: "simbox",
    major: 0,
    minor: 3,
    variant: "postgis",
  });
  assert.equal(releaseLineDistTag(parseReleaseLine("simbox/v0.5")), "line-0-5");
  assert.equal(
    releaseLineDistTag(parseReleaseLine("simbox/v0.3-postgis")),
    "line-0-3-postgis",
  );
  assert.equal(
    validateReleaseConfig({
      ...validConfig,
      releaseLine: "simbox/v0.3-postgis",
      distTag: "line-0-3-postgis",
    }).distTag,
    "line-0-3-postgis",
  );

  for (const line of [
    "v0.3",
    "simbox/0.3",
    "SimBox/v0.3",
    "simbox/v0",
    "simbox/v0.3-",
    "simbox/v0.3-PostGIS",
  ]) {
    assert.throws(() => parseReleaseLine(line), /invalid release line/);
  }
});

test("the package scope follows the manifest, not the tooling", () => {
  const elsewhere = {
    ...validConfig,
    packages: validConfig.packages.map((entry) => ({
      ...entry,
      name: entry.name.replace("@acme/", "@example/"),
    })),
  };
  const resolved = validateReleaseConfig(elsewhere);
  assert.equal(resolved.scope, "example");
  assert.equal(resolved.rootPackage, "@example/pglite");

  assert.throws(
    () =>
      validateReleaseConfig({
        ...validConfig,
        packages: [
          validConfig.packages[0],
          { ...validConfig.packages[1], name: "@example/pglite-react" },
        ],
      }),
    /mixes package scopes/,
  );
  assert.throws(
    () =>
      validateReleaseConfig({
        ...validConfig,
        packages: [
          { ...validConfig.packages[0], name: "@acme/pglite-tools" },
        ],
      }),
    /must include @acme\/pglite/,
  );
});

test("the registry follows the manifest, not the tooling", () => {
  // A line written before the field existed still targets GitHub Packages, so
  // the default is part of the contract rather than a convenience.
  assert.equal(defaultRegistry, "https://npm.pkg.github.com");
  assert.equal(validateReleaseConfig(validConfig).registry, defaultRegistry);
  assert.equal(
    validateReleaseConfig({
      ...validConfig,
      registry: "https://registry.npmjs.org",
    }).registry,
    "https://registry.npmjs.org",
  );

  // The field aims the guard against publishing to the wrong host, so a value
  // the guard cannot vouch for is rejected rather than carried. A plaintext
  // scheme is rejected too: it would be a way around the guard, not a variant
  // of it.
  for (const rejected of [
    "http://registry.npmjs.org",
    "registry.npmjs.org",
    "https://",
    "https://localhost",
    "https://registry.npmjs.org/two words",
    "",
    null,
    42,
  ]) {
    assert.throws(
      () => validateReleaseConfig({ ...validConfig, registry: rejected }),
      /invalid registry/,
      `registry must be rejected: ${String(rejected)}`,
    );
  }

  // Exactly one file may name a registry host, and it is the one that defines
  // the default above. Every other script reads what the line declared and the
  // release context carried — the same rule the owner is already held to, for
  // the same reason: the family has moved registry once and will again.
  const registryHosts = /npm\.pkg\.github\.com|registry\.npmjs\.org/;
  const scripts = readdirSync(new URL(".", import.meta.url)).filter(
    (name) =>
      name.endsWith(".mjs") &&
      !name.endsWith(".test.mjs") &&
      name !== "release-config.mjs",
  );
  assert.ok(scripts.length > 5, "the script scan must not be empty");
  for (const name of scripts) {
    assert.equal(
      registryHosts.test(readFileSync(new URL(name, import.meta.url), "utf8")),
      false,
      `${name} must not name a registry host`,
    );
  }
});

test("fork repositories resolve from the run context and the submodule link", () => {
  assert.equal(
    runContextRepository({
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_REPOSITORY: "acme/pglite",
    }),
    "https://github.com/acme/pglite",
  );
  assert.throws(
    () => runContextRepository({ GITHUB_SERVER_URL: "https://github.com" }),
    /invalid GITHUB_REPOSITORY/,
  );
  assert.throws(
    () =>
      runContextRepository({
        GITHUB_SERVER_URL: "github.com",
        GITHUB_REPOSITORY: "acme/pglite",
      }),
    /invalid GITHUB_SERVER_URL/,
  );

  assert.equal(
    resolveSubmoduleRepository(
      "https://github.com/acme/pglite",
      "../postgres-pglite.git",
    ),
    "https://github.com/acme/postgres-pglite",
  );
  assert.equal(
    resolveSubmoduleRepository(
      "https://example.test/elsewhere/pglite",
      "../postgres-pglite.git",
    ),
    "https://example.test/elsewhere/postgres-pglite",
  );
  assert.equal(
    resolveSubmoduleRepository(
      "https://github.com/acme/pglite",
      "https://github.com/another/postgres-pglite.git",
    ),
    "https://github.com/another/postgres-pglite",
  );
  assert.throws(
    () =>
      resolveSubmoduleRepository(
        "https://github.com/acme/pglite",
        "git@github.com:acme/postgres-pglite.git",
      ),
    /unsupported submodule url/,
  );
});

test("the release workflow reads its identity from the run context", () => {
  const workflow = readFileSync(
    new URL("../workflows/build.yml", import.meta.url),
    "utf8",
  );
  const schema = JSON.parse(
    readFileSync(
      new URL("../attestations/fork-lineage-v2.schema.json", import.meta.url),
      "utf8",
    ),
  );

  assert.match(
    workflow,
    /predicate-type: \$\{\{ github\.server_url \}\}\/\$\{\{ github\.repository \}\}\/attestations\/fork-lineage\/v2/,
  );
  assert.match(
    workflow,
    /SIGNER_WORKFLOW: \$\{\{ job\.workflow_repository \}\}\/\.github\/workflows\/build\.yml/,
  );
  // The scope used to be derived from the repository owner, which is correct on
  // GitHub Packages — there the owner *is* the scope. On a registry where the
  // scope is a free choice, the two are only accidentally the same string, so
  // the scope comes from the line manifest and the owner from the run.
  assert.match(workflow, /scope: "@\$\{\{ needs\.resolve\.outputs\.scope \}\}"/);
  assert.doesNotMatch(workflow, /github\.repository_owner/);
  assert.doesNotMatch(workflow, /--signer-workflow [a-z]/);
  assert.equal(
    ownerNamePattern.test(workflow),
    false,
    "the release workflow must name no owner",
  );

  assert.equal(schema.properties.schemaVersion.const, 2);
  assert.equal(schema.$id, undefined);
  assert.deepEqual(schema.properties.wrapper.required, ["upstream", "fork"]);
  assert.deepEqual(schema.properties.engine.required, ["upstream", "fork"]);
  assert.equal(schema.$defs.forkWrapper.properties.repository.const, undefined);
  assert.equal(schema.$defs.forkEngine.properties.repository.const, undefined);
  assert.equal(
    ownerNamePattern.test(JSON.stringify(schema)),
    false,
    "the lineage schema must name no owner",
  );
});

test("the tooling gate runs on the shared CI branch, and names no other", () => {
  const workflow = readFileSync(
    new URL("../workflows/test-release-tooling.yml", import.meta.url),
    "utf8",
  );

  assert.equal(
    workflow.split("      - simbox/ci\n").length - 1,
    2,
    "simbox/ci must be filtered on for both pull_request and push",
  );
  // The rename listed both names for exactly as long as it took to merge the
  // pull request that renamed the filter. Nothing should carry the old one now.
  assert.equal(
    ownerNamePattern.test(workflow),
    false,
    "the tooling gate must name no owner",
  );
});

test("the line manifest is read from its declared path", () => {
  assert.equal(releaseConfigPath, ".release/line.json");

  const workspace = mkdtempSync(resolve(tmpdir(), "release-line-"));
  try {
    assert.throws(() => loadReleaseConfig(workspace), /ENOENT/);
    mkdirSync(resolve(workspace, ".release"));
    writeFileSync(
      resolve(workspace, releaseConfigPath),
      `${JSON.stringify(validConfig, null, 2)}\n`,
    );
    assert.equal(
      loadReleaseConfig(workspace).releaseLine,
      validConfig.releaseLine,
    );
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});
