/** @type {import('next').NextConfig} */
const nextConfig = {
  // Keep the wasm-pack (nodejs target) package UN-bundled by webpack. Its glue
  // does `require('fs').readFileSync(`${__dirname}/...bg.wasm`)`; bundling would
  // rewrite `__dirname` and break that read. As an external, the package is
  // required at runtime from node_modules with `__dirname` intact.
  serverExternalPackages: ["@makeprisms/pops-core-wasm"],

  // Ensure the .wasm binary is traced into the serverless function bundle for
  // the gated route (the glue reads it from disk at first call).
  outputFileTracingIncludes: {
    "/api/secret": ["../pops-core-wasm/pkg/*.wasm"],
  },

  // Belt-and-braces: `serverExternalPackages` alone did not stop Next 15 from
  // inlining the glue during the build-time page-data pass, so also force the
  // package to a runtime CommonJS `require` for the server build. Combined with
  // the route's lazy `import()`, the module is neither evaluated at build nor
  // bundled — it loads from node_modules at request time, `__dirname` intact.
  webpack: (config, { isServer }) => {
    if (isServer) {
      const externals = Array.isArray(config.externals) ? config.externals : [config.externals].filter(Boolean);
      externals.push({
        "@makeprisms/pops-core-wasm": "commonjs @makeprisms/pops-core-wasm",
      });
      config.externals = externals;
    }
    return config;
  },
};

module.exports = nextConfig;
