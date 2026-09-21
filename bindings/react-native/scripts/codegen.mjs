import { spawnSync } from 'node:child_process';

function node(args) {
  const result = spawnSync(process.execPath, args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
node(['node_modules/@react-native/codegen/lib/cli/combine/combine-js-to-schema-cli.js', 'scripts/schema.json', 'src/NativeNwcMobile.ts']);
for (const platform of ['android', 'ios']) {
  node(['node_modules/react-native/scripts/generate-specs-cli.js',
    '--platform', platform, '--schemaPath', 'scripts/schema.json',
    '--outputDir', `${platform}/generated`, '--libraryName', 'NwcMobileSpec',
    '--javaPackageName', 'com.nwcmobile.reactnative', '--libraryType', 'modules']);
}
