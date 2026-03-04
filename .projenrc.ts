import { awscdk } from 'projen';
import { NodePackageManager, TrailingComma, Transform } from 'projen/lib/javascript';
const project = new awscdk.AwsCdkConstructLibrary({
  author: 'go-to-k',
  authorAddress: '24818752+go-to-k@users.noreply.github.com',
  // majorVersion: 1,
  cdkVersion: '2.178.1',
  defaultReleaseBranch: 'main',
  jsiiVersion: '~5.9.0',
  name: 'ecr-scan-verifier',
  projenrcTs: true,
  repositoryUrl: 'https://github.com/go-to-k/ecr-scan-verifier',
  description: 'Verify ECR image scan findings during CDK deployment',
  prettier: true,
  prettierOptions: {
    settings: {
      singleQuote: true,
      jsxSingleQuote: true,
      trailingComma: TrailingComma.ALL,
      semi: true,
      printWidth: 100,
    },
  },
  eslintOptions: {
    dirs: ['src'],
    prettier: true,
    ignorePatterns: [
      'example/**/*',
      'lambda/**/*',
      'test/assets/**/*',
      'test/*.snapshot/**/*',
      '*.d.ts',
    ],
  },
  jestOptions: {
    configFilePath: 'jest.config.json',
    jestConfig: {
      testEnvironment: 'node',
      roots: ['<rootDir>/test', '<rootDir>/assets/lambda/test'],
      testMatch: ['**/*.test.ts'],
      transform: {
        '^.+\\.tsx?$': new Transform('ts-jest'),
      },
      snapshotSerializers: ['<rootDir>/test/snapshot-plugin.ts'],
    },
  },
  license: 'Apache-2.0',
  keywords: [
    'aws',
    'cdk',
    'aws-cdk',
    'ecr',
    'container',
    'security',
    'vulnerability',
    'scan',
    'image-scanning',
  ],
  gitignore: [
    '*.js',
    '*.d.ts',
    'cdk.out/',
    '.DS_Store',
    'test/cdk-integ.*.snapshot/**/*',
    '!test/integ/**/integ.*.snapshot/**/*',
    'cosign.key',
    'cosign.pub',
  ],
  githubOptions: {
    pullRequestLintOptions: {
      semanticTitleOptions: {
        types: ['feat', 'fix', 'chore', 'docs', 'test', 'refactor', 'ci'],
      },
    },
  },
  tsconfigDev: {
    compilerOptions: {},
    exclude: ['test/integ/**/integ.*.snapshot', 'test/cdk-integ.*.snapshot'],
  },
  devDeps: [
    '@aws-cdk/integ-runner@2.178.1-alpha.0',
    '@aws-cdk/integ-tests-alpha@2.178.1-alpha.0',
    'aws-sdk-client-mock',
    'cdk-ecr-deployment@^4.1.1',
  ],
  packageManager: NodePackageManager.PNPM,
  workflowNodeVersion: '24',
  npmTrustedPublishing: true,
});
project.setScript('cdk', 'cdk');
project.setScript('build', 'tsc -p tsconfig.dev.json && npx projen build');
project.setScript('test', 'tsc -p tsconfig.dev.json && npx projen test');
project.setScript('test:watch', 'tsc -p tsconfig.dev.json && npx projen test:watch');
project.setScript(
  'integ',
  'tsc -p tsconfig.dev.json && cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd - && integ-runner',
);
project.setScript('integ:update', 'pnpm integ --update-on-failed');
project.setScript(
  'integ:basic',
  'tsc -p tsconfig.dev.json && cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd - && integ-runner --directory test/integ/basic',
);
project.setScript('integ:basic:update', 'pnpm integ:basic --update-on-failed');
project.setScript(
  'integ:enhanced',
  'tsc -p tsconfig.dev.json && cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd - && integ-runner --directory test/integ/enhanced',
);
project.setScript('integ:enhanced:update', 'pnpm integ:enhanced --update-on-failed');
project.setScript(
  'integ:signature',
  'tsc -p tsconfig.dev.json && cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd - && integ-runner --directory test/integ/signature',
);
project.setScript('integ:signature:update', 'pnpm integ:signature --update-on-failed');
project.setScript(
  'integ:signature:notation',
  'tsc -p tsconfig.dev.json && cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd - && integ-runner --test-regex "integ.notation.js$"',
);
project.setScript(
  'integ:signature:ecr-signing',
  'tsc -p tsconfig.dev.json && cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd - && integ-runner --test-regex "integ.ecr-signing.js$"',
);
project.setScript(
  'integ:signature:cosign-kms',
  'tsc -p tsconfig.dev.json && cd assets/lambda && pnpm install --frozen-lockfile && pnpm build && cd - && integ-runner --test-regex "integ.cosign-kms.js$"',
);
project.projectBuild.compileTask.prependExec('pnpm install --frozen-lockfile && pnpm build', {
  cwd: 'assets/lambda',
});
// Run basic, enhanced, and signature (CI-safe) tests
// cosign-publickey requires manual setup with environment variables
project.projectBuild.testTask.exec('pnpm integ:basic');
project.projectBuild.testTask.exec('pnpm integ:enhanced');
project.projectBuild.testTask.exec('pnpm integ:signature:notation');
project.projectBuild.testTask.exec('pnpm integ:signature:ecr-signing');
project.projectBuild.testTask.exec('pnpm integ:signature:cosign-kms');

project.synth();
