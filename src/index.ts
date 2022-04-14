import * as core from '@actions/core';
import assert from 'assert';
// eslint-disable-next-line sort-imports
import {getAliyunCredentials, runAWS, unsetAWSCredentials} from './aws';
import {runAliyun} from './aliyun';

const {
  AWS_US_ACTIONS_ROLE_ARN_PREFIX,
  AWS_CN_ACTIONS_ROLE_ARN_PREFIX,
  ALIYUN_ACTIONS_CRED_PREFIX,
  AWS_US_REGION,
  AWS_CN_REGION,
  ALIYUN_REGION,
  ACT
} = process.env;

async function run(): Promise<void> {
  try {
    unsetAWSCredentials();
    const profile = core.getInput('profile', {required: true}).toLowerCase();
    let region: string = AWS_US_REGION || 'us-east-1';

    assert(
      [
        AWS_US_ACTIONS_ROLE_ARN_PREFIX,
        AWS_CN_ACTIONS_ROLE_ARN_PREFIX,
        ALIYUN_ACTIONS_CRED_PREFIX
      ].every(v => !!v),
      'Cloud Role Parameters should be set properly'
    );

    let githubRepository = process.env.GITHUB_REPOSITORY;

    core.info(`GITHUB_REPOSITORY: ${githubRepository}`);

    assert(!!githubRepository);

    if (ACT === 'true') {
      githubRepository = 'NeuralGalaxy/ngiq-dataservice-server';
    }

    const [owner, repo] = githubRepository.split('/');

    assert(owner === 'NeuralGalaxy');

    let roleToAssume = `${AWS_US_ACTIONS_ROLE_ARN_PREFIX}${repo}`;

    const {accessKeyId, secretAccessKey} = await getAliyunCredentials(
      ALIYUN_ACTIONS_CRED_PREFIX as string,
      AWS_US_REGION as string
    );

    core.info(`Setup cloud cli: profile = ${profile}, region = ${region}`);

    switch (profile) {
      case 'aliyun':
      case 'aliyun-prod':
        region = ALIYUN_REGION || 'cn-hangzhou';
        await runAliyun({
          accessKeyId,
          secretAccessKey,
          region
        });
        break;
      case 'aws-cn':
        region = AWS_CN_REGION || 'cn-northwest-1';
        roleToAssume = `${AWS_CN_ACTIONS_ROLE_ARN_PREFIX}${repo}`;
      // eslint-disable-next-line no-fallthrough
      case 'aws-us':
      case 'default':
      default:
        await runAWS({
          region,
          roleToAssume,
          roleDurationSeconds: 3600
        });
        break;
    }
  } catch (error) {
    if (error instanceof Error) core.setFailed(error.message);
  }
}

run();
