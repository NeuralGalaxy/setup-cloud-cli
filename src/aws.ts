import * as core from '@actions/core';
import assert from 'assert';
import aws from 'aws-sdk';
import fs from 'fs';
import path from 'path';

// The max time that a GitHub action is allowed to run is 6 hours.
// That seems like a reasonable default to use if no role duration is defined.
const MAX_ACTION_RUNTIME = 6 * 3600;
const DEFAULT_ROLE_DURATION_FOR_OIDC_ROLES = 3600;
const USER_AGENT = 'configure-aws-credentials-for-github-actions';
const MAX_TAG_VALUE_LENGTH = 256;
const SANITIZATION_CHARACTER = '_';
const ROLE_SESSION_NAME = 'GitHubActions';
const REGION_REGEX = /^[a-z0-9-]+$/g;

async function loadCredentials(): Promise<aws.Credentials> {
  // Force the SDK to re-resolve credentials with the default provider chain.
  //
  // This action typically sets credentials in the environment via environment variables.
  // The SDK never refreshes those env-var-based credentials after initial load.
  // In case there were already env-var creds set in the actions environment when this action
  // loaded, this action needs to refresh the SDK creds after overwriting those environment variables.
  //
  // The credentials object needs to be entirely recreated (instead of simply refreshed),
  // because the credential object type could change when this action writes env var creds.
  // For example, the first load could return EC2 instance metadata credentials
  // in a self-hosted runner, and the second load could return environment credentials
  // from an assume-role call in this action.
  aws.config.credentials = null;

  return new Promise((resolve, reject) => {
    aws.config.getCredentials(err => {
      if (err) {
        reject(err);
      }
      const credentials = aws.config.credentials;
      if (credentials) {
        resolve(credentials as aws.Credentials);
      }
    });
  });
}

async function validateCredentials(expectedAccessKeyId: string): Promise<void> {
  let credentials;
  try {
    credentials = await loadCredentials();

    if (!credentials.accessKeyId) {
      throw new Error('Access key ID empty after loading credentials');
    }
  } catch (error) {
    throw new Error(
      `Credentials could not be loaded, please check your action inputs: ${
        (error as Error).message
      }`
    );
  }

  const actualAccessKeyId = credentials.accessKeyId;

  if (expectedAccessKeyId && expectedAccessKeyId !== actualAccessKeyId) {
    throw new Error(
      'Unexpected failure: Credentials loaded by the SDK do not match the access key ID configured by the action'
    );
  }
}

function getStsClient(region: string): aws.STS {
  return new aws.STS({
    region,
    stsRegionalEndpoints: 'regional',
    customUserAgent: USER_AGENT
  });
}

interface Credentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

function exportCredentials(params: Credentials): void {
  // Configure the AWS CLI and AWS SDKs using environment variables and set them as secrets.
  // Setting the credentials as secrets masks them in Github Actions logs
  const {accessKeyId, secretAccessKey, sessionToken} = params;

  // AWS_ACCESS_KEY_ID:
  // Specifies an AWS access key associated with an IAM user or role
  core.setSecret(accessKeyId);
  core.exportVariable('AWS_ACCESS_KEY_ID', accessKeyId);

  // AWS_SECRET_ACCESS_KEY:
  // Specifies the secret key associated with the access key. This is essentially the "password" for the access key.
  core.setSecret(secretAccessKey);
  core.exportVariable('AWS_SECRET_ACCESS_KEY', secretAccessKey);

  // AWS_SESSION_TOKEN:
  // Specifies the session token value that is required if you are using temporary security credentials.
  if (sessionToken) {
    core.setSecret(sessionToken);
    core.exportVariable('AWS_SESSION_TOKEN', sessionToken);
  } else if (process.env.AWS_SESSION_TOKEN) {
    // clear session token from previous credentials action
    core.exportVariable('AWS_SESSION_TOKEN', '');
  }
}

export function unsetAWSCredentials(): void {
  const awsCredentialsVars = [
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN'
  ];

  for (const key of awsCredentialsVars) {
    core.exportVariable(key, '');
  }

  core.exportVariable('AWS_REGION', process.env.AWS_US_REGION);
  core.exportVariable('AWS_DEFAULT_REGION', process.env.AWS_US_REGION);
}

function exportRegion(region: string): void {
  // AWS_DEFAULT_REGION and AWS_REGION:
  // Specifies the AWS Region to send requests to
  // eslint-disable-next-line i18n-text/no-en
  core.info(`Export AWS Region: ${region}`);
  core.exportVariable('AWS_DEFAULT_REGION', region);
  core.exportVariable('AWS_REGION', region);
}

async function exportAccountId(
  maskAccountId: string | undefined,
  region: string
): Promise<string> {
  // Get the AWS account ID
  const sts = getStsClient(region);
  const identity = await sts.getCallerIdentity().promise();
  const accountId = identity.Account as string;
  if (!maskAccountId || maskAccountId.toLowerCase() === 'true') {
    core.setSecret(accountId);
  }
  core.setOutput('aws-account-id', accountId);
  return accountId;
}

export interface AWSParameters {
  accessKeyId?: string;
  secretAccessKey?: string;
  region: string;
  sessionToken?: string;
  maskAccountId?: string;
  roleToAssume?: string;
  roleExternalId?: string;
  roleDurationSeconds?: number;
  roleSessionName?: string;
  roleSkipSessionTagging?: boolean;
  webIdentityTokenFile?: string;
}

export async function runAWS(params: AWSParameters): Promise<void> {
  // eslint-disable-next-line i18n-text/no-en
  core.info(`Setup aws for region ${params.region}`);
  try {
    // Get inputs
    const {
      accessKeyId,
      secretAccessKey,
      region,
      sessionToken,
      maskAccountId,
      roleToAssume,
      roleExternalId
    } = params;

    let roleDurationSeconds = params.roleDurationSeconds || MAX_ACTION_RUNTIME;
    const roleSessionName = params.roleSessionName || ROLE_SESSION_NAME;
    const roleSkipSessionTagging = params.roleSkipSessionTagging || false;
    const webIdentityTokenFile = params.webIdentityTokenFile;

    if (!region.match(REGION_REGEX)) {
      throw new Error(`Region is not valid: ${region}`);
    }

    exportRegion(region);

    // This wraps the logic for deciding if we should rely on the GH OIDC provider since we may need to reference
    // the decision in a few differennt places. Consolidating it here makes the logic clearer elsewhere.
    const useGitHubOIDCProvider = (): boolean => {
      // The assumption here is that self-hosted runners won't be populating the `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
      // environment variable and they won't be providing a web idenity token file or access key either.
      // V2 of the action might relax this a bit and create an explicit precedence for these so that customers
      // can provide as much info as they want and we will follow the established credential loading precedence.
      return (
        !!roleToAssume &&
        !!process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN &&
        !accessKeyId &&
        !webIdentityTokenFile
      );
    };

    // Always export the source credentials and account ID.
    // The STS client for calling AssumeRole pulls creds from the environment.
    // Plus, in the assume role case, if the AssumeRole call fails, we want
    // the source credentials and account ID to already be masked as secrets
    // in any error messages.
    if (accessKeyId) {
      if (!secretAccessKey) {
        throw new Error(
          "'aws-secret-access-key' must be provided if 'aws-access-key-id' is provided"
        );
      }

      exportCredentials({accessKeyId, secretAccessKey, sessionToken});
    }

    // Attempt to load credentials from the GitHub OIDC provider.
    // If a user provides an IAM Role Arn and DOESN'T provide an Access Key Id
    // The only way to assume the role is via GitHub's OIDC provider.
    let sourceAccountId;
    let webIdentityToken;
    if (useGitHubOIDCProvider()) {
      core.info('useGitHubOIDCProvider');
      webIdentityToken = await core.getIDToken('sts.amazonaws.com');
      roleDurationSeconds =
        params.roleDurationSeconds || DEFAULT_ROLE_DURATION_FOR_OIDC_ROLES;
      // We don't validate the credentials here because we don't have them yet when using OIDC.
    } else {
      // Regardless of whether any source credentials were provided as inputs,
      // validate that the SDK can actually pick up credentials.  This validates
      // cases where this action is on a self-hosted runner that doesn't have credentials
      // configured correctly, and cases where the user intended to provide input
      // credentials but the secrets inputs resolved to empty strings.
      await validateCredentials(accessKeyId as string);

      sourceAccountId = await exportAccountId(maskAccountId, region);
    }

    // Get role credentials if configured to do so
    if (roleToAssume) {
      core.setSecret(roleToAssume);
      // eslint-disable-next-line i18n-text/no-en
      core.info(`Assume AWS role ${roleToAssume}`);
      const roleCredentials = await assumeRole({
        sourceAccountId,
        region,
        roleToAssume,
        roleExternalId,
        roleDurationSeconds,
        roleSessionName,
        roleSkipSessionTagging,
        webIdentityTokenFile,
        webIdentityToken
      });
      exportCredentials(roleCredentials);
      // We need to validate the credentials in 2 of our use-cases
      // First: self-hosted runners. If the GITHUB_ACTIONS environment variable
      //  is set to `true` then we are NOT in a self-hosted runner.
      // Second: Customer provided credentials manually (IAM User keys stored in GH Secrets)
      if (!process.env.GITHUB_ACTIONS || accessKeyId) {
        await validateCredentials(roleCredentials.accessKeyId);
      }
      await exportAccountId(maskAccountId, region);
    }
  } catch (error) {
    core.setFailed((error as Error).message);

    const showStackTrace = process.env.SHOW_STACK_TRACE;

    if (showStackTrace === 'true') {
      throw error;
    }
  }
}

interface AssumeRoleParams {
  sourceAccountId?: string;
  roleToAssume: string;
  roleExternalId?: string;
  roleDurationSeconds: number;
  roleSessionName: string;
  region: string;
  roleSkipSessionTagging?: boolean;
  webIdentityTokenFile?: string;
  webIdentityToken?: string;
}

async function assumeRole(params: AssumeRoleParams): Promise<Credentials> {
  // Assume a role to get short-lived credentials using longer-lived credentials.
  const isDefined = (i: string | boolean | number | undefined): boolean => !!i;

  const {
    sourceAccountId,
    roleToAssume,
    roleExternalId,
    roleDurationSeconds,
    roleSessionName,
    region,
    roleSkipSessionTagging,
    webIdentityTokenFile,
    webIdentityToken
  } = params;
  assert(
    [roleToAssume, roleDurationSeconds, roleSessionName, region].every(
      isDefined
    ),
    'Missing required input when assuming a Role.'
  );

  const {
    GITHUB_REPOSITORY,
    GITHUB_WORKFLOW,
    GITHUB_ACTION,
    GITHUB_ACTOR,
    GITHUB_SHA
  } = process.env;

  core.debug(
    `${GITHUB_REPOSITORY} ${GITHUB_WORKFLOW} ${GITHUB_ACTION} ${GITHUB_ACTOR} ${GITHUB_SHA}`
  );

  assert(
    [
      GITHUB_REPOSITORY,
      GITHUB_WORKFLOW,
      GITHUB_ACTION,
      GITHUB_ACTOR
      // GITHUB_SHA
    ].every(isDefined),
    'Missing required environment value. Are you running in GitHub Actions?'
  );

  const sts = getStsClient(region);

  let roleArn = roleToAssume;
  if (!roleArn.startsWith('arn:aws')) {
    // Supports only 'aws' partition. Customers in other partitions ('aws-cn') will need to provide full ARN
    assert(
      isDefined(sourceAccountId),
      'Source Account ID is needed if the Role Name is provided and not the Role Arn.'
    );
    roleArn = `arn:aws:iam::${sourceAccountId}:role/${roleArn}`;
  }

  const tagArray = [
    {Key: 'GitHub', Value: 'Actions'},
    {Key: 'Repository', Value: GITHUB_REPOSITORY as string},
    {
      Key: 'Workflow',
      Value: sanitizeGithubWorkflowName(GITHUB_WORKFLOW as string)
    },
    {Key: 'Action', Value: GITHUB_ACTION as string},
    {Key: 'Actor', Value: sanitizeGithubActor(GITHUB_ACTOR as string)},
    {Key: 'Commit', Value: GITHUB_SHA as string}
  ];

  if (isDefined(process.env.GITHUB_REF)) {
    tagArray.push({Key: 'Branch', Value: process.env.GITHUB_REF as string});
  }

  const roleSessionTags = roleSkipSessionTagging ? undefined : tagArray;

  if (!roleSessionTags) {
    // eslint-disable-next-line i18n-text/no-en
    core.debug('Role session tagging has been skipped.');
  } else {
    core.debug(`${roleSessionTags.length} role session tags are being used.`);
  }

  const assumeRoleRequest: aws.STS.AssumeRoleRequest = {
    RoleArn: roleArn,
    RoleSessionName: roleSessionName,
    DurationSeconds: roleDurationSeconds,
    Tags: roleSessionTags
  };

  if (roleExternalId) {
    assumeRoleRequest.ExternalId = roleExternalId;
  }

  let assumeFunction = sts.assumeRole.bind(sts);

  // These are customizations needed for the GH OIDC Provider
  core.debug(`webIdentityToken=${webIdentityToken}`);
  core.debug(`webIdentityTokenFile=${webIdentityTokenFile}`);
  if (webIdentityToken) {
    delete assumeRoleRequest.Tags;

    (assumeRoleRequest as aws.STS.AssumeRoleWithWebIdentityRequest).WebIdentityToken = webIdentityToken;
    assumeFunction = sts.assumeRoleWithWebIdentity.bind(sts);
  } else if (webIdentityTokenFile) {
    core.debug(
      'webIdentityTokenFile provided. Will call sts:AssumeRoleWithWebIdentity and take session tags from token contents.'
    );
    delete assumeRoleRequest.Tags;

    const webIdentityTokenFilePath = path.isAbsolute(webIdentityTokenFile)
      ? webIdentityTokenFile
      : path.join(process.env.GITHUB_WORKSPACE as string, webIdentityTokenFile);

    if (!fs.existsSync(webIdentityTokenFilePath)) {
      throw new Error(
        `Web identity token file does not exist: ${webIdentityTokenFilePath}`
      );
    }

    try {
      (assumeRoleRequest as aws.STS.AssumeRoleWithWebIdentityRequest).WebIdentityToken = await fs.promises.readFile(
        webIdentityTokenFilePath,
        'utf8'
      );
      assumeFunction = sts.assumeRoleWithWebIdentity.bind(sts);
    } catch (error) {
      throw new Error(
        `Web identity token file could not be read: ${(error as Error).message}`
      );
    }
  }

  try {
    const credentials = (await assumeFunction(assumeRoleRequest).promise())
      .Credentials;

    assert(!!credentials, 'Should have assumed a role');

    return {
      accessKeyId: credentials.AccessKeyId,
      secretAccessKey: credentials.SecretAccessKey,
      sessionToken: credentials.SessionToken
    };
  } catch (error) {
    throw new Error(
      `Web identity token file could not be read: ${(error as Error).message}`
    );
  }
}

function sanitizeGithubActor(actor: string): string {
  // In some circumstances the actor may contain square brackets. For example, if they're a bot ('[bot]')
  // Square brackets are not allowed in AWS session tags
  return actor.replace(/\[|\]/g, SANITIZATION_CHARACTER);
}

function sanitizeGithubWorkflowName(name: string): string {
  // Workflow names can be almost any valid UTF-8 string, but tags are more restrictive.
  // This replaces anything not conforming to the tag restrictions by inverting the regular expression.
  // See the AWS documentation for constraint specifics https://docs.aws.amazon.com/STS/latest/APIReference/API_Tag.html.
  const nameWithoutSpecialCharacters = name.replace(
    /[^\p{L}\p{Z}\p{N}_:/=+.-@-]/gu,
    SANITIZATION_CHARACTER
  );
  const nameTruncated = nameWithoutSpecialCharacters.slice(
    0,
    MAX_TAG_VALUE_LENGTH
  );
  return nameTruncated;
}

export async function getAliyunCredentials(
  prefix: string,
  region: string
): Promise<{accessKeyId: string; secretAccessKey: string}> {
  exportRegion(region);
  const ssm = new aws.SSM();

  const accessKeyId = await ssm
    .getParameter({
      Name: `${prefix}_access_key_id`,
      WithDecryption: true
    })
    .promise();

  const secretAccessKey = await ssm
    .getParameter({
      Name: `${prefix}_access_key_secert`,
      WithDecryption: true
    })
    .promise();

  return {
    accessKeyId: accessKeyId.Parameter?.Value || '',
    secretAccessKey: secretAccessKey.Parameter?.Value || ''
  };
}
