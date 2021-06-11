/**
 * Copyright (c) 2021 Nordic Semiconductor ASA
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * This script creates CA certs to use for creating device certificates.
 *
 * Example usage:
 * node dist/create-ca-cert.js --cnSubjectPrefix '/C=NO/ST=Norway/L=Trondheim/O=Nordic Semiconductor' --ou 'Test Devices'
 */

import { execSync } from 'child_process';
import { join } from 'path';
import * as yargs from 'yargs';

const defaultCertDir = join(__dirname, '../certs');

const args = yargs
  .scriptName('ca-cert-creator')
  .usage('$0 <cmd> [args]')
  .option('cnSubjectPrefix', {
    type: 'string',
    description: 'The prefix for the cert Subject.',
  })
  .option('ouName', {
    alias: 'ou',
    type: 'string',
    description: 'The Organizational Unit (OU) name of the cert Subject.',
  })
  .option('certFileNamePrefix', {
    alias: 'fn',
    type: 'string',
    description: 'The prefix for the CA cert files.',
    default: 'ca-cert',
  })
  .option('certDir', {
    alias: 'cd',
    type: 'string',
    description:
      'The absolute path to the directory to save the created cert files.',
    default: defaultCertDir,
  })
  .demandOption(['cnSubjectPrefix', 'ouName'])
  .help().argv;

/* tslint:disable-next-line:no-floating-promises */
handler(args);

async function handler({
  cnSubjectPrefix,
  ouName,
  certFileNamePrefix,
  certDir,
}: typeof args) {
  const subject = `${cnSubjectPrefix}/OU=${ouName}`;
  const certPath = `${certDir}/${certFileNamePrefix}`;

  execSync(`openssl ecparam -out ${certPath}.key.pem -name prime256v1 -genkey`);
  execSync(
    `openssl req -x509 -extensions v3_ca -new -nodes -key ${certPath}.key.pem -sha256 -days 1024 -out ${certPath}.crt.pem -subj "${subject}"`,
  );
  console.log(`CA cert files written to ${certDir}.`);
}
