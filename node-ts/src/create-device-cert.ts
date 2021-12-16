/**
 * Copyright (c) 2021 Nordic Semiconductor ASA
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * This script creates ECC 256 device certificates.
 *
 * Example usage:
 * node dist/create-device-cert.js
 */

import { execSync } from 'child_process';
import { join } from 'path';
import * as yargs from 'yargs';
import { v4 } from 'uuid';

const defaultCertDir = join(__dirname, '../certs');

const args = yargs
  .scriptName('device-cert-creator')
  .usage('$0 <cmd> [args]')
  .option('deviceId', {
    type: 'string',
    default: process.env.DEVICE_ID || v4(),
  })
  .option('cnSubject', {
    type: 'string',
    default: '/C=NO/ST=Trondelag/L=Trondheim/O=Nordic Semiconductor ASA',
  })
  .option('certDir', {
    alias: 'cd',
    type: 'string',
    description:
      'The absolute path to the directory for storing the created CSR and certificate files.',
    default: defaultCertDir,
  })
  .option('csrFileName', {
    alias: 'csr',
    type: 'string',
    description: 'Name of your CSR pem file.',
  })
  .option('caCertKeyFileName', {
    alias: 'cak',
    type: 'string',
    description: 'Name of your CA private key pem file',
    default: 'ca-cert.key.pem',
  })
  .option('caCertPemFileName', {
    alias: 'cac',
    type: 'string',
    description: 'Name of your CA certificate pem file',
    default: 'ca-cert.crt.pem',
  })
  .demandOption(['cnSubject', 'caCertKeyFileName', 'caCertPemFileName'])
  .help().argv;

handler(args).catch(console.error);

async function handler({
  deviceId,
  cnSubject,
  certDir,
  csrFileName,
  caCertKeyFileName,
  caCertPemFileName,
}: typeof args) {
  const deviceCertPath = `${certDir}/${deviceId}.crt`;
  const deviceKeyPath = `${certDir}/${deviceId}.key`;
  // Use ECC (ES256) instead of RSA. ECC is 50-100x faster:
  // http://ww1.microchip.com/downloads/en/DeviceDoc/00003442A.pdf
  execSync(
    `openssl ecparam -out ${deviceKeyPath}.temp.pem -name prime256v1 -genkey`,
    process.env,
  );
  execSync(
    `openssl pkcs8 -topk8 -nocrypt -in ${deviceKeyPath}.temp.pem -out ${deviceKeyPath}.pem`,
    process.env,
  );
  execSync(
    `rm ${deviceKeyPath}.temp.pem`,
    process.env,
  );
  if (!csrFileName) {
    csrFileName = `${deviceId}.csr.pem`;
    execSync(
      `openssl req -new -key ${deviceKeyPath}.pem -out ${certDir}/${csrFileName} -subj "${cnSubject}/CN=${deviceId}"`,
      process.env,
    );
  }
  execSync(
    `openssl x509 -req -in ${certDir}/${csrFileName} -CA ${certDir}/${caCertPemFileName} -CAkey ${certDir}/${caCertKeyFileName} -CAcreateserial -out ${deviceCertPath}.pem -days 10950 -sha256`,
    process.env,
  );
  console.log(
    `Device cert files for deviceId ${deviceId} written to ${certDir}.`,
  );
}
