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
  .option('caCertKeyPath', {
    type: 'string',
    description: 'Absolute path to your CA private key pem file',
    default: `${defaultCertDir}/ca-cert.key.pem`,
  })
  .option('caCertPemPath', {
    type: 'string',
    description: 'Absolute path to your CA certificate pem file',
    default: `${defaultCertDir}/ca-cert.crt.pem`,
  })
  .option('certDir', {
    alias: 'cd',
    type: 'string',
    description:
      'The absolute path to the directory to save the created cert files.',
    default: defaultCertDir,
  })
  .demandOption(['cnSubject'])
  .help().argv;

handler(args).catch(console.error);

async function handler({
  deviceId,
  cnSubject,
  caCertKeyPath,
  caCertPemPath,
  certDir,
}: typeof args) {
  const certPath = `${certDir}/${deviceId}.crt.pem`;
  const keyPath = `${certDir}/${deviceId}.key.pem`;
  // Use ECC (ES256) instead of RSA. ECC is 50-100x faster:
  // http://ww1.microchip.com/downloads/en/DeviceDoc/00003442A.pdf
  execSync(
    `openssl ecparam -out ${keyPath} -name prime256v1 -genkey`,
    process.env,
  );
  execSync(
    `openssl req -new -key ${keyPath} -out ${certDir}/${deviceId}.csr.pem -subj "${cnSubject}/CN=${deviceId}"`,
    process.env,
  );
  execSync(
    `openssl x509 -req -in ${certDir}/${deviceId}.csr.pem -CA ${caCertPemPath} -CAkey ${caCertKeyPath} -CAcreateserial -out ${certPath} -days 10950 -sha256`,
    process.env,
  );
  console.log(
    `Device cert files for deviceId ${deviceId} written to ${certDir}.`,
  );
}
