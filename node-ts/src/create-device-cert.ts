/**
 * Copyright (c) 2021 Nordic Semiconductor ASA
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * This script creates ECC 256 device certificates.
 *
 * Example usage:
 * export CA_CERT_KEY_PATH=<path to your CA cert's private key PEM file>
 * export CA_CERT_PEM_PATH=<path to your CA cert's certificate PEM file>
 * node dist/create-device-cert-offline.js --cnSubject '/C=NO/ST=Trondelag/L=Trondheim/O=Nordic Semiconductor ASA' --caCertKeyPath $CA_CERT_KEY_PATH --caCertPemPath $CA_CERT_PEM_PATH
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
  })
  .option('caCertKeyPath', {
    type: 'string',
    description: 'Absolute path to your CA private key pem file',
  })
  .option('caCertPemPath', {
    type: 'string',
    description: 'Absolute path to your CA certificate pem file',
  })
  .option('certDir', {
    alias: 'cd',
    type: 'string',
    description:
      'The absolute path to the directory to save the created cert files.',
    default: defaultCertDir,
  })
  .demandOption(['cnSubject', 'caCertKeyPath', 'caCertPemPath'])
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
  console.log(`Device cert files for ${deviceId} written to ${certDir}.`);
}
