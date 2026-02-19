import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { getConfig, setConfig, isConfigured } from './config.js';
import {
  detectDevice,
  listDevices,
  getDevice,
  listVulnerabilities,
  getVulnerability,
  searchVulnerabilities,
  analyzeFirmware,
  getFirmwareReport,
  listFirmwareReports
} from './api.js';

const program = new Command();

// ============================================================
// Helpers
// ============================================================

function printSuccess(message) {
  console.log(chalk.green('✓') + ' ' + message);
}

function printError(message) {
  console.error(chalk.red('✗') + ' ' + message);
}

function printTable(data, columns) {
  if (!data || data.length === 0) {
    console.log(chalk.yellow('No results found.'));
    return;
  }

  const widths = {};
  columns.forEach(col => {
    widths[col.key] = col.label.length;
    data.forEach(row => {
      const val = String(col.format ? col.format(row[col.key], row) : (row[col.key] ?? ''));
      if (val.length > widths[col.key]) widths[col.key] = val.length;
    });
    widths[col.key] = Math.min(widths[col.key], 40);
  });

  const header = columns.map(col => col.label.padEnd(widths[col.key])).join('  ');
  console.log(chalk.bold(chalk.cyan(header)));
  console.log(chalk.dim('─'.repeat(header.length)));

  data.forEach(row => {
    const line = columns.map(col => {
      const val = String(col.format ? col.format(row[col.key], row) : (row[col.key] ?? ''));
      return val.substring(0, widths[col.key]).padEnd(widths[col.key]);
    }).join('  ');
    console.log(line);
  });

  console.log(chalk.dim(`\n${data.length} result(s)`));
}

function printJson(data) {
  console.log(JSON.stringify(data, null, 2));
}

async function withSpinner(message, fn) {
  const spinner = ora(message).start();
  try {
    const result = await fn();
    spinner.stop();
    return result;
  } catch (error) {
    spinner.stop();
    throw error;
  }
}

function requireAuth() {
  if (!isConfigured()) {
    printError('API key not configured.');
    console.log('\nRun the following to configure:');
    console.log(chalk.cyan('  firmalyzercomiotvas config set --api-key <key>'));
    process.exit(1);
  }
}

// ============================================================
// Program metadata
// ============================================================

program
  .name('firmalyzercomiotvas')
  .description(chalk.bold('IoTVAS CLI') + ' - IoT device discovery and vulnerability assessment')
  .version('1.0.0');

// ============================================================
// CONFIG
// ============================================================

const configCmd = program.command('config').description('Manage CLI configuration');

configCmd
  .command('set')
  .description('Set configuration values')
  .option('--api-key <key>', 'IoTVAS API key')
  .action((options) => {
    if (options.apiKey) {
      setConfig('apiKey', options.apiKey);
      printSuccess('API key set');
    } else {
      printError('No options provided. Use --api-key');
    }
  });

configCmd
  .command('show')
  .description('Show current configuration')
  .action(() => {
    const apiKey = getConfig('apiKey');

    console.log(chalk.bold('\nIoTVAS CLI Configuration\n'));
    console.log('API Key: ', apiKey ? chalk.green('*'.repeat(16)) : chalk.red('not set'));
    console.log('');
  });

// ============================================================
// DEVICES
// ============================================================

const devicesCmd = program.command('devices').description('Manage device detection');

devicesCmd
  .command('detect')
  .description('Detect device from network banners')
  .option('--snmp <banner>', 'SNMP sysdescr banner')
  .option('--ftp <banner>', 'FTP banner')
  .option('--telnet <banner>', 'Telnet banner')
  .option('--hostname <name>', 'Device hostname')
  .option('--http <response>', 'HTTP response')
  .option('--https <response>', 'HTTPS response')
  .option('--upnp <response>', 'UPnP response')
  .option('--mac <address>', 'MAC address')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    requireAuth();

    const banners = {};
    if (options.snmp) banners.snmp = options.snmp;
    if (options.ftp) banners.ftp = options.ftp;
    if (options.telnet) banners.telnet = options.telnet;
    if (options.hostname) banners.hostname = options.hostname;
    if (options.http) banners.http = options.http;
    if (options.https) banners.https = options.https;
    if (options.upnp) banners.upnp = options.upnp;
    if (options.mac) banners.mac = options.mac;

    if (Object.keys(banners).length === 0) {
      printError('No banners provided. Use --snmp, --ftp, --telnet, --hostname, --http, --https, --upnp, or --mac');
      process.exit(1);
    }

    try {
      const result = await withSpinner('Detecting device...', () => detectDevice(banners));

      if (options.json) {
        printJson(result);
        return;
      }

      printSuccess('Device detected');
      console.log(chalk.bold('\nDevice Information:\n'));
      console.log('Type:       ', result.type || 'N/A');
      console.log('Maker:      ', result.maker || 'N/A');
      console.log('Model:      ', result.model || 'N/A');
      console.log('EOL Status: ', result.eol_status || 'N/A');
      if (result.cves && result.cves.length > 0) {
        console.log('CVEs:       ', result.cves.join(', '));
      }
    } catch (error) {
      printError(error.message);
      process.exit(1);
    }
  });

devicesCmd
  .command('list')
  .description('List detected devices')
  .option('--limit <n>', 'Maximum number of results', '50')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    requireAuth();
    try {
      const devices = await withSpinner('Fetching devices...', () =>
        listDevices({ limit: parseInt(options.limit) })
      );

      if (options.json) {
        printJson(devices);
        return;
      }

      printTable(devices, [
        { key: 'id', label: 'ID' },
        { key: 'type', label: 'Type' },
        { key: 'maker', label: 'Maker' },
        { key: 'model', label: 'Model' },
        { key: 'eol_status', label: 'EOL Status' }
      ]);
    } catch (error) {
      printError(error.message);
      process.exit(1);
    }
  });

devicesCmd
  .command('get <device-id>')
  .description('Get device details')
  .option('--json', 'Output as JSON')
  .action(async (deviceId, options) => {
    requireAuth();
    try {
      const device = await withSpinner('Fetching device...', () => getDevice(deviceId));

      if (options.json) {
        printJson(device);
        return;
      }

      console.log(chalk.bold('\nDevice Details\n'));
      console.log('ID:         ', chalk.cyan(device.id));
      console.log('Type:       ', device.type || 'N/A');
      console.log('Maker:      ', device.maker || 'N/A');
      console.log('Model:      ', device.model || 'N/A');
      console.log('EOL Status: ', device.eol_status || 'N/A');
    } catch (error) {
      printError(error.message);
      process.exit(1);
    }
  });

// ============================================================
// VULNERABILITIES
// ============================================================

const vulnCmd = program.command('vulnerabilities').description('Manage vulnerabilities');

vulnCmd
  .command('list')
  .description('List vulnerabilities')
  .option('--limit <n>', 'Maximum number of results', '50')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    requireAuth();
    try {
      const vulns = await withSpinner('Fetching vulnerabilities...', () =>
        listVulnerabilities({ limit: parseInt(options.limit) })
      );

      if (options.json) {
        printJson(vulns);
        return;
      }

      printTable(vulns, [
        { key: 'cve_id', label: 'CVE ID' },
        { key: 'severity', label: 'Severity' },
        { key: 'score', label: 'Score' },
        { key: 'description', label: 'Description' }
      ]);
    } catch (error) {
      printError(error.message);
      process.exit(1);
    }
  });

vulnCmd
  .command('get <cve-id>')
  .description('Get vulnerability details')
  .option('--json', 'Output as JSON')
  .action(async (cveId, options) => {
    requireAuth();
    try {
      const vuln = await withSpinner('Fetching vulnerability...', () => getVulnerability(cveId));

      if (options.json) {
        printJson(vuln);
        return;
      }

      console.log(chalk.bold('\nVulnerability Details\n'));
      console.log('CVE ID:      ', chalk.cyan(vuln.cve_id));
      console.log('Severity:    ', vuln.severity || 'N/A');
      console.log('Score:       ', vuln.score || 'N/A');
      console.log('Description: ', vuln.description || 'N/A');
    } catch (error) {
      printError(error.message);
      process.exit(1);
    }
  });

vulnCmd
  .command('search <query>')
  .description('Search vulnerabilities')
  .option('--json', 'Output as JSON')
  .action(async (query, options) => {
    requireAuth();
    try {
      const results = await withSpinner('Searching vulnerabilities...', () =>
        searchVulnerabilities(query)
      );

      if (options.json) {
        printJson(results);
        return;
      }

      printTable(results, [
        { key: 'cve_id', label: 'CVE ID' },
        { key: 'severity', label: 'Severity' },
        { key: 'score', label: 'Score' },
        { key: 'description', label: 'Description' }
      ]);
    } catch (error) {
      printError(error.message);
      process.exit(1);
    }
  });

// ============================================================
// FIRMWARE
// ============================================================

const firmwareCmd = program.command('firmware').description('Manage firmware analysis');

firmwareCmd
  .command('analyze <hash>')
  .description('Analyze firmware by hash')
  .option('--json', 'Output as JSON')
  .action(async (hash, options) => {
    requireAuth();
    try {
      const result = await withSpinner('Analyzing firmware...', () => analyzeFirmware(hash));

      if (options.json) {
        printJson(result);
        return;
      }

      printSuccess('Firmware analysis started');
      console.log('Report ID: ', chalk.cyan(result.report_id || result.id));
    } catch (error) {
      printError(error.message);
      process.exit(1);
    }
  });

firmwareCmd
  .command('report <report-id>')
  .description('Get firmware analysis report')
  .option('--json', 'Output as JSON')
  .action(async (reportId, options) => {
    requireAuth();
    try {
      const report = await withSpinner('Fetching report...', () => getFirmwareReport(reportId));

      if (options.json) {
        printJson(report);
        return;
      }

      console.log(chalk.bold('\nFirmware Report\n'));
      console.log('Report ID: ', chalk.cyan(report.id));
      console.log('Status:    ', report.status || 'N/A');
      console.log('Hash:      ', report.hash || 'N/A');
    } catch (error) {
      printError(error.message);
      process.exit(1);
    }
  });

firmwareCmd
  .command('list-reports')
  .description('List firmware analysis reports')
  .option('--limit <n>', 'Maximum number of results', '50')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    requireAuth();
    try {
      const reports = await withSpinner('Fetching reports...', () =>
        listFirmwareReports({ limit: parseInt(options.limit) })
      );

      if (options.json) {
        printJson(reports);
        return;
      }

      printTable(reports, [
        { key: 'id', label: 'Report ID' },
        { key: 'hash', label: 'Hash' },
        { key: 'status', label: 'Status' },
        { key: 'created_at', label: 'Created' }
      ]);
    } catch (error) {
      printError(error.message);
      process.exit(1);
    }
  });

// ============================================================
// Parse
// ============================================================

program.parse(process.argv);

if (process.argv.length <= 2) {
  program.help();
}
