import axios from 'axios';
import { getConfig } from './config.js';

const IOTVAS_BASE_URL = 'https://iotvas-api.firmalyzer.com/api/v1';

/**
 * Create axios client with auth headers
 */
function createClient() {
  const apiKey = getConfig('apiKey');

  if (!apiKey) {
    throw new Error('API key not configured. Run: firmalyzercomiotvas config set --api-key <key>');
  }

  return axios.create({
    baseURL: IOTVAS_BASE_URL,
    headers: {
      'x-api-key': apiKey,
      'Content-Type': 'application/json'
    }
  });
}

function handleApiError(error) {
  if (error.response) {
    const status = error.response.status;
    const data = error.response.data;

    if (status === 401) {
      throw new Error('Authentication failed. Check your API key.');
    } else if (status === 403) {
      throw new Error('Access forbidden. Check your API permissions.');
    } else if (status === 404) {
      throw new Error('Resource not found.');
    } else if (status === 429) {
      throw new Error('Rate limit exceeded. Please wait before retrying.');
    } else {
      const message = data?.message || data?.error || JSON.stringify(data);
      throw new Error(`API Error (${status}): ${message}`);
    }
  } else if (error.request) {
    throw new Error('No response from IoTVAS API. Check your internet connection.');
  } else {
    throw error;
  }
}

// ============================================================
// DEVICE DETECTION
// ============================================================

export async function detectDevice(banners) {
  const client = createClient();
  try {
    const response = await client.post('/device/detect', banners);
    return response.data;
  } catch (error) {
    handleApiError(error);
  }
}

export async function listDevices(params = {}) {
  const client = createClient();
  try {
    const response = await client.get('/devices', { params });
    return response.data;
  } catch (error) {
    handleApiError(error);
  }
}

export async function getDevice(deviceId) {
  const client = createClient();
  try {
    const response = await client.get(`/devices/${deviceId}`);
    return response.data;
  } catch (error) {
    handleApiError(error);
  }
}

// ============================================================
// VULNERABILITIES
// ============================================================

export async function listVulnerabilities(params = {}) {
  const client = createClient();
  try {
    const response = await client.get('/vulnerabilities', { params });
    return response.data;
  } catch (error) {
    handleApiError(error);
  }
}

export async function getVulnerability(cveId) {
  const client = createClient();
  try {
    const response = await client.get(`/vulnerabilities/${cveId}`);
    return response.data;
  } catch (error) {
    handleApiError(error);
  }
}

export async function searchVulnerabilities(query) {
  const client = createClient();
  try {
    const response = await client.post('/vulnerabilities/search', { query });
    return response.data;
  } catch (error) {
    handleApiError(error);
  }
}

// ============================================================
// FIRMWARE
// ============================================================

export async function analyzeFirmware(firmwareHash) {
  const client = createClient();
  try {
    const response = await client.post('/firmware/analyze', { hash: firmwareHash });
    return response.data;
  } catch (error) {
    handleApiError(error);
  }
}

export async function getFirmwareReport(reportId) {
  const client = createClient();
  try {
    const response = await client.get(`/firmware/reports/${reportId}`);
    return response.data;
  } catch (error) {
    handleApiError(error);
  }
}

export async function listFirmwareReports(params = {}) {
  const client = createClient();
  try {
    const response = await client.get('/firmware/reports', { params });
    return response.data;
  } catch (error) {
    handleApiError(error);
  }
}
