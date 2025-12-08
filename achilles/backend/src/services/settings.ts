import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as os from 'os';
import { AppSettings, ElasticsearchSettings } from '../types/analytics';

const SETTINGS_DIR = path.join(os.homedir(), '.achilles');
const SETTINGS_FILE = path.join(SETTINGS_DIR, 'settings.json');

// Derive encryption key from machine ID
function getEncryptionKey(): Buffer {
  const machineId = os.hostname() + os.userInfo().username;
  return crypto.createHash('sha256').update(machineId).digest();
}

// Encrypt a string
function encrypt(text: string): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

// Decrypt a string
function decrypt(encryptedText: string): string {
  const key = getEncryptionKey();
  const [ivHex, authTagHex, encrypted] = encryptedText.split(':');

  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// Default settings
const defaultSettings: AppSettings = {
  elasticsearch: {
    connectionType: 'cloud',
    cloudId: '',
    apiKey: '',
    indexPattern: 'f0rtika-results-*'
  },
  defaults: {
    dateRange: '7d',
    organization: null
  }
};

// Ensure settings directory exists
function ensureSettingsDir(): void {
  if (!fs.existsSync(SETTINGS_DIR)) {
    fs.mkdirSync(SETTINGS_DIR, { recursive: true });
  }
}

// Load settings from file
export function loadSettings(): AppSettings {
  ensureSettingsDir();

  if (!fs.existsSync(SETTINGS_FILE)) {
    return defaultSettings;
  }

  try {
    const data = fs.readFileSync(SETTINGS_FILE, 'utf8');
    const settings = JSON.parse(data) as AppSettings;

    // Decrypt sensitive fields
    if (settings.elasticsearch.cloudId?.startsWith('enc:')) {
      settings.elasticsearch.cloudId = decrypt(settings.elasticsearch.cloudId.slice(4));
    }
    if (settings.elasticsearch.apiKey?.startsWith('enc:')) {
      settings.elasticsearch.apiKey = decrypt(settings.elasticsearch.apiKey.slice(4));
    }
    if (settings.elasticsearch.password?.startsWith('enc:')) {
      settings.elasticsearch.password = decrypt(settings.elasticsearch.password.slice(4));
    }

    return settings;
  } catch (error) {
    console.error('Error loading settings:', error);
    return defaultSettings;
  }
}

// Save settings to file
export function saveSettings(settings: AppSettings): void {
  ensureSettingsDir();

  // Create a copy with encrypted sensitive fields
  const settingsToSave: AppSettings = {
    ...settings,
    elasticsearch: {
      ...settings.elasticsearch
    }
  };

  // Encrypt sensitive fields
  if (settingsToSave.elasticsearch.cloudId) {
    settingsToSave.elasticsearch.cloudId = 'enc:' + encrypt(settingsToSave.elasticsearch.cloudId);
  }
  if (settingsToSave.elasticsearch.apiKey) {
    settingsToSave.elasticsearch.apiKey = 'enc:' + encrypt(settingsToSave.elasticsearch.apiKey);
  }
  if (settingsToSave.elasticsearch.password) {
    settingsToSave.elasticsearch.password = 'enc:' + encrypt(settingsToSave.elasticsearch.password);
  }

  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settingsToSave, null, 2));
}

// Get settings with credentials masked
export function getMaskedSettings(): AppSettings {
  const settings = loadSettings();

  return {
    ...settings,
    elasticsearch: {
      ...settings.elasticsearch,
      cloudId: settings.elasticsearch.cloudId ? '********' : '',
      apiKey: settings.elasticsearch.apiKey ? '********' : '',
      password: settings.elasticsearch.password ? '********' : ''
    }
  };
}

// Check if settings are configured
export function isConfigured(): boolean {
  const settings = loadSettings();

  if (settings.elasticsearch.connectionType === 'cloud') {
    return !!(settings.elasticsearch.cloudId && settings.elasticsearch.apiKey);
  } else {
    return !!(settings.elasticsearch.node &&
      (settings.elasticsearch.apiKey ||
       (settings.elasticsearch.username && settings.elasticsearch.password)));
  }
}
