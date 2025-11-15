// API service for communicating with backend

import axios from 'axios';
import { TestMetadata, TestDetails, TestFile, FileContent } from '../types/test';

const API_BASE_URL = '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
});

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

/**
 * Get all tests with optional filtering
 */
export async function getAllTests(filters?: {
  search?: string;
  technique?: string;
  category?: string;
  severity?: string;
}): Promise<TestMetadata[]> {
  try {
    const response = await api.get('/tests', { params: filters });
    return response.data.tests;
  } catch (error) {
    console.error('Error fetching tests:', error);
    throw error;
  }
}

/**
 * Get detailed information about a specific test
 */
export async function getTestDetails(uuid: string): Promise<TestDetails> {
  try {
    const response = await api.get(`/tests/${uuid}`);
    return response.data.test;
  } catch (error) {
    console.error('Error fetching test details:', error);
    throw error;
  }
}

/**
 * Get list of files in a test
 */
export async function getTestFiles(uuid: string): Promise<TestFile[]> {
  try {
    const response = await api.get(`/tests/${uuid}/files`);
    return response.data.files;
  } catch (error) {
    console.error('Error fetching test files:', error);
    throw error;
  }
}

/**
 * Get content of a specific file
 */
export async function getFileContent(uuid: string, filename: string): Promise<FileContent> {
  try {
    const response = await api.get(`/tests/${uuid}/file/${filename}`);
    return response.data.file;
  } catch (error) {
    console.error('Error fetching file content:', error);
    throw error;
  }
}

/**
 * Get attack flow diagram HTML
 */
export async function getAttackFlow(uuid: string): Promise<string> {
  try {
    const response = await api.get(`/tests/${uuid}/attack-flow`);
    return response.data.html;
  } catch (error) {
    console.error('Error fetching attack flow:', error);
    throw error;
  }
}

/**
 * Refresh test index
 */
export async function refreshTests(): Promise<void> {
  try {
    await api.post('/tests/refresh');
  } catch (error) {
    console.error('Error refreshing tests:', error);
    throw error;
  }
}
