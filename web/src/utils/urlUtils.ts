/**
 * URL Utility Functions for KeyPouch
 * Automatically converts URLs to HTTPS based on configuration
 */

// Configuration constants - these can be overridden by environment variables
const AUTO_HTTPS_ENABLED = true;
const DEFAULT_URL_PROTOCOL = 'https';
const URL_DOMAIN_REGEX = /^(www\.|http:\/\/)/;

/**
 * Converts a URL to HTTPS if auto-HTTPS is enabled
 * @param {string} url - The URL to convert
 * @returns {string} - The converted URL
 */
export const autoHttpsUrl = (url: string): string => {
  if (!url || !AUTO_HTTPS_ENABLED) {
    return url;
  }

  try {
    const urlObj = new URL(url);
    
    // Check if URL matches the regex pattern (www. or http://)
    if (URL_DOMAIN_REGEX.test(url)) {
      // Convert to HTTPS
      urlObj.protocol = 'https:';
      return urlObj.toString();
    }
    
    return url;
  } catch (error) {
    console.warn('Invalid URL provided to autoHttpsUrl:', url, error);
    return url;
  }
};

/**
 * Ensures a URL has the correct protocol
 * @param {string} url - The URL to process
 * @param {string} defaultProtocol - Default protocol (https, http)
 * @returns {string} - The processed URL
 */
export const normalizeUrl = (url: string, defaultProtocol: string = DEFAULT_URL_PROTOCOL): string => {
  if (!url) return url;
  
  try {
    const urlObj = new URL(url);
    
    // If no protocol, add default
    if (!urlObj.protocol) {
      return `${defaultProtocol}://${url}`;
    }
    
    // Apply auto-HTTPS conversion
    return autoHttpsUrl(url);
  } catch (error) {
    // If URL parsing fails, try to add protocol
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      return `${defaultProtocol}://${url}`;
    }
    return url;
  }
};

/**
 * Batch process multiple URLs
 * @param {string[]} urls - Array of URLs to process
 * @returns {string[]} - Array of processed URLs
 */
export const batchNormalizeUrls = (urls: string[]): string[] => {
  return urls.map(url => normalizeUrl(url));
};

/**
 * Check if a URL is HTTPS
 * @param {string} url - The URL to check
 * @returns {boolean} - True if HTTPS
 */
export const isHttps = (url: string): boolean => {
  try {
    return new URL(url).protocol === 'https:';
  } catch (error) {
    return false;
  }
};

/**
 * Extract domain from URL
 * @param {string} url - The URL
 * @returns {string} - The domain
 */
export const extractDomain = (url: string): string => {
  try {
    return new URL(url).hostname;
  } catch (error) {
    return url;
  }
};

/**
 * React Hook for URL normalization
 * @returns {object} - URL utility functions
 */
export const useUrlUtils = () => {
  return {
    autoHttpsUrl,
    normalizeUrl,
    batchNormalizeUrls,
    isHttps,
    extractDomain
  };
};
