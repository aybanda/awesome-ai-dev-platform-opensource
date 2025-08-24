// URL validation utilities to prevent SSRF (Server-Side Request Forgery) attacks
// This file provides comprehensive security measures to prevent internal network access

export class UrlValidator {
  private static readonly ALLOWED_PROTOCOLS = ['http:', 'https:'];
  private static readonly ALLOWED_DOMAINS = [
    'aixblock.io',
    'api.aixblock.io',
    'staging-api.aixblock.io',
    'localhost' // Only for development
  ];
  
  private static readonly BLOCKED_IPS = [
    '127.0.0.1',
    'localhost',
    '0.0.0.0',
    '::1'
  ];

  /**
   * Validates if a URL is safe to use (prevents SSRF)
   */
  static isValidUrl(url: string): boolean {
    try {
      const parsedUrl = new URL(url);
      
      // Check protocol
      if (!this.ALLOWED_PROTOCOLS.includes(parsedUrl.protocol)) {
        console.warn(`Blocked URL with invalid protocol: ${parsedUrl.protocol}`);
        return false;
      }
      
      // Check for blocked IPs
      if (this.BLOCKED_IPS.includes(parsedUrl.hostname)) {
        console.warn(`Blocked URL with blocked IP: ${parsedUrl.hostname}`);
        return false;
      }
      
      // Check for localhost variations
      if (parsedUrl.hostname.includes('localhost') || 
          parsedUrl.hostname.includes('127.0.0.1')) {
        console.warn(`Blocked URL with localhost variation: ${parsedUrl.hostname}`);
        return false;
      }
      
      // Check for private IP ranges
      if (this.isPrivateIP(parsedUrl.hostname)) {
        console.warn(`Blocked URL with private IP: ${parsedUrl.hostname}`);
        return false;
      }
      
      // Check domain whitelist (only in production)
      if (process.env.NODE_ENV === 'production') {
        if (!this.ALLOWED_DOMAINS.some(domain => 
          parsedUrl.hostname.endsWith(domain))) {
          console.warn(`Blocked URL with unauthorized domain: ${parsedUrl.hostname}`);
          return false;
        }
      }
      
      return true;
    } catch (error) {
      console.error('URL validation error:', error);
      return false;
    }
  }

  /**
   * Checks if an IP address is in private ranges
   */
  private static isPrivateIP(hostname: string): boolean {
    // Simple check for common private IP patterns
    const privatePatterns = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./
    ];
    
    return privatePatterns.some(pattern => pattern.test(hostname));
  }

  /**
   * Sanitizes a URL to ensure it's safe
   */
  static sanitizeUrl(url: string): string {
    if (this.isValidUrl(url)) {
      return url;
    }
    
    // Return safe default if URL is invalid
    console.warn(`URL sanitized from ${url} to safe default`);
    return 'https://api.aixblock.io';
  }

  /**
   * Validates and sanitizes model trial URL specifically
   */
  static getSafeModelTrialUrl(): string {
    // Import the environment configuration
    try {
      // Dynamic import to avoid circular dependencies
      const { getSafeModelTrialUrl } = require('../config/environment');
      const url = getSafeModelTrialUrl();
      
      if (this.isValidUrl(url)) {
        return url;
      }
    } catch (error) {
      console.warn('Environment config not available, using safe default');
    }
    
    // Return safe production URL as fallback
    return 'https://api.aixblock.io/model_trial';
  }

  /**
   * Logs security events for monitoring
   */
  static logSecurityEvent(event: string, details: any): void {
    if (process.env.NODE_ENV === 'production') {
      console.warn(`[SECURITY] ${event}:`, details);
      // In production, you might want to send this to a security monitoring service
    } else {
      console.log(`[SECURITY] ${event}:`, details);
    }
  }
}
