// Environment configuration for different deployment stages
// This file replaces hardcoded internal URLs with secure, environment-based configuration
// to prevent SSRF (Server-Side Request Forgery) vulnerabilities

export const environment = {
  development: {
    apiBaseUrl: 'http://localhost:3000',
    modelTrialUrl: 'http://localhost:3000/model_trial'
  },
  staging: {
    apiBaseUrl: 'https://staging-api.aixblock.io',
    modelTrialUrl: 'https://staging-api.aixblock.io/model_trial'
  },
  production: {
    apiBaseUrl: 'https://api.aixblock.io',
    modelTrialUrl: 'https://api.aixblock.io/model_trial'
  }
};

// Get current environment
export const getCurrentEnvironment = () => {
  if (process.env.NODE_ENV === 'production') {
    return environment.production;
  } else if (process.env.NODE_ENV === 'staging') {
    return environment.staging;
  } else {
    return environment.development;
  }
};

// Get API base URL safely
export const getApiBaseUrl = () => {
  const env = getCurrentEnvironment();
  return env.apiBaseUrl;
};

// Get model trial URL safely
export const getModelTrialUrl = () => {
  const env = getCurrentEnvironment();
  return env.modelTrialUrl;
};

// Fallback to production if environment is not set
export const getSafeModelTrialUrl = () => {
  try {
    return getModelTrialUrl();
  } catch (error) {
    console.warn('Environment not configured, using production fallback');
    return environment.production.modelTrialUrl;
  }
};
