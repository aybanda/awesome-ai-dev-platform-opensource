/* eslint-disable react/jsx-no-target-blank */

import React from "react";
import { escapeHtml } from "./utilities";

const URL_CORS_DOCS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors";

export default {
  DONE: "Done!",
  NO_COMP_LEFT: "No more annotations",
  NO_NEXT_TASK: "No More Tasks Left in Queue",
  NO_ACCESS: "You don't have access to this task",

  CONFIRM_TO_DELETE_ALL_REGIONS: "Please confirm you want to delete all labeled regions",

  // Tree validation messages
  ERR_REQUIRED: ({ modelName, field }) => {
    return `Attribute <b>${escapeHtml(field)}</b> is required for <b>${escapeHtml(modelName)}</b>`;
  },

  ERR_UNKNOWN_TAG: ({ modelName, field, value }) => {
    return `Tag with name <b>${escapeHtml(value)}</b> is not registered. Referenced by <b>${escapeHtml(modelName)}#${escapeHtml(field)}</b>.`;
  },

  ERR_TAG_NOT_FOUND: ({ modelName, field, value }) => {
    return `Tag with name <b>${escapeHtml(value)}</b> does not exist in the config. Referenced by <b>${escapeHtml(modelName)}#${escapeHtml(field)}</b>.`;
  },

  ERR_TAG_UNSUPPORTED: ({ modelName, field, value, validType }) => {
    return `Invalid attribute <b>${escapeHtml(field)}</b> for <b>${escapeHtml(modelName)}</b>: referenced tag is <b>${escapeHtml(value)}</b>, but <b>${escapeHtml(modelName)}</b> can only control <b>${[]
      .concat(validType)
      .map(escapeHtml)
      .join(", ")}</b>`;
  },

  ERR_PARENT_TAG_UNEXPECTED: ({ validType, value }) => {
    return `Tag <b>${escapeHtml(value)}</b> must be a child of one of the tags <b>${[].concat(validType).map(escapeHtml).join(", ")}</b>.`;
  },

  ERR_BAD_TYPE: ({ modelName, field, validType }) => {
    return `Attribute <b>${escapeHtml(field)}</b> of tag <b>${escapeHtml(modelName)}</b> has invalid type. Valid types are: <b>${escapeHtml(validType)}</b>.`;
  },

  ERR_INTERNAL: ({ value }) => {
    return `Internal error. See browser console for more info. Try again or contact developers.<br/>${escapeHtml(value)}`;
  },

  ERR_GENERAL: ({ value }) => {
    // SECURITY FIX: HTML-encode the value to prevent XSS
    return escapeHtml(value);
  },

  // Object loading errors
  URL_CORS_DOCS,

  ERR_LOADING_AUDIO: ({ attr, url, error }) => (
    <p>
      Error while loading audio. Check <code>{escapeHtml(attr)}</code> field in task.
      <br />
      Technical description: {escapeHtml(error)}
      <br />
      URL: {escapeHtml(url)}
    </p>
  ),

  ERR_LOADING_S3: ({ attr, url }) => `
    <div>
      <p>
        There was an issue loading URL from <code>${escapeHtml(attr)}</code> value.
        The request parameters are invalid.
        If you are using S3, make sure you've specified the right bucket region name.
      </p>
      <p>URL: <code><a href="${escapeHtml(url)}" target="_blank">${escapeHtml(url)}</a></code></p>
    </div>
  `,

  ERR_LOADING_CORS: ({ attr, url }) => `
    <div>
      <p>
        There was an issue loading URL from <code>${escapeHtml(attr)}</code> value.
        Most likely that's because static server has wide-open CORS.
        <a href="${URL_CORS_DOCS}" target="_blank">Read more on that here.</a>
      </p>
      <p>
        Also check that:
        <ul>
          <li>URL is valid</li>
          <li>Network is reachable</li>
        </ul>
      </p>
      <p>URL: <code><a href="${escapeHtml(url)}" target="_blank">${escapeHtml(url)}</a></code></p>
    </div>
  `,

  ERR_LOADING_HTTP: ({ attr, url, error }) => `
    <div>
      <p>
        There was an issue loading URL from <code>${escapeHtml(attr)}</code> value
      </p>
      <p>
        Things to look out for:
        <ul>
          <li>URL is valid</li>
          <li>URL scheme matches the service scheme, i.e. https and https</li>
          <li>
            The static server has wide-open CORS,
            <a href="${URL_CORS_DOCS}" target="_blank">more on that here</a>
          </li>
        </ul>
      </p>
      <p>
        Technical description: <code>${escapeHtml(error)}</code>
        <br />
        URL: <code><a href="${escapeHtml(url)}" target="_blank">${escapeHtml(url)}</a></code>
      </p>
    </div>
  `,
};
