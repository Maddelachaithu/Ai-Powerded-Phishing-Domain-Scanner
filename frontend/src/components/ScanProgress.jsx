import React from 'react';

export default function ScanProgress({ checked, total, status }) {
  if (status !== 'running') return null;

  const percentage = total > 0 ? Math.round((checked / total) * 100) : 0;

  return (
    <div className="progress-card">
      <div className="progress-header">
        <div className="progress-status-container">
          <span className="scanner-status-pulse"></span>
          <span className="progress-status-text">Scanning candidates...</span>
        </div>
        <span className="progress-ratio">
          {checked} / {total} processed ({percentage}%)
        </span>
      </div>
      <div className="progress-bar-track">
        <div 
          className="progress-bar-fill" 
          style={{ width: `${percentage}%` }}
        ></div>
      </div>
      <div className="progress-footer-tip">
        DNS queries and Certificate Transparency logs are being analyzed in parallel.
      </div>
    </div>
  );
}
