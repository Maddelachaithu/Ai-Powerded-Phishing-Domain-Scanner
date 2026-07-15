import React from 'react';

export default function ConfidenceBadge({ confidence }) {
  if (confidence !== 'reduced') return null;
  
  return (
    <span className="confidence-badge" title="crt.sh Certificate transparency log query timed out. Scoring assumes no certificate is present, but results may be incomplete.">
      ⚠️ Partial Data (Reduced Confidence)
    </span>
  );
}
