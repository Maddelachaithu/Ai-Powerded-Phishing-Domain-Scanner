import React from 'react';

export default function RiskBadge({ label }) {
  let colorClass = 'badge-low';
  if (label === 'MEDIUM') colorClass = 'badge-medium';
  if (label === 'HIGH') colorClass = 'badge-high';
  
  return (
    <span className={`risk-badge ${colorClass}`}>
      {label}
    </span>
  );
}
