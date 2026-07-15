import React, { useState } from 'react';
import RiskBadge from './RiskBadge';
import ConfidenceBadge from './ConfidenceBadge';

export default function ResultCard({ result }) {
  const [expanded, setExpanded] = useState(false);

  const {
    domain,
    dns_resolves,
    certificate_status,
    registered_date,
    registrar,
    risk_score,
    risk_label,
    confidence,
    reasons,
    techniques
  } = result;

  return (
    <div 
      className={`result-card ${expanded ? 'is-expanded' : ''}`} 
      onClick={() => setExpanded(!expanded)}
    >
      <div className="card-header">
        <div className="domain-section">
          <span className="domain-text-technical">{domain}</span>
          <ConfidenceBadge confidence={confidence} />
        </div>
        <div className="risk-score-badge-section">
          <RiskBadge label={risk_label} />
          <span className="risk-score-points">{risk_score} pts</span>
          <button className="expand-card-btn" aria-label="Toggle details">
            {expanded ? '▲' : '▼'}
          </button>
        </div>
      </div>

      <div className="card-summary-row">
        <div className="summary-field">
          <span className="summary-field-label">DNS Status:</span>
          <span className={`summary-field-value ${dns_resolves ? 'dns-active' : 'dns-inactive'}`}>
            {dns_resolves ? '● Active' : '○ Offline'}
          </span>
        </div>
        <div className="summary-field">
          <span className="summary-field-label">TLS Cert:</span>
          <span className={`summary-field-value cert-${certificate_status}`}>
            {certificate_status === 'confirmed' ? '✓ Found' : certificate_status === 'unknown' ? '? Unknown' : '✗ None'}
          </span>
        </div>
        <div className="summary-field">
          <span className="summary-field-label">Age/WHOIS:</span>
          <span className="summary-field-value text-muted">
            {registered_date ? registered_date : 'Unknown / Unregistered'}
          </span>
        </div>
      </div>

      {expanded && (
        <div className="card-details-panel" onClick={(e) => e.stopPropagation()}>
          <div className="details-divider"></div>
          
          <div className="danger-zone-alert">
            <span className="alert-icon">⚠️</span>
            <div className="alert-text-content">
              <strong>DO NOT VISIT THIS DOMAIN:</strong> Flagged domains are likely typosquats and could contain active malware, phishing, or social engineering attacks.
            </div>
          </div>

          <div className="tech-details-grid">
            <div className="tech-field">
              <span className="tech-label">Target Name:</span>
              <span className="tech-value">{domain}</span>
            </div>
            <div className="tech-field">
              <span className="tech-label">Registrar:</span>
              <span className="tech-value">{registrar || 'Not available'}</span>
            </div>
            <div className="tech-field">
              <span className="tech-label">Registration Date:</span>
              <span className="tech-value">{registered_date || 'Unknown'}</span>
            </div>
            <div className="tech-field">
              <span className="tech-label">Generation Method(s):</span>
              <span className="tech-value tag-list">
                {techniques && techniques.map((t, idx) => (
                  <span key={idx} className="tech-tag">{t}</span>
                ))}
              </span>
            </div>
          </div>

          <div className="risk-reasons-container">
            <span className="reasons-section-title">Risk Analysis Reasons:</span>
            <ul className="reasons-list">
              {reasons && reasons.length > 0 ? (
                reasons.map((r, index) => (
                  <li key={index} className="reason-item-bullet">
                    <span className="reason-bullet-marker">+</span>
                    <span className="reason-text">{r}</span>
                  </li>
                ))
              ) : (
                <li className="reason-item-bullet neutral">
                  <span className="reason-bullet-marker">○</span>
                  <span className="reason-text">No high risk signals matched (+0)</span>
                </li>
              )}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
