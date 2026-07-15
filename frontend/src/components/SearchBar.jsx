import React, { useState } from 'react';

export default function SearchBar({ onScan, loading }) {
  const [domain, setDomain] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    const val = domain.trim().toLowerCase();
    
    if (!val) {
      setError('Please enter a target domain.');
      return;
    }
    if (!val.includes('.')) {
      setError('Please enter a valid domain (e.g., brand.com) containing a dot.');
      return;
    }
    
    setError('');
    onScan(val);
  };

  return (
    <div className="search-container">
      <form onSubmit={handleSubmit} className="search-bar-form">
        <div className="search-input-wrapper">
          <span className="search-terminal-icon">&gt;_</span>
          <input
            type="text"
            className="search-input"
            placeholder="Target domain (e.g., paypal.com, google.com)..."
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            disabled={loading}
          />
        </div>
        <button type="submit" className="search-button" disabled={loading}>
          {loading ? (
            <span className="scanning-loader">
              <span className="spinner-dots">Scouting...</span>
            </span>
          ) : (
            'Scan Target'
          )}
        </button>
      </form>
      {error && <p className="search-error-msg">{error}</p>}
    </div>
  );
}
