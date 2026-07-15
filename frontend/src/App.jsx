import React, { useState, useMemo } from 'react';
import SearchBar from './components/SearchBar';
import ScanProgress from './components/ScanProgress';
import ResultCard from './components/ResultCard';
import './App.css';

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_BASE = API_URL;

export default function App() {
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('idle'); // idle, running, completed, failed
  const [error, setError] = useState('');
  
  const [domainScanned, setDomainScanned] = useState('');
  const [checked, setChecked] = useState(0);
  const [total, setTotal] = useState(0);
  const [flaggedCount, setFlaggedCount] = useState(0);
  const [unknownCount, setUnknownCount] = useState(0);
  const [results, setResults] = useState([]);
  
  // Filtering & Sorting State
  const [riskFilter, setRiskFilter] = useState('ALL'); // ALL, HIGH, MEDIUM, LOW
  const [confidenceFilter, setConfidenceFilter] = useState('ALL'); // ALL, full, reduced
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('score-desc'); // score-desc, score-asc, alpha-asc

  const handleScan = async (targetDomain) => {
    setLoading(true);
    setStatus('running');
    setError('');
    setChecked(0);
    setTotal(0);
    setFlaggedCount(0);
    setUnknownCount(0);
    setResults([]);
    setDomainScanned(targetDomain);

    // Generate a unique transaction id to query progress
    const clientScanId = `scan-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    // Set up polling interval to fetch progress metrics
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`${API_BASE}/api/scan/progress/${clientScanId}`);
        if (response.ok) {
          const progressData = await response.json();
          if (progressData.status === 'running') {
            setChecked(progressData.checked || 0);
            setTotal(progressData.total || 0);
            // Optional: update counts dynamically if backend gathers them
            setFlaggedCount(progressData.flagged_count || 0);
            setUnknownCount(progressData.unknown_count || 0);
          }
        }
      } catch (err) {
        console.warn('Unable to reach progress API', err);
      }
    }, 700);

    try {
      const response = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          domain: targetDomain,
          scan_id: clientScanId,
        }),
      });

      clearInterval(pollInterval);

      if (!response.ok) {
        const errDetail = await response.json();
        throw new Error(errDetail.detail || 'Failed to analyze target domain.');
      }

      const scanResult = await response.json();
      
      // Store results
      setResults(scanResult.results || []);
      setTotal(scanResult.total_variants_checked || 0);
      setChecked(scanResult.total_variants_checked || 0);
      setFlaggedCount(scanResult.flagged_count || 0);
      setUnknownCount(scanResult.unknown_count || 0);
      setDomainScanned(scanResult.domain_scanned);
      setStatus('completed');
    } catch (err) {
      clearInterval(pollInterval);
      setError(err.message || 'An unexpected error occurred during analysis.');
      setStatus('failed');
    } finally {
      setLoading(false);
    }
  };

  // Filter and sort the results array
  const filteredAndSortedResults = useMemo(() => {
    let output = [...results];

    // Filter by risk
    if (riskFilter !== 'ALL') {
      output = output.filter(r => r.risk_label === riskFilter);
    }

    // Filter by confidence
    if (confidenceFilter !== 'ALL') {
      output = output.filter(r => r.confidence === confidenceFilter);
    }

    // Filter by textual query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      output = output.filter(r => r.domain.toLowerCase().includes(q));
    }

    // Sort options
    if (sortBy === 'score-desc') {
      output.sort((a, b) => b.risk_score - a.risk_score);
    } else if (sortBy === 'score-asc') {
      output.sort((a, b) => a.risk_score - b.risk_score);
    } else if (sortBy === 'alpha-asc') {
      output.sort((a, b) => a.domain.localeCompare(b.domain));
    }

    return output;
  }, [results, riskFilter, confidenceFilter, searchQuery, sortBy]);

  return (
    <div className="app-layout">
      {/* Sidebar / Banner Title */}
      <header className="app-header">
        <div className="header-brand">
          <div className="brand-logo-shield">🛡️</div>
          <div>
            <h1>SENTINEL DOMAIN WATCH</h1>
            <p className="subtitle">Brand Protection Typosquat Scanner</p>
          </div>
        </div>
        <div className="header-status">
          <span className="api-badge">API: ONLINE</span>
        </div>
      </header>

      <main className="dashboard-container">
        {/* Input Control Center */}
        <section className="control-panel card-glow">
          <h2>Brand Protection Scouting</h2>
          <p className="panel-desc">
            Generate and scan typosquatting and homoglyph mutations for phishing risk assessment. 
            All audits query public records only.
          </p>
          <SearchBar onScan={handleScan} loading={loading} />
        </section>

        {/* Live Progress Bar */}
        <ScanProgress checked={checked} total={total} status={status} />

        {/* Error Notice */}
        {status === 'failed' && (
          <div className="error-card">
            <span className="error-card-title">⚠️ SCAN FAILED</span>
            <p className="error-card-body">{error}</p>
          </div>
        )}

        {/* Post-Scan Statistics Panel */}
        {status === 'completed' && (
          <section className="stats-grid">
            <div className="stat-card">
              <span className="stat-title">Target Brand</span>
              <span className="stat-value text-monospace">{domainScanned}</span>
            </div>
            <div className="stat-card">
              <span className="stat-title">Candidates Screened</span>
              <span className="stat-value">{total}</span>
            </div>
            <div className="stat-card warning-stat">
              <span className="stat-title">Flagged Typosquats</span>
              <span className="stat-value">{flaggedCount}</span>
            </div>
            <div className="stat-card info-stat">
              <span className="stat-title">Manual Audits Needed</span>
              <span className="stat-value">{unknownCount}</span>
            </div>
          </section>
        )}

        {/* Main Audit Results Area */}
        {results.length > 0 && (
          <section className="results-wrapper card-glow">
            <div className="results-header-row">
              <h3>Scouted Typosquat Findings ({filteredAndSortedResults.length})</h3>
              
              {/* Filters Controls Panel */}
              <div className="filter-controls-bar">
                <input 
                  type="text" 
                  placeholder="Filter by variant name..."
                  className="filter-text-input"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
                
                <select 
                  value={riskFilter} 
                  onChange={(e) => setRiskFilter(e.target.value)}
                  className="filter-select"
                >
                  <option value="ALL">All Risk Levels</option>
                  <option value="HIGH">Risk: HIGH</option>
                  <option value="MEDIUM">Risk: MEDIUM</option>
                  <option value="LOW">Risk: LOW</option>
                </select>

                <select 
                  value={confidenceFilter} 
                  onChange={(e) => setConfidenceFilter(e.target.value)}
                  className="filter-select"
                >
                  <option value="ALL">All Confidences</option>
                  <option value="full">Full Data</option>
                  <option value="reduced">Reduced Confidence (Manual Check)</option>
                </select>

                <select 
                  value={sortBy} 
                  onChange={(e) => setSortBy(e.target.value)}
                  className="filter-select"
                >
                  <option value="score-desc">Risk: High to Low</option>
                  <option value="score-asc">Risk: Low to High</option>
                  <option value="alpha-asc">Name: A to Z</option>
                </select>
              </div>
            </div>

            <div className="results-list">
              {filteredAndSortedResults.length > 0 ? (
                filteredAndSortedResults.map((result, idx) => (
                  <ResultCard key={idx} result={result} />
                ))
              ) : (
                <div className="empty-results">
                  No records match your selected filters. Try broadening your criteria.
                </div>
              )}
            </div>
          </section>
        )}

        {/* Idle/Initial screen layout */}
        {status === 'idle' && (
          <section className="idle-hero">
            <div className="hero-art">🔍</div>
            <h2>Scan Brands for Hostile Mutations</h2>
            <p>
              Typosquats are registered to hijack domain traffic or serve phishing templates. 
              Sentinel scans homoglyphs, omissions, TLD swaps, and prefixes, correlating DNS with Certificate Transparency.
            </p>
            <div className="example-tags">
              <span>Try scanning:</span>
              <button className="example-btn" onClick={() => handleScan('paypal.com')}>paypal.com</button>
              <button className="example-btn" onClick={() => handleScan('github.com')}>github.com</button>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
