// src/pages/Scanner.tsx - VERSION FINALE ULTRA-OPTIMISÉE
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import InputUrl from "../components/common/InputUrl";
import AppLayout from "../components/layout";
import ScanResultBox from "../pages/ScanResultBox";
import ScanService, { ScanResult } from "../services/ScanService";

interface ExtendedScanResult extends ScanResult {
  user_message?: string;
}

const Scanner: React.FC = () => {
  const [scanResult, setScanResult] = useState<ExtendedScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [pollCount, setPollCount] = useState(0);
  const [scansHistory, setScansHistory] = useState<ExtendedScanResult[]>([]);
  const [showResultDetails, setShowResultDetails] = useState(false);
  const [searchResults, setSearchResults] = useState<ExtendedScanResult[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [userMessage, setUserMessage] = useState<string | null>(null);
  
  const navigate = useNavigate();

  // 🔥 POLLING ULTRA-OPTIMISÉ - MINIMAL IMPACT
  useEffect(() => {
    let pollingTimeoutId: number | null = null;
    let currentInterval = 10000; // 🔥 Commencer à 10 secondes (au lieu de 5)
    const maxInterval = 60000;   // 🔥 Maximum 60 secondes (au lieu de 45)
    const backoffFactor = 1.5;   // 🔥 Croissance plus rapide
    
    let consecutiveErrors = 0;
    let consecutiveRunning = 0;
    let isActive = true; // Protection contre les race conditions

    const executePoll = async () => {
      if (!scanId || !loading || !isActive) return;

      try {
        console.log(`🔥 Ultra-optimized polling - Interval: ${Math.round(currentInterval/1000)}s`);
        
        const resultData = await ScanService.getScanResult(scanId);

        // Détecter changement de statut
        const statusChanged = scanStatus !== resultData.status;
        if (statusChanged) {
          console.log(`📊 Status transition: ${scanStatus} → ${resultData.status}`);
          consecutiveRunning = 0; // Reset compteur si changement
        }

        setPollCount(prev => prev + 1);
        setScanStatus(resultData.status);
        
        if (resultData.user_message) {
          setUserMessage(resultData.user_message);
        }
        
        consecutiveErrors = 0; // Reset erreurs
        
        // 🔥 LOGIQUE ULTRA-OPTIMISÉE par statut
        if (resultData.status === 'completed') {
          console.log('✅ Scan completed - stopping polling');
          setScanResult(resultData);
          setLoading(false);
          setScansHistory(prevHistory => [resultData, ...prevHistory]);
          ScanService.saveScanToLocalStorage(resultData);
          return; // STOP
        } 
        else if (resultData.status === 'failed') {
          console.log('❌ Scan failed - stopping polling');
          setScanResult(resultData);
          setLoading(false);
          return; // STOP
        }
        else if (resultData.status === 'timeout') {
          console.log('⏰ Scan timeout - max interval');
          setScanResult(resultData);
          currentInterval = maxInterval; // 🔥 Directement au max pour timeout
        }
        else if (resultData.status === 'running') {
          consecutiveRunning++;
          console.log(`🔄 Scan running (${consecutiveRunning}x)`);
          
          // 🔥 AGRESSIF : Augmenter rapidement l'intervalle
          if (consecutiveRunning > 2) { // Plus tôt qu'avant (2 au lieu de 5)
            currentInterval = Math.min(currentInterval * backoffFactor, maxInterval);
            console.log(`📈 Increased to ${Math.round(currentInterval/1000)}s after ${consecutiveRunning} running statuses`);
          }
        }
        else if (resultData.status === 'pending') {
          console.log('⏳ Scan pending - moderate interval');
          currentInterval = Math.max(currentInterval, 12000); // 🔥 12s minimum pour pending
        }
        
        // 🔥 PROTECTION réduite : 80 tentatives max (au lieu de 120)
        if (pollCount > 80) {
          console.log('🛑 Maximum polling attempts reached');
          setUserMessage("The scan is taking longer than expected. Please check back later or refresh the page.");
          setLoading(false);
          return;
        }
        
        // 🔥 Programmer le prochain poll si toujours actif
        if (isActive) {
          console.log(`⏰ Next poll in ${Math.round(currentInterval/1000)}s`);
          pollingTimeoutId = window.setTimeout(executePoll, currentInterval);
        }
        
      } catch (err: any) {
        consecutiveErrors++;
        console.warn(`🔥 Polling error #${consecutiveErrors}:`, err.message);
        
        // 🔥 Backoff très agressif sur erreurs
        if (consecutiveErrors >= 2) {
          currentInterval = Math.min(currentInterval * 2, maxInterval); // x2 au lieu de 1.8
          console.log(`📈 Error backoff - new interval: ${Math.round(currentInterval/1000)}s`);
        }
        
        // 🔥 Arrêt rapide : 3 erreurs au lieu de 5
        if (consecutiveErrors >= 3) {
          console.error('🛑 Too many polling errors - stopping');
          setError('Connection issues detected. Please refresh the page.');
          setLoading(false);
          return;
        }
        
        // Continuer avec backoff si encore actif
        if (isActive) {
          pollingTimeoutId = window.setTimeout(executePoll, currentInterval);
        }
      }
    };

    // Démarrer le polling ultra-optimisé
    if (scanId && loading) {
      console.log('🔥 Starting ULTRA-OPTIMIZED polling for scan:', scanId);
      executePoll();
    }

    // Nettoyage robuste
    return () => {
      isActive = false;
      if (pollingTimeoutId !== null) {
        console.log('🧹 Cleaning up ultra-optimized polling');
        window.clearTimeout(pollingTimeoutId);
      }
    };
  }, [scanId, loading, scanStatus]); // Dépendances minimales

  // Effet pour charger l'historique des scans au chargement du composant
  useEffect(() => {
    const fetchScanHistory = async () => {
      try {
        const historyData = await ScanService.getScanHistory();
        setScansHistory(historyData);
      } catch (err: any) {
        console.error("Error loading history:", err.message);
      }
    };

    fetchScanHistory();
  }, []);

  const handleScan = async (url: string) => {
    setIsSearching(true);
    setSearchResults([]); // Clear previous results
    
    try {
      const searchData = await ScanService.searchScans(url, true);
      
      if (searchData && searchData.length > 0) {
        console.log(`🔍 Found ${searchData.length} existing scans for this URL`);
        setSearchResults(searchData);
        setIsSearching(false);
        return;
      }
      
      // Nouveau scan
      setIsSearching(false);
      setLoading(true);
      setScanResult(null);
      setError(null);
      setScanId(null);
      setScanStatus(null);
      setPollCount(0);
      setShowResultDetails(false);
      setUserMessage(null); // Reset user message

      const data = await ScanService.startScan(url);

      if (data && data.scan_id) {
        setScanId(data.scan_id);
        setScanStatus('pending');
      } else {
        throw new Error("Scan ID not received");
      }
      
    } catch (err: any) {
      console.error("Scan start error:", err.message);
      setError(err.message);
      setLoading(false);
      setIsSearching(false);
    }
  };

  // 🔥 Messages améliorés avec timing précis
  const getStatusMessage = () => {
    if (userMessage) {
      return userMessage;
    }
    
    if (!scanStatus) return "Initializing scan...";
    
    // Estimation basée sur pollCount et intervalle actuel
    const estimatedMinutes = Math.floor((pollCount * 10) / 60); // Approximation avec 10s moyen
    
    switch (scanStatus) {
      case 'pending':
        return "Scan is queued and will start shortly...";
      case 'running':
        if (pollCount > 30) {
          return `🔍 Deep security analysis in progress (${estimatedMinutes} min)...`;
        } else if (pollCount > 15) {
          return `🛡️ Comprehensive security scan running (${estimatedMinutes} min)...`;
        }
        return `🚀 Security scan in progress... (check ${pollCount})`;
      case 'completed':
        return "✅ Scan completed successfully! Security report is ready.";
      case 'failed':
        return "❌ Scan encountered issues. Our system will retry automatically.";
      case 'timeout':
        return "⏱️ Complex site detected. Extended analysis continues in background...";
      default:
        return `Status: ${scanStatus}`;
    }
  };

  // Navigate to scan history page
  const goToScanHistory = () => {
    navigate('/scan-history');
  };

  // Navigate to scan details
  const goToScanDetails = (scan: ExtendedScanResult) => {
    const scanIdentifier = scan.id || scan.scan_id;
    
    if (scanIdentifier) {
      navigate(`/scan/${scanIdentifier}`);
    } else {
      setError("Missing scan ID. Cannot display details.");
    }
  };

  return (
    <AppLayout>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", width:"100%" }}>
        <h2 style={{ color: "var(--text-color)" }}>Scan a Website</h2>
        <div>
          <button 
            onClick={goToScanHistory} 
            style={{
              padding: "8px 16px",
              background: "var(--border-color)",
              color: "var(--bg-color)",
              border: "none",
              borderRadius: "4px",
              cursor: "pointer",
              marginRight: "10px",
              marginLeft:"15px"
            }}
          >
            Scan History
          </button>
        </div>
      </div>

      <InputUrl onSubmit={handleScan} />

      {/* Search Results */}
      {searchResults && searchResults.length > 0 && (
        <div style={searchResultsStyle}>
          <h4>Scanned URLs:</h4>
          <div>
            {searchResults.map((result, index) => (
              <div 
                key={index} 
                style={searchResultItemStyle}
                onClick={() => goToScanDetails(result)}
              >
                <div>
                  <strong>{result.url}</strong>
                  <span style={{
                    marginLeft: "10px", 
                    color: result.status === 'completed' ? '#2ecc71' : '#e74c3c'
                  }}>
                    {result.status}
                  </span>
                </div>
                <div style={{ fontSize: "0.8rem", opacity: 0.7 }}>
                  {new Date(result.created_at).toLocaleDateString()} {new Date(result.created_at).toLocaleTimeString()}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Information area */}
      <div style={infoBoxStyle}>
        <strong>Disclaimer:</strong> By clicking <strong>Scan</strong>, our tools will help you:
        <ul style={{ paddingLeft: "1.5rem", marginTop: "0.5rem" }}>
          <li>Do a deep scan for vulnerabilities and risks</li>
          <li>Verify the SSL/TLS configuration</li>
          <li>Do an advanced HTTP headers check</li>
          <li>Check for outdated servers and CMS</li>
        </ul>
      </div>

      {/* Warning */}
      <div style={warningBoxStyle}>
        <h3 style={{ color: "orange", fontSize: "1.5rem" }}>⚠️ Warning</h3>
        <p>
          This tool is for educational and ethical testing purposes only.
          <br />
          Make sure you have authorization before scanning any target.
        </p>
      </div>

      {/* Scan Status Box */}
      {(loading || scanResult) && (
        <ScanResultBox 
          loading={loading}
          status={scanStatus} 
          url={scanResult?.url || "URL being scanned..."} 
          statusMessage={getStatusMessage()}
          error={error}
          userMessage={""}
          scanId={scanId}
          onViewDetails={scanResult ? () => goToScanDetails(scanResult) : undefined}
        />
      )}
    </AppLayout>
  );
};

// Styles identiques
const infoBoxStyle = {
  marginTop: "2rem",
  padding: "1.5rem",
  border: "1px solid var(--accent-color)",
  borderRadius: "8px",
  boxShadow: "0 0 12px var(--accent-color)",
  backgroundColor: "rgba(255, 255, 255, 0.05)",
  color: "var(--text-color)",
  fontSize: "0.9rem",
  width: "100%",
  maxWidth: "800px",
  boxSizing: "border-box" as const,
  height: "auto",
  minHeight: "fit-content",
  margin: "2rem auto",
};

const warningBoxStyle = {
  marginTop: "2rem",
  padding: "1.5rem",
  border: "2px solid orange",
  borderRadius: "10px",
  backgroundColor: "rgba(255, 0, 0, 0.05)",
  boxShadow: "0 0 12px red",
  color: "var(--text-color)",
  fontFamily: "'Orbitron', sans-serif",
  width: "100%",
  maxWidth: "800px",
  boxSizing: "border-box" as const,
  height: "auto",
  margin: "2rem auto",
};

const searchResultsStyle = {
  marginTop: "1rem",
  padding: "1rem",
  color:"var(--text-color)",
  backgroundColor: "var(--bg-color)",
  borderRadius: "8px",
  border: "1px solid var(--accent-color)",
  width: "100%",
  maxWidth: "800px",
  boxSizing: "border-box" as const,
  height: "auto",
  margin: "1rem auto",
};

const searchResultItemStyle = {
  padding: "10px",
  borderBottom: "1px solid rgba(255, 255, 255, 0.1)",
  cursor: "pointer",
  transition: "background-color 0.2s ease",
};

export default Scanner;