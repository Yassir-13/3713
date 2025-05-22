// src/pages/Scanner.tsx
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

  // Effet pour gérer le polling des résultats avec backoff exponentiel
  useEffect(() => {
    let pollingTimeoutId: number | null = null;
    let currentInterval = 2000; // Commencer à 2 secondes
    const maxInterval = 30000;   // Maximum 30 secondes
    const backoffFactor = 1.5;   // Facteur de croissance
    
    let consecutiveErrors = 0;

    const executePoll = async () => {
      if (!scanId || !loading) return;

      try {
        const resultData = await ScanService.getScanResult(scanId);

        // Mettre à jour le nombre de tentatives
        setPollCount(prev => prev + 1);
        
        // Mettre à jour le statut du scan
        setScanStatus(resultData.status);
        
        // Enregistrer le message utilisateur
        if (resultData.user_message) {
          setUserMessage(resultData.user_message);
        }
        
        // Réinitialiser les erreurs consécutives
        consecutiveErrors = 0;
        
        // Vérifier les différents statuts
        if (resultData.status === 'completed') {
        setScanResult(resultData);
        setLoading(false);
        setScansHistory(prevHistory => [resultData, ...prevHistory]);
        
        // Sauvegarder dans localStorage pour l'historique local
        ScanService.saveScanToLocalStorage(resultData);
  
        return; // Arrêter le polling
        } 
        else if (resultData.status === 'failed') {
          setScanResult(resultData);
          setLoading(false);
          return; // Arrêter le polling
        }
        else if (resultData.status === 'timeout') {
          setScanResult(resultData);
          // Augmenter l'intervalle pour les timeouts
          currentInterval = Math.min(currentInterval * backoffFactor, maxInterval);
        }
        
        // Protection après 180 tentatives
        if (pollCount > 180) {
          setUserMessage("The scan is taking a long time. You can check back later for results.");
          setLoading(false);
          return;
        }
        
        // Continuer le polling avec l'intervalle actuel
        pollingTimeoutId = window.setTimeout(executePoll, currentInterval);
        
      } catch (err: any) {
        // Incrémenter les erreurs consécutives
        consecutiveErrors++;
        
        // Log de débogage
        console.warn("Polling error:", err.message);
        
        // Après 3 erreurs consécutives, augmenter l'intervalle
        if (consecutiveErrors >= 3) {
          currentInterval = Math.min(currentInterval * backoffFactor, maxInterval);
          consecutiveErrors = 0; // Réinitialiser après augmentation
        }
        
        // Afficher un message d'erreur après plusieurs échecs
        if (consecutiveErrors % 5 === 0) {
          setError(`Connection issue: ${err.message}. We'll keep trying...`);
        }
        
        // Continuer le polling même en cas d'erreur
        pollingTimeoutId = window.setTimeout(executePoll, currentInterval);
      }
    };

    // Démarrer le polling immédiatement
    if (scanId && loading) {
      executePoll();
    }

    // Nettoyage
    return () => {
      if (pollingTimeoutId !== null) {
        window.clearTimeout(pollingTimeoutId);
      }
    };
  }, [scanId, loading]); // Dépendances minimales pour éviter les boucles

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
    // Vérifier d'abord si l'URL a déjà été scannée
    setIsSearching(true);
    try {
      const searchData = await ScanService.searchScans(url, true);
      
      if (searchData && searchData.length > 0) {
        // URL déjà scannée, montrer les résultats existants
        setSearchResults(searchData);
        setIsSearching(false);
        return;
      }
      
      // Si l'URL n'a pas été scannée, procéder au scan
      setIsSearching(false);
      setLoading(true);
      setScanResult(null);
      setError(null);
      setScanId(null);
      setScanStatus(null);
      setPollCount(0);
      setShowResultDetails(false);

      // Lancer le scan
      const data = await ScanService.startScan(url);

      // Stocker l'ID du scan pour le polling
      if (data && data.scan_id) {
        setScanId(data.scan_id);
        setScanStatus('pending');
      } else {
        throw new Error("Scan ID not received");
      }
      
    } catch (err: any) {
      setError(err.message);
      setLoading(false);
      setIsSearching(false);
    }
  };

  // Function to display appropriate status message
  const getStatusMessage = () => {
    // Use custom message from backend if available
    if (userMessage) {
      return userMessage;
    }
    
    if (!scanStatus) return "Initializing scan...";
    
    switch (scanStatus) {
      case 'pending':
        return "Scan is queued...";
      case 'running':
        if (pollCount > 60) {
          return `Scan in progress (duration: ${Math.floor(pollCount/12)} min). This site requires in-depth analysis...`;
        }
        return `Scan in progress (check ${pollCount})...`;
      case 'completed':
        return "Scan completed successfully!";
      case 'failed':
        return "Scan failed. We'll try to restart it automatically.";
      case 'timeout':
        return "Scan is taking longer than expected. Please wait, we continue the analysis in the background.";
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
    // Use scan.id or scan.scan_id depending on what's available
    const scanIdentifier = scan.id || scan.scan_id;
    
    if (scanIdentifier) {
      navigate(`/scan/${scanIdentifier}`);
    } else {
      setError("Missing scan ID. Cannot display details.");
    }
  };

  return (
    <AppLayout>
      {error && (
        <div style={{
          margin: "20px 0",
          padding: "15px",
          backgroundColor: "rgba(231, 76, 60, 0.1)",
          border: "1px solid #e74c3c",
          borderRadius: "5px",
          color: "#e74c3c"
        }}>
          <strong>Error:</strong> {error}
        </div>
      )}
      
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
          scanId={scanId} // Passez le scanId
          onViewDetails={scanResult ? () => goToScanDetails(scanResult) : undefined} // Fonction conditionnelle
        />
      )}
    </AppLayout>
  );
};

// Styles
const infoBoxStyle = {
  marginTop: "2rem",
  padding: "1.5rem",
  border: "1px solid var(--accent-color)",
  borderRadius: "8px",
  boxShadow: "0 0 12px var(--accent-color)",
  backgroundColor: "rgba(255, 255, 255, 0.05)",
  color: "var(--text-color)",
  fontSize: "0.9rem",
  width: "100%", // Largeur fixe à 100% du conteneur parent
  maxWidth: "800px", // Limite maximale pour les grands écrans
  boxSizing: "border-box" as const, // Important pour que padding soit inclus dans width
  height: "auto", // Hauteur automatique selon le contenu
  minHeight: "fit-content", // S'assure que la hauteur s'adapte au contenu minimum
  margin: "2rem auto", // Centré horizontalement
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
  width: "100%", // Largeur fixe à 100% du conteneur parent
  maxWidth: "800px", // Limite maximale pour les grands écrans
  boxSizing: "border-box" as const,
  height: "auto", // Hauteur automatique
  margin: "2rem auto", // Centré horizontalement
};

const searchResultsStyle = {
  marginTop: "1rem",
  padding: "1rem",
  color:"var(--text-color)",
  backgroundColor: "var(--bg-color)",
  borderRadius: "8px",
  border: "1px solid var(--accent-color)",
  width: "100%", // Largeur fixe
  maxWidth: "800px", // Limite maximale
  boxSizing: "border-box" as const,
  height: "auto", // Hauteur adaptative
  margin: "1rem auto", // Centré horizontalement
};

const searchResultItemStyle = {
  padding: "10px",
  borderBottom: "1px solid rgba(255, 255, 255, 0.1)",
  cursor: "pointer",
  transition: "background-color 0.2s ease",
};

export default Scanner;