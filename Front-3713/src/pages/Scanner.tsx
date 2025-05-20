// src/pages/Scanner.tsx
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import InputUrl from "../Scomponents/layout/common/InputUrl";
import AppLayout from "../Scomponents/layout/layout";
import ScanResultBox from "../pages/ScanResultBox";
import ScanHistory from "../pages/ScanHistory";
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
  const [showHistory, setShowHistory] = useState(false);
 const [scansHistory, setScansHistory] = useState<ExtendedScanResult[]>([]);
  const [showResultDetails, setShowResultDetails] = useState(false);
  const [searchResults, setSearchResults] = useState<ExtendedScanResult[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [userMessage, setUserMessage] = useState<string | null>(null);
  
  const navigate = useNavigate();

  // Effet pour gérer le polling des résultats
// Remplacer votre useEffect actuel par celui-ci
useEffect(() => {
  let pollingInterval: number | null = null;

  if (scanId && loading) {
    pollingInterval = window.setInterval(async () => {
      try {
        const resultData = await ScanService.getScanResult(scanId);

        // Mettre à jour le nombre de tentatives
        setPollCount(prev => prev + 1);
        
        // Mettre à jour le statut du scan
        setScanStatus(resultData.status);
        
        // Enregistrer le message spécifique à l'utilisateur s'il existe
        if (resultData.user_message) {
          setUserMessage(resultData.user_message);
        }
        
        // Vérifier si le scan est terminé ou en erreur
        if (resultData.status === 'completed') {
          setScanResult(resultData);
          setLoading(false);

          // Ajouter le scan à l'historique quand il est terminé
          setScansHistory(prevHistory => [
            resultData,
            ...prevHistory
          ]);

          if (pollingInterval !== null) clearInterval(pollingInterval);
        } 
        // Gestion spéciale pour les statuts d'erreur et de timeout
        else if (resultData.status === 'failed' || resultData.status === 'timeout') {
          setScanResult(resultData);
          
          // Ne pas arrêter le polling pour les timeouts - le backend va relancer le scan
          if (resultData.status as string === 'timeout') {
            // Continuer le polling mais réduire la fréquence
            if (pollingInterval !== null) {
              clearInterval(pollingInterval);
              pollingInterval = window.setInterval(async () => {
                try {
                  const updatedData = await ScanService.getScanResult(scanId);
                  setScanStatus(updatedData.status);
                  
                  if (updatedData.user_message) {
                    setUserMessage(updatedData.user_message);
                  }
                  
                  if (updatedData.status === 'completed') {
                    setScanResult(updatedData);
                    setLoading(false);
                    if (pollingInterval !== null) clearInterval(pollingInterval);
                  }
                } catch (err: any) {
                  // Ignorer les erreurs temporaires pendant le polling
                  console.warn("Erreur de polling:", err.message);
                }
              }, 15000); // Vérifier toutes les 15 secondes pour les timeouts
            }
          } else {
            // Pour les vraies erreurs, arrêter le polling
            setLoading(false);
            if (pollingInterval !== null) clearInterval(pollingInterval);
          }
        } 
        // Protection après 180 tentatives (15 minutes à 5s d'intervalle)
        else if (pollCount > 180) {
          setUserMessage("Le scan prend beaucoup de temps. Vous pouvez revenir plus tard pour voir les résultats.");
          setLoading(false);
          if (pollingInterval !== null) clearInterval(pollingInterval);
        }
      } catch (err: any) {
        // Ne pas afficher d'erreur pour les problèmes temporaires de réseau
        console.warn("Erreur temporaire lors du polling:", err.message);
        
        // Seulement afficher l'erreur après plusieurs échecs consécutifs
        if (pollCount % 5 === 0) { // Tous les 5 échecs
          setError(`Problème de connexion: ${err.message}. Nous continuons à essayer...`);
        }
      }
    }, 5000); // Vérifier toutes les 5 secondes
  }

  return () => {
    if (pollingInterval !== null) clearInterval(pollingInterval);
  };
}, [scanId, loading, pollCount]);

  // Effet pour charger l'historique des scans au chargement du composant
  useEffect(() => {
    const fetchScanHistory = async () => {
      try {
        const historyData = await ScanService.getScanHistory();
        setScansHistory(historyData);
      } catch (err: any) {
        console.error("Erreur lors du chargement de l'historique:", err.message);
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
        throw new Error("ID du scan non reçu");
      }
      
    } catch (err: any) {
      setError(err.message);
      setLoading(false);
      setIsSearching(false);
    }
  };

  // Fonction pour afficher le message de statut approprié
  // Remplacer la fonction entière par celle-ci
const getStatusMessage = () => {
  // Utiliser le message personnalisé du backend s'il existe
  if (userMessage) {
    return userMessage;
  }
  
  if (!scanStatus) return "Initialisation du scan...";
  
  switch (scanStatus) {
    case 'pending':
      return "Le scan est en file d'attente...";
    case 'running':
      if (pollCount > 60) {
        return `Scan en cours (durée: ${Math.floor(pollCount/12)} min). Ce site nécessite une analyse approfondie...`;
      }
      return `Scan en cours (vérification ${pollCount})...`;
    case 'completed':
      return "Scan terminé avec succès!";
    case 'failed':
      return "Le scan a échoué. Nous allons essayer de le relancer automatiquement.";
    case 'timeout':
      return "Le scan prend plus de temps que prévu. Veuillez patienter, nous continuons l'analyse en arrière-plan.";
    default:
      return `Statut: ${scanStatus}`;
  }
};

  // Fonction pour basculer entre la vue principale et l'historique
  const toggleHistory = () => {
    setShowHistory(!showHistory);
  };

  // Fonction pour naviguer vers les détails du scan
  const goToScanDetails = (scan: ExtendedScanResult) => {

    // Utiliser scan.id ou scan.scan_id selon ce qui est disponible
    const scanIdentifier = scan.id || scan.scan_id;
    
    if (scanIdentifier) {
      navigate(`/scan/${scanIdentifier}`);
    } else {
      setError("ID du scan manquant. Impossible d'afficher les détails.");
    }
  };

  // Fonction pour tester le scan sans API (pour déboguer)
  const testScanSimulation = () => {
    setLoading(true);
    setScanResult(null);
    setError(null);
    setScanId("test-scan-id");
    setScanStatus("pending");
    setPollCount(0);
    setShowResultDetails(false);
    
    // Simuler un changement de statut après 3 secondes
    setTimeout(() => {
      setScanStatus("running");
      
      // Simuler la fin du scan après 6 secondes
      setTimeout(() => {
        setScanStatus("completed");
        setScanResult({
          id: "test-scan-id",
          scan_id: "test-scan-id",
          url: "https://example.com",
          status: "completed",
          created_at: new Date().toISOString(),
          whatweb_output: "Simulation de résultat WhatWeb",
          sslyze_output: "Simulation de résultat SSLyze"
        });
        setLoading(false);
      }, 3000);
    }, 3000);
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
          <strong>Erreur:</strong> {error}
        </div>
      )}
      
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h2 style={{ color: "var(--text-color)" }}>Scan a Website</h2>
        <div>
          <button 
            onClick={toggleHistory} 
            style={{
              padding: "8px 16px",
              background: "var(--border-color)",
              color: "var(--bg-color)",
              border: "none",
              borderRadius: "4px",
              cursor: "pointer",
              marginRight: "10px"
            }}
          >
            {showHistory ? "Nouveau Scan" : "Historique des Scans"}
          </button>
          
          {/* Bouton de test de simulation */}
          <button 
            onClick={testScanSimulation} 
            style={{
              padding: "8px 16px",
              background: "#3498db",
              color: "white",
              border: "none",
              borderRadius: "4px",
              cursor: "pointer"
            }}
          >
            Test (Simulation)
          </button>
        </div>
      </div>

      {!showHistory ? (
        <>
          <InputUrl onSubmit={handleScan} />

          {/* Résultats de recherche */}
          {searchResults && searchResults.length > 0 && (
            <div style={searchResultsStyle}>
              <h4>URLs déjà scannées:</h4>
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

          {/* Zone d'information */}
          <div style={infoBoxStyle}>
            <strong>Disclaimer:</strong> By clicking <strong>Scan</strong>, our tools will help you:
            <ul style={{ paddingLeft: "1.5rem", marginTop: "0.5rem" }}>
              <li>Do a deep scan for vulnerabilities and risks</li>
              <li>Verify the SSL/TLS configuration</li>
              <li>Do an advanced HTTP headers check</li>
              <li>Check for outdated servers and CMS</li>
            </ul>
          </div>

          {/* Avertissement */}
          <div style={warningBoxStyle}>
            <h3 style={{ color: "orange", fontSize: "1.5rem" }}>⚠️ Warning</h3>
            <p>
              This tool is for educational and ethical testing purposes only.
              <br />
              Make sure you have authorization before scanning any target.
            </p>
          </div>

          {/* Box de Statut du Scan */}
          {(loading || scanResult) && (
              <ScanResultBox 
                loading={loading}
                status={scanStatus} 
                url={scanResult?.url || "URL en cours de scan..."} 
                statusMessage={getStatusMessage()}
                error={error}
                userMessage={userMessage}
              />
          )}

          {/* Résultat détaillé si demandé */}
          {scanResult && showResultDetails && (
            <div style={resultStyle}>
              <h3>Résultats détaillés:</h3>
              
              {/* WhatWeb Results */}
              {scanResult.whatweb_output && (
                <div style={{ marginBottom: "1rem" }}>
                  <h4>WhatWeb Results:</h4>
                  <pre style={{ 
                    whiteSpace: "pre-wrap", 
                    backgroundColor: "rgba(0,0,0,0.2)", 
                    padding: "1rem",
                    borderRadius: "5px"
                  }}>
                    {scanResult.whatweb_output}
                  </pre>
                </div>
              )}
              
              {/* SSLyze Results */}
              {scanResult.sslyze_output && (
                <div style={{ marginBottom: "1rem" }}>
                  <h4>SSLyze Results:</h4>
                  <pre style={{ 
                    whiteSpace: "pre-wrap", 
                    backgroundColor: "rgba(0,0,0,0.2)", 
                    padding: "1rem",
                    borderRadius: "5px"
                  }}>
                    {scanResult.sslyze_output}
                  </pre>
                </div>
              )}
              
              {/* ZAP Results */}
              {scanResult.zap_output && scanResult.zap_output !== 'ZAP simulation' && (
                <div style={{ marginBottom: "1rem" }}>
                  <h4>ZAP Results:</h4>
                  <pre style={{ 
                    whiteSpace: "pre-wrap", 
                    backgroundColor: "rgba(0,0,0,0.2)", 
                    padding: "1rem",
                    borderRadius: "5px"
                  }}>
                    {scanResult.zap_output}
                  </pre>
                </div>
              )}
              
              {/* Error if any */}
              {scanResult.error && (
                <div style={{ 
                  marginTop: "1rem", 
                  color: "red", 
                  border: "1px solid red",
                  padding: "0.5rem",
                  borderRadius: "5px"
                }}>
                  <strong>Error:</strong> {scanResult.error}
                </div>
              )}
            </div>
          )}
        </>
      ) : (
        <ScanHistory 
          scans={scansHistory} 
          onSelectScan={goToScanDetails} 
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
};

const resultStyle = {
  marginTop: "2rem",
  padding: "1.5rem",
  border: "2px dashed var(--accent-color)",
  backgroundColor: "rgba(255, 255, 255, 0.03)",
  borderRadius: "10px",
  color: "var(--text-color)",
  maxWidth: "800px",
};

const searchResultsStyle = {
  marginTop: "1rem",
  padding: "1rem",
  backgroundColor: "rgba(255, 255, 255, 0.05)",
  borderRadius: "8px",
  border: "1px solid var(--accent-color)",
};

const searchResultItemStyle = {
  padding: "10px",
  borderBottom: "1px solid rgba(255, 255, 255, 0.1)",
  cursor: "pointer",
  transition: "background-color 0.2s ease",
};

export default Scanner;