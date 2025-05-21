// src/pages/ScanDetailsPage.tsx
import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import AppLayout from "../components/layout";
import ScanService, { ScanResult } from "../services/ScanService";

const ScanDetailsContent: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const navigate = useNavigate();

  useEffect(() => {
    const fetchScanDetails = async () => {
      if (!scanId) return;
      
      try {
        setLoading(true);
        const result = await ScanService.getScanResult(scanId);
        if (result && !result.id && result.scan_id) {
          result.id = result.scan_id;
        }
        setScan(result);
      } catch (err: any) {
        console.error("Erreur lors du chargement des détails:", err.message);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchScanDetails();
  }, [scanId]);

  const handleBack = () => {
    navigate('/scanner');
  };

  // Fonction pour obtenir la couleur de statut
  const getStatusColor = (status: string | null) => {
    if (!status) return "#3498db";
    
    switch (status) {
      case "completed":
        return "#2ecc71"; // vert
      case "failed":
        return "#e74c3c"; // rouge
      case "pending":
      case "running":
        return "#f39c12"; // orange/jaune
      default:
        return "#3498db"; // bleu
    }
  };

  return (
    <div style={styles.scanDetailsPage}>
      <div style={styles.scanDetailsHeader}>
        <button 
          onClick={handleBack}
          style={styles.backButton}
        >
          &larr; Retour au Scanner
        </button>
        
        <h2>Détails du Scan</h2>
      </div>

      {loading ? (
        <div style={styles.loadingState}>
          <p>Chargement des détails du scan...</p>
        </div>
      ) : error ? (
        <div style={styles.errorState}>
          <h3>Erreur:</h3>
          <p>{error}</p>
          <button 
            onClick={handleBack}
            style={{...styles.backButton, marginTop: "20px"}}
          >
            Retour au Scanner
          </button>
        </div>
      ) : scan ? (
        <div style={styles.scanContent}>
          <div style={styles.summaryBox}>
            <h3>Informations générales</h3>
            
            <div style={styles.infoRow}>
              <strong>URL:</strong> 
              <span style={{ wordBreak: "break-all" }}>{scan.url}</span>
            </div>
            
            <div style={styles.infoRow}>
              <strong>Statut:</strong>
              <span style={{
                color: getStatusColor(scan.status),
                fontWeight: "bold"
              }}>
                {scan.status}
              </span>
            </div>
            
            <div style={styles.infoRow}>
              <strong>Date du scan:</strong>
              <span>{new Date(scan.created_at).toLocaleString()}</span>
            </div>
          </div>

          {scan.error && (
            <div style={styles.errorBox}>
              <h3>Erreur du scan</h3>
              <p>{scan.error}</p>
            </div>
          )}

          <div style={styles.resultsBox}>
            <h3>Résultats Rapides</h3>
            {scan.gemini_analysis && (
                <div style={styles.geminiAnalysisSection}>
                  <div style={styles.geminiContent}>
                    {scan.gemini_analysis}
                  </div>
                </div>
              )}
          </div>
        </div>
      ) : (
        <div style={styles.errorState}>
          <h3>Scan introuvable</h3>
          <p>Le scan demandé n'existe pas ou a été supprimé.</p>
          <button 
            onClick={handleBack}
            style={{...styles.backButton, marginTop: "20px"}}
          >
            Retour au Scanner
          </button>
        </div>
      )}
    </div>
  );
};

// Objet styles pour les styles inline
const styles = {
  geminiAnalysisSection: {
  padding: "20px",
  backgroundColor: "rgba(52, 152, 219, 0.05)",
  borderRadius: "8px",
  border: "1px solid #3498db",
  marginTop: "30px",
},
geminiContent: {
  whiteSpace: "pre-wrap" as const,
  lineHeight: "1.6",
  fontSize: "0.95rem",
},
  scanDetailsPage: {
    padding: "150px",
    color: "var(--text-color)",
    width: "100%",
    maxWidth: "1200px",
    margin: "0 auto"
  },
  scanDetailsHeader: {
    display: "flex",
    alignItems: "center",
    marginBottom: "30px",
    gap: "20px",
  },
  backButton: {
    padding: "8px 16px",
    backgroundColor: "transparent",
    color: "var(--text-color)",
    border: "1px solid var(--accent-color)",
    borderRadius: "4px",
    cursor: "pointer",
    display: "flex" as const,
    alignItems: "center",
    transition: "background-color 0.2s",
  },
  loadingState: {
    padding: "30px",
    textAlign: "center" as const,
    backgroundColor: "rgba(255, 255, 255, 0.03)",
    borderRadius: "8px",
    border: "1px solid rgba(255, 255, 255, 0.1)",
  },
  errorState: {
    padding: "30px",
    textAlign: "center" as const,
    backgroundColor: "rgba(231, 76, 60, 0.05)",
    borderRadius: "8px",
    border: "1px solid #e74c3c",
    color: "#e74c3c",
  },
  scanContent: {
    display: "flex",
    flexDirection: "column" as const,
    gap: "30px",
  },
  summaryBox: {
    padding: "20px",
    backgroundColor: "rgba(255, 255, 255, 0.03)",
    borderRadius: "8px",
    border: "1px solid var(--accent-color)",
  },
  infoRow: {
    display: "flex",
    margin: "12px 0",
    alignItems: "center",
    gap: "10px",
  },
  errorBox: {
    padding: "20px",
    backgroundColor: "rgba(231, 76, 60, 0.05)",
    borderRadius: "8px",
    border: "1px solid #e74c3c",
  },
  resultsBox: {
    padding: "20px",
    backgroundColor: "rgba(255, 255, 255, 0.03)",
    borderRadius: "8px",
    border: "1px solid var(--accent-color)",
  },
  resultSection: {
    marginBottom: "30px",
  },
  codeBlock: {
    whiteSpace: "pre-wrap" as const,
    backgroundColor: "rgba(0, 0, 0, 0.3)",
    padding: "15px",
    borderRadius: "5px",
    overflow: "auto" as const,
    maxHeight: "500px",
    fontSize: "0.9rem",
  },
  emptyResults: {
    textAlign: "center" as const,
    opacity: 0.7,
  }
};

// Composant principal qui utilise AppLayout
const ScanDetailsPage: React.FC = () => {
  return (
    <AppLayout>
      <ScanDetailsContent />
    </AppLayout>
  );
};

export default ScanDetailsPage;