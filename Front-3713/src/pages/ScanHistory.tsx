// src/pages/ScanHistory.tsx
import React, { useState } from "react";
import { ScanResult } from "../services/ScanService";

interface ScanHistoryProps {
  scans: ScanResult[];
  onSelectScan: (scan: ScanResult) => void;
  isLoading?: boolean;
  error?: string | null;
}

const ScanHistory: React.FC<ScanHistoryProps> = ({ 
  scans, 
  onSelectScan,
  isLoading = false,
  error = null
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  
  // Vérifier que scans est un tableau avant de filtrer
  const safeScans = Array.isArray(scans) ? scans : [];
  
  // Filtrer les scans en fonction de la recherche
  const filteredScans = safeScans.filter(scan => 
    (scan.url || "").toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Fonction pour formater la date de façon sécurisée
  const formatDate = (dateString: string) => {
    try {
      const date = new Date(dateString);
      
      // Vérifier si la date est valide
      if (isNaN(date.getTime())) {
        return "Unknown date";
      }
      
      const options: Intl.DateTimeFormatOptions = {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      };
      return date.toLocaleDateString(undefined, options);
    } catch (e) {
      return "Unknown date";
    }
  };

  // Fonction pour obtenir la couleur de statut
  const getStatusColor = (status: string = "") => {
    switch (status.toLowerCase()) {
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

  // Fonction sécurisée pour obtenir une clé unique
  const getSafeKey = (scan: ScanResult, index: number): string => {
    if (scan.id) return `scan-${scan.id}`;
    if (scan.scan_id) return `scan-${scan.scan_id}`;
    return `scan-index-${index}`;
  };

  // Afficher l'état de chargement
  if (isLoading) {
    return (
      <div style={containerStyle}>
        <div style={emptyStateStyle}>
          <p>Loading scan history...</p>
        </div>
      </div>
    );
  }

  // Afficher l'erreur si présente
  if (error) {
    return (
      <div style={containerStyle}>
        <div style={{
          ...emptyStateStyle,
          backgroundColor: "rgba(231, 76, 60, 0.1)",
          border: "1px solid #e74c3c",
          color: "#e74c3c"
        }}>
          <p>Error loading scan history: {error}</p>
        </div>
      </div>
    );
  }

  return (
    <div style={containerStyle}>
      {/* Barre de recherche */}
      <div style={searchBoxStyle}>
        <input
          type="text"
          placeholder="Search by URL..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={searchInputStyle}
        />
      </div>
      
      {filteredScans.length === 0 ? (
        <div style={emptyStateStyle}>
          <p>
            {searchQuery ? 
              "No results found for this search." : 
              "No scans in history."}
          </p>
        </div>
      ) : (
        <div style={listContainerStyle}>
          {filteredScans.map((scan, index) => {
            return (
              <div 
                key={getSafeKey(scan, index)}
                style={scanItemStyle}
                onClick={() => scan && onSelectScan(scan)}
              >
                <div style={scanItemHeaderStyle}>
                  <span style={{ 
                    color: getStatusColor(scan.status),
                    fontWeight: "bold",
                    display: "flex",
                    alignItems: "center"
                  }}>
                    {scan.status === "completed" ? "✓" : scan.status === "failed" ? "✗" : "⋯"}
                    &nbsp;{scan.status || "Unknown"}
                  </span>
                  <span style={{ fontSize: "0.9rem", opacity: 0.7 }}>
                    {scan.created_at ? formatDate(scan.created_at) : "Unknown date"}
                  </span>
                </div>
                
                <div style={scanItemContentStyle}>
                  <span style={{ fontWeight: "bold" }}>URL: </span>
                  <span style={{ wordBreak: "break-all" }}>{scan.url || "No URL"}</span>
                </div>
                
                <div style={{ 
                  display: "flex", 
                  justifyContent: "flex-end",
                  marginTop: "10px",
                  padding: "0 16px 16px"
                }}>
                  <button style={viewButtonStyle}>
                    View details
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// Styles - exactement les mêmes qu'à l'origine
const containerStyle = {
  padding: "16px",
  color: "var(--text-color)",
  width: "100%",
};

const emptyStateStyle = {
  textAlign: "center" as const,
  padding: "40px",
  backgroundColor: "rgba(255, 255, 255, 0.05)",
  borderRadius: "8px",
  marginTop: "20px",
};

const listContainerStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
  gap: "20px",
};

const scanItemStyle = {
  border: "1px solid var(--accent-color)",
  borderRadius: "8px",
  overflow: "hidden",
  backgroundColor: "rgba(0, 0, 0, 0.2)",
  transition: "transform 0.2s ease, box-shadow 0.2s ease",
  cursor: "pointer",
  boxShadow: "0 4px 6px rgba(0, 0, 0, 0.1)",
};

const scanItemHeaderStyle = {
  padding: "12px 16px",
  borderBottom: "1px solid rgba(255, 255, 255, 0.1)",
  backgroundColor: "rgba(0, 0, 0, 0.3)",
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
};

const scanItemContentStyle = {
  padding: "16px",
};

const viewButtonStyle = {
  backgroundColor: "var(--accent-color)",
  color: "var(--bg-color)",
  border: "none",
  padding: "8px 12px",
  borderRadius: "4px",
  cursor: "pointer",
  fontSize: "0.9rem",
};

const searchBoxStyle = {
  marginBottom: "20px",
  display: "flex",
  alignItems: "center",
};

const searchInputStyle = {
  width: "100%",
  padding: "10px 15px",
  border: "1px solid var(--accent-color)",
  borderRadius: "4px",
  backgroundColor: "rgba(255, 255, 255, 0.08)",
  color: "var(--text-color)",
  fontSize: "0.9rem",
};

export default ScanHistory;