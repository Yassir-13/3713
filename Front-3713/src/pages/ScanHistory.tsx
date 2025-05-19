// src/components/ScanHistory.tsx
import React, { useState } from "react";
import { ScanResult } from "../services/ScanService";

interface ScanHistoryProps {
  scans: ScanResult[];
  onSelectScan: (scan: ScanResult) => void;
}

const ScanHistory: React.FC<ScanHistoryProps> = ({ scans, onSelectScan }) => {
  const [searchQuery, setSearchQuery] = useState("");
  
  // Vérifier que scans est un tableau avant de filtrer
  const safeScans = Array.isArray(scans) ? scans : [];
  
  // Filtrer les scans en fonction de la recherche
  const filteredScans = safeScans.filter(scan => 
    scan.url.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Fonction pour formater la date
  const formatDate = (dateString: string) => {
    try {
      const options: Intl.DateTimeFormatOptions = {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      };
      return new Date(dateString).toLocaleDateString(undefined, options);
    } catch (e) {
      return "Date inconnue";
    }
  };

  // Fonction pour obtenir la couleur de statut
  const getStatusColor = (status: string) => {
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
    <div style={containerStyle}>
      <h2 style={{ marginBottom: "20px", color: "var(--text-color)" }}>Historique des Scans</h2>
      
      {/* Barre de recherche */}
      <div style={searchBoxStyle}>
        <input
          type="text"
          placeholder="Rechercher par URL..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={searchInputStyle}
        />
      </div>
      
      {filteredScans.length === 0 ? (
        <div style={emptyStateStyle}>
          <p>
            {searchQuery ? 
              "Aucun résultat trouvé pour cette recherche." : 
              "Aucun scan dans l'historique."}
          </p>
        </div>
      ) : (
        <div style={listContainerStyle}>
          {filteredScans.map((scan, index) => {
            // S'assurer que l'identifiant est disponible en priorisant scan.id, puis scan.scan_id
            const scanIdentifier = scan.id || scan.scan_id || index;
            
            return (
              <div 
                key={scanIdentifier.toString()} 
                style={scanItemStyle}
                onClick={() => onSelectScan(scan)}
              >
                <div style={scanItemHeaderStyle}>
                  <span style={{ 
                    color: getStatusColor(scan.status),
                    fontWeight: "bold",
                    display: "flex",
                    alignItems: "center"
                  }}>
                    {scan.status === "completed" ? "✓" : scan.status === "failed" ? "✗" : "⋯"}
                    &nbsp;{scan.status}
                  </span>
                  <span style={{ fontSize: "0.9rem", opacity: 0.7 }}>
                    {scan.created_at ? formatDate(scan.created_at) : "Date inconnue"}
                  </span>
                </div>
                
                <div style={scanItemContentStyle}>
                  <span style={{ fontWeight: "bold" }}>URL : </span>
                  <span style={{ wordBreak: "break-all" }}>{scan.url}</span>
                </div>
                
                <div style={{ 
                  display: "flex", 
                  justifyContent: "flex-end",
                  marginTop: "10px"
                }}>
                  <button style={viewButtonStyle}>
                    Voir les détails
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

// Styles
const containerStyle = {
  padding: "16px",
  color: "var(--text-color)",
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
  color: "white",
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