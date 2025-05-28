import React from "react";

interface ScanResultBoxProps {
  loading: boolean;
  status: string | null;
  url: string;
  statusMessage: string;
  error: string | null;
  userMessage?: string | null;
  scanId?: string | null; // Ajout du scanId
  onViewDetails?: () => void; // Fonction optionnelle pour voir les détails
}

const ScanResultBox: React.FC<ScanResultBoxProps> = ({
  loading,
  status,
  url,
  statusMessage,
  error,
  userMessage,
  scanId,
  onViewDetails
}) => {
  const getStatusColor = () => {
    switch (status) {
      case "completed":
        return "#2ecc71"; // green
      case "failed":
        return "#e74c3c"; // red
      case "timeout":
        return "#e67e22"; // dark orange
      case "pending":
      case "running":
        return "#f39c12"; // orange/yellow
      default:
        return "#3498db"; // blue
    }
  };

  // Fonction pour gérer le clic sur le bouton
  const handleViewDetails = () => {
    if (onViewDetails && scanId) {
      onViewDetails();
    }
  };

  return (
    <div style={{
      marginTop: "2rem",
      padding: "1.5rem",
      border: `2px solid ${getStatusColor()}`,
      borderRadius: "8px",
      backgroundColor: "rgba(0, 0, 0, 0.2)",
      boxShadow: `0 0 12px ${getStatusColor()}`,
      color: "var(--text-color)",
      width: "100%",
      maxWidth: "800px",
      boxSizing: "border-box" as const,
      margin: "2rem auto",
    }}>
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "flex-start",
        marginBottom: "1rem",
      }}>
        <div>
          <h3 style={{ margin: 0 }}>Scan {status === "completed" ? "Results" : "Status"}</h3>
          <p style={{ margin: "0.5rem 0 0 0", opacity: 0.8 }}>URL: {url}</p>
        </div>
        <div style={{
          backgroundColor: getStatusColor(),
          color: "white",
          padding: "5px 10px",
          borderRadius: "4px",
          fontWeight: "bold",
          fontSize: "0.8rem",
          textTransform: "uppercase" as const,
        }}>
          {status || "Preparing"}
        </div>
      </div>

      <div style={{
        backgroundColor: "rgba(0, 0, 0, 0.3)",
        padding: "1rem",
        borderRadius: "5px",
        marginBottom: "1rem",
      }}>
        <div style={{ display: "flex", alignItems: "center" }}>
          {loading && (
            <span style={{
              display: "inline-block",
              width: "12px",
              height: "12px",
              borderRadius: "50%",
              backgroundColor: getStatusColor(),
              marginRight: "10px",
              animation: "pulse 1s infinite",
            }} />
          )}
          <p style={{ margin: 0 }}>{statusMessage}</p>
        </div>
        
        {userMessage && <p style={{ marginTop: "8px", fontSize: "0.9rem" }}>{userMessage}</p>}
      </div>

      {error && (
        <div style={{
          backgroundColor: "rgba(231, 76, 60, 0.2)",
          border: "1px solid #e74c3c",
          padding: "0.75rem",
          borderRadius: "5px",
          marginBottom: "1rem",
          color: "#e74c3c",
        }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Bouton View Details - seulement si on a un scanId et une fonction onViewDetails */}
      {scanId && onViewDetails && (status === "completed" || status === "failed" || status === "timeout" || !loading) && (
        <button
          onClick={handleViewDetails}
          style={{
            padding: "8px 16px",
            backgroundColor: "var(--accent-color)",
            color: "var(--bg-color)",
            border: "none",
            borderRadius: "4px",
            cursor: "pointer",
            fontWeight: "bold",
          }}
        >
          {status === "completed" ?"View Results" :"View Results" }
      
        </button>
      )}
    </div>
  );
};

export default ScanResultBox;