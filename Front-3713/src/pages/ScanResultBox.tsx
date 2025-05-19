// src/components/ScanResultBox.tsx
import React from "react";

interface ScanResultBoxProps {
  loading: boolean;
  status: string | null;
  url: string;
  statusMessage: string;
  onViewDetails: () => void;
  error: string | null;
}

const ScanResultBox: React.FC<ScanResultBoxProps> = ({
  loading,
  status,
  url,
  statusMessage,
  onViewDetails,
  error
}) => {
  const getStatusColor = () => {
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
    <div style={{
      marginTop: "2rem",
      padding: "1.5rem",
      border: `2px solid ${getStatusColor()}`,
      borderRadius: "8px",
      backgroundColor: "rgba(0, 0, 0, 0.2)",
      boxShadow: `0 0 12px ${getStatusColor()}`,
      color: "var(--text-color)",
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
        <p style={{ margin: 0 }}>
          {loading ? (
            <span style={{ display: "flex", alignItems: "center" }}>
              <span style={{
                display: "inline-block",
                width: "12px",
                height: "12px",
                borderRadius: "50%",
                backgroundColor: getStatusColor(),
                marginRight: "10px",
                animation: "pulse 1s infinite",
              }} />
              {statusMessage}
            </span>
          ) : (
            statusMessage
          )}
        </p>
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

      {(status === "completed" || !loading) && (
        <button
          onClick={onViewDetails}
          style={{
            padding: "8px 16px",
            backgroundColor: "var(--accent-color)",
            color: "white",
            border: "none",
            borderRadius: "4px",
            cursor: "pointer",
            fontWeight: "bold",
          }}
        >
          {status === "completed" ? "View Full Report" : "Check Progress"}
        </button>
      )}
    </div>
  );
};

export default ScanResultBox;