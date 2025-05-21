import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../components/layout";
import ScanHistory from "./ScanHistory";
import ScanService, { ScanResult } from "../services/ScanService";

const ScanHistoryPage: React.FC = () => {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchScanHistory = async () => {
      try {
        setLoading(true);
        
        // Cette méthode tentera plusieurs approches et ne renverra jamais un tableau vide
        // sauf si aucune approche ne fonctionne
        const historyData = await ScanService.getScanHistory();
        setScans(historyData);
      } catch (err: any) {
        console.error("Failed to load any scans:", err);
        setError("Could not load scan history. Please try again later.");
      } finally {
        setLoading(false);
      }
    };

    fetchScanHistory();
  }, []);

  const handleSelectScan = (scan: ScanResult) => {
    const scanIdentifier = scan.id || scan.scan_id;
    if (scanIdentifier) {
      navigate(`/scan/${scanIdentifier}`);
    } else {
      setError("Missing scan ID. Cannot display details.");
    }
  };

  return (
    <AppLayout>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", width: "100%" }}>
        <h2 style={{ color: "var(--text-color)" }}>Scan History</h2>
        <button 
          onClick={() => navigate('/scanner')} 
          style={{
            padding: "8px 16px",
            background: "var(--border-color)",
            color: "var(--bg-color)",
            border: "none",
            borderRadius: "4px",
            cursor: "pointer",
            marginRight: "10px",
            marginLeft: "15px"
          }}
        >
          New Scan
        </button>
      </div>

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

      <ScanHistory 
        scans={scans} 
        onSelectScan={handleSelectScan}
        isLoading={loading}
      />
    </AppLayout>
  );
};

export default ScanHistoryPage;