import React from "react";
import Sidebar from "./Sidebar";
import ScannerHeader from "./ScannerHeader";

interface AppLayoutProps {
  children: React.ReactNode;
}

const layout: React.FC<AppLayoutProps> = ({ children }) => {
  return (
    <>
      <ScannerHeader />
      <div style={{ display: "flex" }}>
        <Sidebar />
        <main style={{ padding: '2rem', paddingTop: '8rem', minHeight: 'calc(100vh - 12rem)' }}>
          {children}
        </main>
      </div>
    </>
  );
};

export default layout;
