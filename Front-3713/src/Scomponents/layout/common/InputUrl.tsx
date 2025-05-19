import React, { useState } from "react";

interface InputUrlProps {
  onSubmit: (url: string) => void;
}

const InputUrl: React.FC<InputUrlProps> = ({ onSubmit }) => {
  const [url, setUrl] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      onSubmit(url.trim());
    }
  };

  return (
    <form onSubmit={handleSubmit} style={styles.form}>
      <input
        type="url"
        placeholder="Enter a website URL..."
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        style={styles.input}
        required
      />
      <button type="submit" style={styles.button}>
        Scan
      </button>
    </form>
  );
};

const styles = {
  form: {
    display: "flex",
    gap: "1rem",
    alignItems: "center",
    width: "100%",
    maxWidth: "600px",
    margin: "2rem auto",
  },
  input: {
    flex: 1,
    padding: "1rem",
    fontSize: "1rem",
    border: "2px solid var(--accent-color)",
    borderRadius: "5px",
    backgroundColor: "var(--bg-color)",
    color: "var(--text-color)",
  },
  button: {
    padding: "1rem 2rem",
    fontSize: "1rem",
    backgroundColor: "var(--accent-color)",
    color: "var(--bg-color)",
    border: "none",
    borderRadius: "5px",
    cursor: "pointer",
  },
};

export default InputUrl;