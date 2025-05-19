// src/services/ScanService.ts
import api from '../config/api';

export interface ScanResult {
  id?: string;         // Optionnel pour compatibilité
  scan_id?: string;    // Pour compatibilité avec le backend
  url: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  created_at: string;
  whatweb_output?: string;
  sslyze_output?: string;
  zap_output?: string;
  error?: string;
  gemini_analysis?: string;
}

class ScanService {
  async startScan(url: string): Promise<{ scan_id: string }> {
    try {
      const response = await api.post('/scan', { url });
      return response.data;
    } catch (error: any) {
      if (error.response && error.response.data) {
        throw new Error(error.response.data.message || 'Erreur lors du scan');
      }
      throw new Error('Erreur de connexion au serveur');
    }
  }

  async getScanResult(scanId: string): Promise<ScanResult> {
    try {
      const response = await api.get(`/scan-results/${scanId}`);
      const data = response.data;
      
      // Adapter la réponse si nécessaire
      if (data.scan_id && !data.id) {
        data.id = data.scan_id;
      }
      
      return data;
    } catch (error: any) {
      if (error.response && error.response.data) {
        throw new Error(error.response.data.message || 'Erreur lors de la récupération des résultats');
      }
      throw new Error('Erreur de connexion au serveur');
    }
  }

  async getScanHistory(): Promise<ScanResult[]> {
    try {
      const response = await api.get('/scan-history');
      // Adapter chaque élément si nécessaire
      return response.data.map((item: any) => {
        if (item.scan_id && !item.id) {
          item.id = item.scan_id;
        }
        return item;
      });
    } catch (error: any) {
      if (error.response && error.response.data) {
        throw new Error(error.response.data.message || 'Erreur lors de la récupération de l\'historique');
      }
      throw new Error('Erreur de connexion au serveur');
    }
  }

async searchScans(query: string, isUrl: boolean = false): Promise<ScanResult[]> {
  try {
    // Utiliser le paramètre approprié selon isUrl
    const param = isUrl ? 'url' : 'q';
    console.log(`Searching with ${param}=${query}`); // Debug
    
    const response = await api.get(`/search-scans?${param}=${encodeURIComponent(query)}`);
    
    console.log('Search response:', response.data); // Debug
    
    // Si les résultats sont dans un sous-objet 'results'
    const data = response.data.results || response.data;
    
    // Adapter chaque élément si nécessaire
    return Array.isArray(data) ? data.map((item: any) => {
      if (item.scan_id && !item.id) {
        item.id = item.scan_id;
      }
      return item;
    }) : [];
  } catch (error: any) {
    console.error('Search error:', error); // Debug
    if (error.response && error.response.data) {
      throw new Error(error.response.data.message || 'Erreur lors de la recherche');
    }
    throw new Error('Erreur de connexion au serveur');
  }
}
}

export default new ScanService();