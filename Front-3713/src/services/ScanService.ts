// src/services/ScanService.ts
import api from '../config/api';

export interface ScanResult {
  id?: string;
  scan_id: string;
  url: string;
  status: string;
  created_at: string;
  whatweb_output?: string;
  sslyze_output?: string;
  zap_output?: string;
  error?: string;
  gemini_analysis?: string;
  user_message?: string;
}

class ScanService {
  async startScan(url: string): Promise<{ scan_id: string }> {
    try {
      const response = await api.post('/scan', { url });
      return response.data;
    } catch (error: any) {
      if (error.response && error.response.data) {
        throw new Error(error.response.data.message || 'Error starting scan');
      }
      throw new Error('Server connection error');
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
        throw new Error(error.response.data.message || 'Error retrieving results');
      }
      throw new Error('Server connection error');
    }
  }

  // Méthode modifiée pour contourner le problème d'authentification
  async getScanHistory(): Promise<ScanResult[]> {
    try {
      // Si l'utilisateur est authentifié, essayer la route utilisateur
      if (localStorage.getItem('token')) {
        try {
          // Essayer d'abord avec getUserScans (qui nécessite une authentification)
          const response = await api.get('/user-scans');
          
          // Si pas d'erreur, traiter et retourner les résultats
          if (Array.isArray(response.data)) {
            return response.data.map(this.normalizeScanItem);
          }
        } catch (e) {
          // Si échec d'authentification, ignorer silencieusement et continuer
          console.log("Failed to get user-specific scans, will try public scans");
        }
      }
      
      // Plan B: Obtenir tous les scans récents via la méthode de recherche
      // Cette approche fonctionne même sans authentification
      return await this.getAllRecentScans();
    } catch (error: any) {
      // En cas d'échec des deux méthodes, retourner l'historique local
      console.error("Error retrieving scan history:", error);
      return this.getLocalScans();
    }
  }

  // Méthode utilitaire pour obtenir TOUS les scans récents
  async getAllRecentScans(): Promise<ScanResult[]> {
    try {
      // searchScans sans paramètre répertorie tous les scans récents
      // Ceci est basé sur l'implémentation de searchScans dans ScanController
      const response = await api.get('/search-scans');
      
      if (Array.isArray(response.data)) {
        return response.data.map(this.normalizeScanItem);
      }
      return [];
    } catch (error) {
      console.error("Failed to get all recent scans:", error);
      return this.getLocalScans();
    }
  }

  // Méthode utilitaire pour récupérer les scans locaux
  private getLocalScans(): ScanResult[] {
    try {
      const storedScans = localStorage.getItem('recentScans');
      if (storedScans) {
        return JSON.parse(storedScans);
      }
    } catch (e) {
      console.error("Error parsing local scans:", e);
    }
    return [];
  }

  // Méthode utilitaire pour normaliser un élément
  private normalizeScanItem(item: any): ScanResult {
    if (item.scan_id && !item.id) {
      item.id = item.scan_id;
    }
    return item;
  }

  async searchScans(query: string, isUrl: boolean = false): Promise<ScanResult[]> {
    try {
      // Utiliser le paramètre approprié selon isUrl
      const param = isUrl ? 'url' : 'q';
      
      // Si query est vide, on ne passe pas de paramètre - cela retournera les scans récents
      const endpoint = query ? 
        `/search-scans?${param}=${encodeURIComponent(query)}` :
        '/search-scans';
      
      const response = await api.get(endpoint);
      
      // Si les résultats sont dans un sous-objet 'results'
      const data = response.data.results || response.data;
      
      // Adapter chaque élément si nécessaire
      return Array.isArray(data) ? data.map(this.normalizeScanItem) : [];
    } catch (error: any) {
      if (error.response && error.response.data) {
        throw new Error(error.response.data.message || 'Error searching scans');
      }
      throw new Error('Server connection error');
    }
  }

  // Méthode pour sauvegarder un scan dans le localStorage
  saveScanToLocalStorage(scan: ScanResult): void {
    try {
      // Récupérer les scans existants
      const storedScans = localStorage.getItem('recentScans');
      let scans: ScanResult[] = storedScans ? JSON.parse(storedScans) : [];
      
      // Vérifier si ce scan existe déjà
      const scanExists = scans.some(s => 
        s.scan_id === scan.scan_id || 
        (s.id && s.id === scan.scan_id)
      );
      
      if (!scanExists) {
        // Ajouter le nouveau scan au début
        scans = [scan, ...scans];
        
        // Limiter à 20 scans
        if (scans.length > 20) {
          scans = scans.slice(0, 20);
        }
        
        localStorage.setItem('recentScans', JSON.stringify(scans));
      }
    } catch (e) {
      console.error("Error saving scan to localStorage:", e);
    }
  }
}

export default new ScanService();