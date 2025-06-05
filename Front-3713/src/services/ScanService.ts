// src/services/ScanService.ts - VERSION CORRIGÉE
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
  nuclei_output?: string;
  error?: string;
  gemini_analysis?: string;
  user_message?: string;
}

class ScanService {
  async startScan(url: string): Promise<{ scan_id: string }> {
    try {
      console.log('🔧 DEBUG: Starting scan for URL:', url);
      const response = await api.post('/scan', { url });
      console.log('🔧 DEBUG: Scan started successfully:', response.data);
      return response.data;
    } catch (error: any) {
      console.error('🔧 DEBUG: Start scan error:', error);
      
      if (error.response && error.response.data) {
        throw new Error(error.response.data.message || 'Error starting scan');
      }
      throw new Error('Server connection error');
    }
  }

  async getScanResult(scanId: string): Promise<ScanResult> {
    try {
      console.log('🔧 DEBUG: Getting scan result for ID:', scanId);
      const response = await api.get(`/scan-results/${scanId}`);
      const data = response.data;
      
      console.log('🔧 DEBUG: Scan result received:', {
        scan_id: data.scan_id,
        status: data.status,
        hasAnalysis: !!data.gemini_analysis
      });
      
      // 🔧 CORRECTION : Normalisation plus robuste
      const normalizedData = this.normalizeScanItem(data);
      return normalizedData;
      
    } catch (error: any) {
      console.error('🔧 DEBUG: Get scan result error:', error);
      
      if (error.response && error.response.data) {
        throw new Error(error.response.data.message || 'Error retrieving results');
      }
      throw new Error('Server connection error');
    }
  }

  async getScanHistory(): Promise<ScanResult[]> {
    try {
      console.log('🔧 DEBUG: Getting scan history');
      
      // 🔧 CORRECTION : Stratégie de fallback améliorée
      if (this.isAuthenticated()) {
        try {
          const response = await api.get('/user-scans');
          if (Array.isArray(response.data)) {
            console.log('🔧 DEBUG: User scans retrieved:', response.data.length);
            return response.data.map(this.normalizeScanItem);
          }
        } catch (e) {
          console.warn("🔧 DEBUG: Failed to get user-specific scans, trying public scans");
        }
      }
      
      // Fallback vers scans publics récents
      return await this.getAllRecentScans();
      
    } catch (error: any) {
      console.error("🔧 DEBUG: Error retrieving scan history:", error);
      return this.getLocalScans();
    }
  }

  // 🔧 NOUVELLE MÉTHODE : Vérifier l'authentification
  private isAuthenticated(): boolean {
    const token = localStorage.getItem('token');
    return !!token;
  }

  // Méthode utilitaire pour obtenir TOUS les scans récents
  async getAllRecentScans(): Promise<ScanResult[]> {
    try {
      console.log('🔧 DEBUG: Getting all recent scans');
      const response = await api.get('/search-scans');
      
      if (Array.isArray(response.data)) {
        console.log('🔧 DEBUG: Recent scans retrieved:', response.data.length);
        return response.data.map(this.normalizeScanItem);
      }
      return [];
    } catch (error) {
      console.error("🔧 DEBUG: Failed to get all recent scans:", error);
      return this.getLocalScans();
    }
  }

  // Méthode utilitaire pour récupérer les scans locaux
  private getLocalScans(): ScanResult[] {
    try {
      const storedScans = localStorage.getItem('recentScans');
      if (storedScans) {
        const parsed = JSON.parse(storedScans);
        console.log('🔧 DEBUG: Local scans retrieved:', parsed.length);
        return parsed.map(this.normalizeScanItem);
      }
    } catch (e) {
      console.error("🔧 DEBUG: Error parsing local scans:", e);
    }
    return [];
  }

  // 🔧 CORRECTION : Méthode de normalisation améliorée
  private normalizeScanItem(item: any): ScanResult {
    // S'assurer que l'objet a les propriétés minimales requises
    const normalized: ScanResult = {
      id: item.id || item.scan_id || 'unknown',
      scan_id: item.scan_id || item.id || 'unknown',
      url: item.url || 'Unknown URL',
      status: item.status || 'unknown',
      created_at: item.created_at || new Date().toISOString(),
      whatweb_output: item.whatweb_output,
      sslyze_output: item.sslyze_output,
      zap_output: item.zap_output,
      nuclei_output: item.nuclei_output,
      error: item.error,
      gemini_analysis: item.gemini_analysis,
      user_message: item.user_message
    };

    return normalized;
  }

  async searchScans(query: string, isUrl: boolean = false): Promise<ScanResult[]> {
    try {
      console.log('🔧 DEBUG: Searching scans:', { query, isUrl });
      
      // Utiliser le paramètre approprié selon isUrl
      const param = isUrl ? 'url' : 'q';
      
      // Si query est vide, on ne passe pas de paramètre
      const endpoint = query ? 
        `/search-scans?${param}=${encodeURIComponent(query)}` :
        '/search-scans';
      
      const response = await api.get(endpoint);
      
      // Si les résultats sont dans un sous-objet 'results'
      const data = response.data.results || response.data;
      
      console.log('🔧 DEBUG: Search results:', { count: Array.isArray(data) ? data.length : 0 });
      
      return Array.isArray(data) ? data.map(this.normalizeScanItem) : [];
    } catch (error: any) {
      console.error('🔧 DEBUG: Search scans error:', error);
      
      if (error.response && error.response.data) {
        throw new Error(error.response.data.message || 'Error searching scans');
      }
      throw new Error('Server connection error');
    }
  }

  // 🔧 CORRECTION : Sauvegarde locale améliorée
  saveScanToLocalStorage(scan: ScanResult): void {
    try {
      const normalizedScan = this.normalizeScanItem(scan);
      
      // Récupérer les scans existants
      const storedScans = localStorage.getItem('recentScans');
      let scans: ScanResult[] = storedScans ? JSON.parse(storedScans) : [];
      
      // Vérifier si ce scan existe déjà
      const scanExists = scans.some(s => 
        s.scan_id === normalizedScan.scan_id || 
        (s.id && s.id === normalizedScan.scan_id)
      );
      
      if (!scanExists) {
        // Ajouter le nouveau scan au début
        scans = [normalizedScan, ...scans];
        
        // Limiter à 50 scans pour éviter la surcharge
        if (scans.length > 50) {
          scans = scans.slice(0, 50);
        }
        
        localStorage.setItem('recentScans', JSON.stringify(scans));
        console.log('🔧 DEBUG: Scan saved to localStorage:', normalizedScan.scan_id);
      }
    } catch (e) {
      console.error("🔧 DEBUG: Error saving scan to localStorage:", e);
    }
  }
}

export default new ScanService();