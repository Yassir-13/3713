<?php

namespace App\Jobs;

use App\Models\ScanResult;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;

class ScanWebsite implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $url;
    protected $scan_id;
    
    // Timeouts adaptés pour sites complexes - GARDÉS COMME DEMANDÉ
    public $timeout = 2400; // 40 minutes pour gérer tous types de sites
    public $tries = 3; // Augmenté pour les reprises
    public $backoff = 120; // 2 minutes entre les essais

    public function __construct($url, $scan_id)
    {
        // Validation et nettoyage de l'URL dès la construction
        $this->url = $this->sanitizeAndValidateUrl($url);
        $this->scan_id = $scan_id;
    }

    public function handle()
    {
        $scan = ScanResult::where('scan_id', $this->scan_id)->first();
        if (!$scan) {
            Log::error("Scan ID {$this->scan_id} non trouvé");
            return;
        }

        Log::info("Début du scan 3713 sécurisé pour l'URL", [
            'scan_id' => $this->scan_id,
            'url_length' => strlen($this->url) // Log sécurisé sans exposer l'URL
        ]);

        $isRetry = $scan->status === 'failed' || $scan->status === 'timeout';
        
        if ($isRetry) {
            Log::info("Reprise du scan 3713", ['scan_id' => $this->scan_id]);
        }

        $scan->update([
            'status' => 'running',
            'error' => $isRetry ? ($scan->error . "\n(Reprise 3713 le " . now() . ")") : null
        ]);

        try {
            // ÉTAPE 1: WhatWeb 
            Log::info("Démarrage WhatWeb sécurisé");
            $whatweb = $this->runSecureCommand('whatweb', ['-v'], $this->url, 60);
            Log::info("WhatWeb terminé", ['bytes' => strlen($whatweb)]);
            
            // ÉTAPE 2: SSLyze
            Log::info("Démarrage SSLyze sécurisé");
            $sslHost = $this->extractHostFromUrl($this->url);
            $sslyze = $this->runSecureCommand('sslyze', [], $sslHost, 120);
            Log::info("SSLyze terminé", ['bytes' => strlen($sslyze)]);
            
            // ÉTAPE 3: Nuclei
            Log::info("Démarrage Nuclei sécurisé");
            $nucleiResults = $this->runNucleiSecure($this->url);
            Log::info("Nuclei terminé");
            
            // ÉTAPE 4: ZAP
            Log::info("Démarrage ZAP sécurisé");
            $zapResults = $this->runZapScanSecure($this->url);
            Log::info("ZAP terminé");

            // SAUVEGARDE RÉSULTATS
            $scan->update([
                'whatweb_output' => $whatweb ?: 'Aucun résultat',
                'sslyze_output' => $sslyze ?: 'Aucun résultat',
                'nuclei_output' => $nucleiResults ?: 'Aucun résultat',
                'zap_output' => $zapResults ?: 'Aucun résultat',
            ]);
            
            // ÉTAPE 5: Analyse Gemini
            Log::info("Génération analyse Gemini sécurisée");
            try {
                $prompt = $this->preparePromptFromScanData($scan);
                $analysis = $this->callGeminiAPI($prompt);
                
                $scan->update([
                    'gemini_analysis' => $analysis,
                    'status' => 'completed'
                ]);
                
                Log::info("Analyse Gemini générée avec succès", ['scan_id' => $this->scan_id]);
            } catch (\Exception $e) {
                Log::warning("Erreur Gemini", ['error' => $e->getMessage(), 'scan_id' => $this->scan_id]);
                $scan->update([
                    'gemini_analysis' => "L'analyse automatique n'a pas pu être générée: " . $e->getMessage(),
                    'status' => 'completed'
                ]);
            }
            
            Log::info("Scan 3713 terminé avec succès", ['scan_id' => $this->scan_id]);
            
        } catch (\Exception $e) {
            $errorMessage = "Erreur scan 3713: " . $e->getMessage();
            Log::error($errorMessage, ['scan_id' => $this->scan_id]);
            
            $isTimeout = stripos($e->getMessage(), 'timeout') !== false || 
                         stripos($e->getMessage(), 'timed out') !== false ||
                         $e instanceof \Illuminate\Queue\MaxAttemptsExceededException;
            
            $scan->update([
                'status' => $isTimeout ? 'timeout' : 'failed',
                'error' => $errorMessage
            ]);
            
            if ($isTimeout && $this->attempts() < $this->tries) {
                throw $e;
            }
        }
    }

    // 🆕 NOUVELLE MÉTHODE CRITIQUE : Extraire hostname:port pour SSLyze
    private function extractHostFromUrl($url)
    {
        $components = parse_url($url);
        $host = $components['host'] ?? '';
        $port = $components['port'] ?? null;
        
        // Pour HTTPS, port par défaut = 443
        // Pour HTTP, port par défaut = 80
        if (!$port) {
            $scheme = $components['scheme'] ?? 'https';
            $port = ($scheme === 'https') ? 443 : 80;
        }
        
        // SSLyze attend "hostname:port"
        return $host . ':' . $port;
    }

    /**
     * VALIDATION ET NETTOYAGE SÉCURISÉ DES URLs
     */
    private function sanitizeAndValidateUrl($url)
    {
        // Étape 1: Nettoyage basique
        $url = trim($url);
        
        // Étape 2: Validation du format URL
        if (!filter_var($url, FILTER_VALIDATE_URL) && !filter_var("https://$url", FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException("URL invalide fournie");
        }
        
        // Étape 3: Ajout du protocole si manquant
        if (!preg_match('/^https?:\/\//', $url)) {
            $url = "https://" . $url;
        }
        
        // Étape 4: Parsing et validation des composants
        $components = parse_url($url);
        if (!$components || !isset($components['host'])) {
            throw new \InvalidArgumentException("URL malformée");
        }
        
        // Étape 5: Validation du hostname (anti-injection)
        $hostname = $components['host'];
        if (!preg_match('/^[a-zA-Z0-9.-]+$/', $hostname)) {
            throw new \InvalidArgumentException("Hostname contient des caractères non autorisés");
        }
        
        // Étape 6: Blacklist des IPs privées/locales (sécurité réseau)
        if (filter_var($hostname, FILTER_VALIDATE_IP)) {
            if (!filter_var($hostname, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                throw new \InvalidArgumentException("Adresses IP privées/réservées non autorisées");
            }
        }
        
        // Étape 7: Limitation de la longueur
        if (strlen($url) > 2048) {
            throw new \InvalidArgumentException("URL trop longue");
        }
        
        return $url;
    }

    /**
     * 🔥 MÉTHODE CORRIGÉE: Exécution sécurisée des commandes (VERSION SÉCURISÉE)
     */
    private function runSecureCommand($tool, $args = [], $target = null, $timeout = 60)
    {
        // Étape 1: Validation du nom de l'outil (whitelist)
        $allowedTools = [
            'whatweb' => '/opt/whatweb/whatweb',
            'sslyze' => '/opt/venv/bin/sslyze',
            'nuclei' => '/usr/local/bin/nuclei'
        ];
        
        if (!isset($allowedTools[$tool])) {
            throw new \InvalidArgumentException("Outil non autorisé: $tool");
        }
        
        $toolPath = $allowedTools[$tool];
        
        // Étape 2: Validation que l'outil existe et est exécutable
        if (!file_exists($toolPath) || !is_executable($toolPath)) {
            throw new \RuntimeException("Outil non disponible: $toolPath");
        }
        
        // Étape 3: Construction sécurisée de la commande
        $command = [$toolPath];
        
        // 🔒 SÉCURITÉ: Validation des arguments contre l'injection
        foreach ($args as $arg) {
            if (!$this->isArgumentSafe($arg)) {
                throw new \InvalidArgumentException("Argument non sécurisé: $arg");
            }
            $command[] = $arg;
        }
        
        if ($target) {
            $command[] = escapeshellarg($target);
        }
        
        // Étape 4: Exécution avec proc_open sécurisé
        return $this->executeCommandSecurely($command, $timeout);
    }

    /**
     * 🔒 SÉCURITÉ: Validation des arguments contre l'injection de commandes
     */
    private function isArgumentSafe($arg)
    {
        // Caractères dangereux pour l'injection de commandes
        $dangerousChars = ['`', '$', '|', '&', ';', '>', '<'];
        
        foreach ($dangerousChars as $char) {
            if (strpos($arg, $char) !== false) {
                return false;
            }
        }

        // Patterns d'injection de commandes
        $dangerousPatterns = [
            '/\$\(.*\)/',     // $(command)
            '/`.*`/',         // `command`
            '/;\s*\w/',       // ; command
        ];

        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $arg)) {
                return false;
            }
        }

        return true;
    }

    /**
     * 🔒 NOUVELLE MÉTHODE: Exécution système sécurisée avec proc_open
     */
    private function executeCommandSecurely($command, $timeout = 60)
    {
        Log::info("Exécution sécurisée", [
            'tool' => basename($command[0]),
            'timeout' => $timeout
        ]);
        
        $descriptorspec = [
            0 => ['pipe', 'r'],  // stdin
            1 => ['pipe', 'w'],  // stdout
            2 => ['pipe', 'w'],  // stderr
        ];
        
        // 🔒 Environnement sécurisé et minimal
        $env = [
            'PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/whatweb:/opt/venv/bin',
            'HOME' => '/tmp',
            'USER' => 'www-data',
            'SHELL' => '/bin/bash',
            'LANG' => 'C',
            'LC_ALL' => 'C'
        ];
        
        // 🔒 CRITIQUE: proc_open avec tableau sécurisé (pas de string)
        $process = proc_open($command, $descriptorspec, $pipes, null, $env);
        
        if (!is_resource($process)) {
            throw new \RuntimeException('Impossible de démarrer la commande sécurisée');
        }
        
        // Configuration non-bloquante
        stream_set_blocking($pipes[1], 0);
        stream_set_blocking($pipes[2], 0);
        fclose($pipes[0]);
        
        $output = '';
        $errorOutput = '';
        $startTime = time();
        
        do {
            // Lecture des sorties
            $tmpOut = fread($pipes[1], 8192);
            if ($tmpOut !== false && $tmpOut !== '') $output .= $tmpOut;
            
            $tmpErr = fread($pipes[2], 8192);
            if ($tmpErr !== false && $tmpErr !== '') $errorOutput .= $tmpErr;
            
            $status = proc_get_status($process);
            
            // Vérification timeout strict
            if (time() - $startTime > $timeout) {
                proc_terminate($process, 9); // SIGKILL
                throw new \RuntimeException("Commande terminée après timeout de {$timeout} secondes");
            }
            
            usleep(100000); // 100ms
            
        } while ($status['running']);
        
        // Récupération finale des sorties
        while (($tmpOut = fread($pipes[1], 8192)) !== false && $tmpOut !== '') {
            $output .= $tmpOut;
        }
        while (($tmpErr = fread($pipes[2], 8192)) !== false && $tmpErr !== '') {
            $errorOutput .= $tmpErr;
        }
        
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);
        
        // Log sécurisé du résultat
        Log::info("Commande terminée", [
            'exit_code' => $exitCode,
            'output_length' => strlen($output),
            'error_length' => strlen($errorOutput)
        ]);
        
        if ($exitCode !== 0 && empty($output)) {
            Log::warning("Commande échouée", [
                'exit_code' => $exitCode,
                'error_preview' => substr($errorOutput, 0, 200)
            ]);
        }
        
        return $output ?: $errorOutput;
    }

    /**
     * VERSION SÉCURISÉE DE NUCLEI
     */
    protected function runNucleiSecure($url)
    {
        return $this->runNucleiUltraOptimizedSecure($url);
    }

    /**
     * NUCLEI ULTRA-OPTIMISÉ 3713 - VERSION SÉCURISÉE CORRIGÉE
     */
    protected function runNucleiUltraOptimizedSecure($url)
    {
        Log::info("Nuclei 3713 Ultra-Optimisé SÉCURISÉ", ['scan_id' => $this->scan_id]);
        
        // URL déjà validée dans le constructeur, pas besoin de re-valider
        
        try {
            $commands = [
                'exposures_critical' => [
                    'tool' => 'nuclei',
                    'args' => ['-t', 'http/exposures/', '-jsonl', '-silent', '-no-color', '-u'],
                    'critical' => true,
                    'timeout' => 180,
                    'description' => 'Exposures critiques'
                ],
                'technologies' => [
                    'tool' => 'nuclei',
                    'args' => ['-t', 'http/technologies/', '-jsonl', '-silent', '-no-color', '-u'],
                    'timeout' => 70,
                    'critical' => true,
                    'description' => 'Détection technologies'
                ],
                'misconfigurations' => [
                    'tool' => 'nuclei',
                    'args' => ['-t', 'http/misconfiguration/', '-jsonl', '-silent', '-no-color', '-u'],
                    'timeout' => 180,
                    'critical' => true,
                    'description' => 'Erreurs de configuration'
                ],
                'takeovers' => [
                    'tool' => 'nuclei',
                    'args' => ['-t', 'http/takeovers/', '-jsonl', '-silent', '-no-color', '-u'],
                    'timeout' => 120,
                    'critical' => false,
                    'description' => 'Vulnérabilités de takeover'
                ],
                'CVES' => [
                    'tool' => 'nuclei',
                    'args' => ['-t', 'http/cves/', '-jsonl', '-silent', '-no-color', '-u'],
                    'timeout' => 600,
                    'critical' => true,
                    'description' => 'Détection CVEs'
                ],
            ];
            
            $startTime = time();
            $allResults = [];
            $executedScans = 0;
            $totalScans = count($commands);
            
            Log::info("Démarrage de {$totalScans} scans Nuclei 3713 sécurisés");
            
            // Exécution séquentielle
            foreach ($commands as $scanType => $config) {
                $executedScans++;
                Log::info("[{$executedScans}/{$totalScans}] Scan sécurisé {$scanType}: {$config['description']}");
                
                try {
                    $scanStart = time();
                    
                    // CORRECTION : Utiliser la méthode sécurisée avec URL séparée
                    $output = $this->runSecureCommand(
                        $config['tool'], 
                        $config['args'], // Arguments incluant -u
                        $url, // URL passée séparément
                        $config['timeout']
                    );
                    
                    $scanDuration = time() - $scanStart;
                    $resultsFound = 0;
                    
                    if (!empty(trim($output))) {
                        $lines = explode("\n", trim($output));
                        
                        foreach ($lines as $line) {
                            $line = trim($line);
                            
                            // Ignorer les lignes vides et les stats Nuclei
                            if (empty($line) || $this->isNucleiStatsLine($line)) {
                                continue;
                            }
                            
                            // Parser le JSON de chaque ligne
                            $finding = json_decode($line, true);
                            
                            if ($finding && isset($finding['info'])) {
                                $processedFinding = [
                                    'id' => $finding['template-id'] ?? 'unknown',
                                    'name' => $finding['info']['name'] ?? 'Vulnérabilité inconnue',
                                    'severity' => strtolower($finding['info']['severity'] ?? 'info'),
                                    'url' => $finding['matched-at'] ?? $finding['host'] ?? $url,
                                    'description' => $finding['info']['description'] ?? 'Aucune description',
                                    'scan_type' => $scanType,
                                    'tags' => $finding['info']['tags'] ?? [],
                                    'reference' => $finding['info']['reference'] ?? [],
                                    'classification' => $finding['info']['classification'] ?? [],
                                    'timestamp' => $finding['timestamp'] ?? now()->toISOString()
                                ];
                                
                                $allResults[] = $processedFinding;
                                $resultsFound++;
                            }
                        }
                    }
                    
                    Log::info("{$scanType} sécurisé: {$resultsFound} résultats en {$scanDuration}s");
                    
                } catch (\Exception $e) {
                    Log::warning("Scan sécurisé {$scanType} erreur: " . $e->getMessage());
                    
                    // Pour les scans critiques, enregistrer l'erreur comme résultat
                    if ($config['critical']) {
                        $allResults[] = [
                            'id' => 'error-' . $scanType,
                            'name' => "Erreur scan sécurisé {$scanType}",
                            'severity' => 'info',
                            'url' => $url,
                            'description' => "Erreur lors du scan sécurisé: " . $e->getMessage(),
                            'scan_type' => $scanType,
                            'tags' => ['error', '3713', 'secure'],
                            'reference' => [],
                            'classification' => ['error'],
                            'timestamp' => now()->toISOString()
                        ];
                    }
                }
            }
            
            $totalDuration = time() - $startTime;
            
            // Tri par sévérité (Critical > High > Medium > Low > Info)
            usort($allResults, function($a, $b) {
                $severityOrder = [
                    'critical' => 0, 
                    'high' => 1, 
                    'medium' => 2, 
                    'low' => 3, 
                    'info' => 4
                ];
                return ($severityOrder[$a['severity']] ?? 4) <=> ($severityOrder[$b['severity']] ?? 4);
            });
            
            // Calcul intelligent du niveau de risque
            $criticalCount = count(array_filter($allResults, fn($f) => $f['severity'] === 'critical'));
            $highCount = count(array_filter($allResults, fn($f) => $f['severity'] === 'high'));
            $mediumCount = count(array_filter($allResults, fn($f) => $f['severity'] === 'medium'));
            $lowCount = count(array_filter($allResults, fn($f) => $f['severity'] === 'low'));
            
            // Logique de risque avancée
            $riskLevel = 'low';
            if ($criticalCount > 0) {
                $riskLevel = 'critical';
            } elseif ($highCount >= 3) {
                $riskLevel = 'high';
            } elseif ($highCount > 0 || $mediumCount >= 5) {
                $riskLevel = 'medium';
            } elseif ($mediumCount > 0 || $lowCount >= 3) {
                $riskLevel = 'low';
            }
            
            // Résumé détaillé
            $summary = [
                'total_findings' => count($allResults),
                'critical_count' => $criticalCount,
                'high_count' => $highCount,
                'medium_count' => $mediumCount,
                'low_count' => $lowCount,
                'info_count' => count(array_filter($allResults, fn($f) => $f['severity'] === 'info')),
                'risk_level' => $riskLevel,
                'scans_executed' => $executedScans,
                'scans_total' => $totalScans,
                'scan_efficiency' => $executedScans > 0 ? round(count($allResults) / $executedScans, 2) : 0,
                'scan_coverage' => round(($executedScans / $totalScans) * 100, 1)
            ];
            
            // Résultats finaux structurés
            $finalResults = [
                'scan_metadata' => [
                    'strategy' => '3713_nuclei_ultra_optimized_SECURE',
                    'target_url_length' => strlen($url), // Ne pas exposer l'URL complète
                    'total_duration' => $totalDuration,
                    'nuclei_version' => $this->getNucleiVersionSecure(),
                    'templates_used' => array_keys($commands),
                    'timestamp' => now()->toISOString(),
                    'scan_id' => $this->scan_id,
                    'security_level' => 'ENHANCED'
                ],
                'results' => $allResults,
                'summary' => $summary
            ];
            
            Log::info("Nuclei 3713 Ultra-Optimisé SÉCURISÉ terminé", [
                'duration' => $totalDuration,
                'findings' => count($allResults),
                'risk_level' => $riskLevel,
                'scan_id' => $this->scan_id
            ]);
            
            return json_encode($finalResults, JSON_PRETTY_PRINT);
            
        } catch (\Exception $e) {
            Log::error("Nuclei 3713 sécurisé erreur globale", [
                'error' => $e->getMessage(),
                'scan_id' => $this->scan_id
            ]);
            return json_encode([
                "error" => $e->getMessage(),
                "target_url_length" => strlen($url), // Pas d'exposition de l'URL
                "timestamp" => now()->toISOString(),
                "scan_id" => $this->scan_id,
                "security_level" => "ENHANCED"
            ]);
        }
    }
    
    /**
     * Version sécurisée pour obtenir la version de Nuclei
     */
    private function getNucleiVersionSecure()
    {
        try {
            $versionOutput = $this->runSecureCommand('nuclei', ['-version'], null, 10);
            
            // Extraire le numéro de version de façon sécurisée
            if (preg_match('/v?(\d+\.\d+\.\d+)/', $versionOutput, $matches)) {
                return $matches[1];
            }
            
            return 'Version sécurisée';
        } catch (\Exception $e) {
            Log::info("Version Nuclei non récupérée (mode sécurisé)", ['scan_id' => $this->scan_id]);
            return 'Version sécurisée';
        }
    }
    
    /**
     * Vérifie si une ligne est une ligne de statistiques Nuclei à ignorer
     */
    private function isNucleiStatsLine($line)
    {
        $statsPatterns = [
            '/^\[/',  // Lignes commençant par [
            '/Templates loaded/',
            '/Targets loaded/',
            '/Using Nuclei Engine/',
            '/Executing \d+ signed/',
            '/Running httpx/',
            '/\d+\/\d+ \[/',  // Progress indicators
            '/Stats:/',
            '/Matched:/',
            '/Duration:/',
        ];
        
        foreach ($statsPatterns as $pattern) {
            if (preg_match($pattern, $line)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * VERSION SÉCURISÉE DE ZAP SCAN
     */
    protected function runZapScanSecure($targetUrl)
    {
        // L'URL est déjà validée, pas besoin de re-valider
        
        $apiKey = $this->getSecureEnvValue('ZAP_API_KEY', '13373713');
        $apiHost = $this->getSecureEnvValue('ZAP_API_HOST', 'http://zap:8090');
        
        if (!$this->isValidZapHost($apiHost)) {
            throw new \InvalidArgumentException("Host ZAP non sécurisé");
        }

        try {
            // 1. Vérification rapide API + extraction domaine SÉCURISÉE
            $apiCheckUrl = "{$apiHost}/JSON/core/view/version/?apikey=" . urlencode($apiKey);
            $checkResponse = Http::timeout(5)->get($apiCheckUrl);
            if (!$checkResponse->successful()) {
                throw new \Exception("API ZAP inaccessible en mode sécurisé");
            }
            
            $urlParts = parse_url($targetUrl);
            $domain = $urlParts['host']; // Déjà validé par sanitizeAndValidateUrl
            $scheme = $urlParts['scheme'] ?? 'https';
            
            Log::info("Configuration ZAP sécurisée", ['scan_id' => $this->scan_id]);
            
            // 2-5. Configuration ZAP optimisée (identique mais avec logs sécurisés)
            $this->configureZapSecurely($apiHost, $apiKey);
            
            // 6. Création contexte sécurisé
            $contextName = 'ctx_secure_' . substr(hash('sha256', $domain . $this->scan_id), 0, 8);
            $contextId = $this->createZapContextSecurely($apiHost, $apiKey, $contextName, $scheme, $domain);
            
            // 7. Spider sécurisé
            $spiderId = $this->runZapSpiderSecurely($apiHost, $apiKey, $targetUrl, $contextName);
            
            // 8. Scan actif sécurisé
            $scanId = $this->runZapActiveScanSecurely($apiHost, $apiKey, $targetUrl, $contextId);
            
            // 9. Récupération résultats sécurisée
            $resultsUrl = "{$apiHost}/JSON/core/view/alerts/?apikey=" . urlencode($apiKey) . 
                         "&baseurl=" . urlencode($targetUrl) . "&riskFilter=high,medium";
            $resultsResponse = Http::timeout(30)->get($resultsUrl);
            
            if (!$resultsResponse->successful()) {
                throw new \Exception("Échec récupération résultats sécurisés: " . $resultsResponse->status());
            }
            
            Log::info("ZAP scan sécurisé terminé", ['scan_id' => $this->scan_id]);
            
            return json_encode($resultsResponse->json(), JSON_PRETTY_PRINT);
            
        } catch (\Exception $e) {
            Log::error("Exception ZAP sécurisé", [
                'error' => $e->getMessage(),
                'scan_id' => $this->scan_id
            ]);
            throw $e;
        }
    }

    /**
     * Validation sécurisée des variables d'environnement
     */
    private function getSecureEnvValue($key, $default)
    {
        $value = env($key, $default);
        
        if (empty($value)) {
            return $default;
        }
        
        // Validation basique contre l'injection
        if (strlen($value) > 1000 || preg_match('/[`$;|&><]/', $value)) {
            Log::warning("Environment variable potentially dangerous", [
                'key' => $key,
                'scan_id' => $this->scan_id
            ]);
            return $default;
        }
        
        return $value;
    }

    /**
     * Validation du host ZAP
     */
    private function isValidZapHost($host)
    {
        // Accepter seulement les hosts locaux/Docker sécurisés
        $allowedHosts = [
            'http://zap:8090',
            'http://localhost:8090',
            'http://127.0.0.1:8090',
            'https://zap:8443',
            'https://localhost:8443',
            'https://127.0.0.1:8443'
        ];
        
        return in_array($host, $allowedHosts);
    }

    /**
     * Configuration ZAP sécurisée
     */
    private function configureZapSecurely($apiHost, $apiKey)
    {
        $configs = [
            'maxParseSizeBytes' => 1048576,
            'maxScanDurationInMins' => 10,
            'handleAntiCSRFTokens' => 'true',
            'hostPerScan' => 3,
            'threadPerHost' => 5
        ];
        
        foreach ($configs as $param => $value) {
            try {
                $url = "{$apiHost}/JSON/spider/action/setOption{$param}/?apikey=" . urlencode($apiKey) . 
                       "&Integer=" . urlencode($value);
                Http::timeout(5)->get($url);
            } catch (\Exception $e) {
                Log::warning("Configuration ZAP échouée", ['param' => $param, 'scan_id' => $this->scan_id]);
            }
        }
    }

    /**
     * Création contexte ZAP sécurisé
     */
    private function createZapContextSecurely($apiHost, $apiKey, $contextName, $scheme, $domain)
    {
        try {
            // ÉTAPE 1: Créer le contexte
            $createContextUrl = "{$apiHost}/JSON/context/action/newContext/?apikey=" . urlencode($apiKey) . 
                               "&contextName=" . urlencode($contextName);
            
            $contextResponse = Http::timeout(10)->get($createContextUrl);
            
            if (!$contextResponse->successful()) {
                throw new \Exception("Échec création contexte ZAP - Status: {$contextResponse->status()}");
            }
            
            $responseBody = $contextResponse->body();
            if (empty($responseBody)) {
                throw new \Exception("Réponse ZAP vide pour la création du contexte");
            }
            
            $contextData = json_decode($responseBody, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \Exception("Erreur JSON ZAP: " . json_last_error_msg());
            }
            
            if (!is_array($contextData)) {
                throw new \Exception("Format de réponse ZAP inattendu");
            }
            
            $contextId = $contextData['contextId'] ?? null;
            if (!$contextId) {
                throw new \Exception("ID contexte manquant dans la réponse ZAP");
            }
            
            // ÉTAPE 2: Configurer l'inclusion dans le contexte
            $regex = $scheme . '://' . preg_quote($domain, '/') . '.*';
            $includeUrl = "{$apiHost}/JSON/context/action/includeInContext/?apikey=" . urlencode($apiKey) . 
                         "&contextName=" . urlencode($contextName) . "&regex=" . urlencode($regex);
            
            $includeResponse = Http::timeout(5)->get($includeUrl);
            
            if (!$includeResponse->successful()) {
                Log::warning("ZAP Include failed but continuing", [
                    'status' => $includeResponse->status(),
                    'scan_id' => $this->scan_id
                ]);
            }
            
            return $contextId;
            
        } catch (\Exception $e) {
            Log::error("ZAP Context Creation FAILED", [
                'error' => $e->getMessage(),
                'scan_id' => $this->scan_id
            ]);
            
            throw new \Exception("Échec création contexte ZAP: " . $e->getMessage());
        }
    }

    /**
     * Spider ZAP sécurisé
     */
    private function runZapSpiderSecurely($apiHost, $apiKey, $targetUrl, $contextName)
    {
        $spiderParams = [
            'url' => $targetUrl,
            'maxChildren' => 10,
            'recurse' => 'true',
            'contextName' => $contextName,
            'subtreeOnly' => 'true'
        ];
        
        $spiderUrl = "{$apiHost}/JSON/spider/action/scan/?apikey=" . urlencode($apiKey) . "&" . 
                    http_build_query($spiderParams);
        $response = Http::timeout(10)->get($spiderUrl);
        
        if (!$response->successful()) {
            throw new \Exception("Échec spider sécurisé: " . $response->status());
        }
        
        $spiderId = $response->json()['scan'];
        
        // Attente sécurisée du spider
        $this->waitForZapProcessSecurely($apiHost, $apiKey, 'spider', $spiderId, 120);
        
        return $spiderId;
    }

    /**
     * Scan actif ZAP sécurisé
     */
    private function runZapActiveScanSecurely($apiHost, $apiKey, $targetUrl, $contextId)
    {
        $scanParams = [
            'url' => $targetUrl,
            'contextId' => $contextId,
            'recurse' => 'true',
            'inScopeOnly' => 'true',
            'scanPolicyName' => '',
            'method' => 'GET'
        ];
        
        $scanUrl = "{$apiHost}/JSON/ascan/action/scan/?apikey=" . urlencode($apiKey) . "&" . 
                  http_build_query($scanParams);
        $scanResponse = Http::timeout(10)->get($scanUrl);
        
        if (!$scanResponse->successful()) {
            throw new \Exception("Échec scan actif sécurisé: " . $scanResponse->status());
        }
        
        $scanId = $scanResponse->json()['scan'];
        
        // Attente sécurisée du scan actif
        $this->waitForZapProcessSecurely($apiHost, $apiKey, 'ascan', $scanId, 420);
        
        return $scanId;
    }

    /**
     * Attente sécurisée des processus ZAP
     */
    private function waitForZapProcessSecurely($apiHost, $apiKey, $processType, $processId, $maxTime)
    {
        $startTime = time();
        $progress = 0;
        $waitInterval = 2;
        
        while ($progress < 100) {
            if (time() - $startTime > $maxTime) {
                Log::warning("Process ZAP sécurisé timeout", [
                    'type' => $processType,
                    'max_time' => $maxTime,
                    'scan_id' => $this->scan_id
                ]);
                break;
            }
            
            sleep($waitInterval);
            $waitInterval = min($waitInterval * 1.2, 10);
            
            try {
                $statusUrl = "{$apiHost}/JSON/{$processType}/view/status/?apikey=" . urlencode($apiKey) . 
                           "&scanId=" . urlencode($processId);
                $statusResponse = Http::timeout(5)->get($statusUrl);
                
                if ($statusResponse->successful()) {
                    $progress = (int)($statusResponse->json()['status'] ?? 0);
                }
            } catch (\Exception $e) {
                Log::warning("Erreur statut ZAP sécurisé", [
                    'type' => $processType,
                    'error' => $e->getMessage(),
                    'scan_id' => $this->scan_id
                ]);
            }
        }
    }

    /**
     * Prépare le prompt pour Gemini en fonction des données de scan
     */
    private function preparePromptFromScanData($scan)
    {
        // Ne pas exposer l'URL complète dans les logs
        $urlLength = strlen($scan->url);
        
        // Extraire les données de tous les outils
        $whatwebData = $this->extractRelevantDataFromWhatWeb($scan->whatweb_output);
        $sslyzeData = $this->extractRelevantDataFromSSLyze($scan->sslyze_output);
        $zapData = $this->extractRelevantDataFromZAP($scan->zap_output);
        $nucleiData = $this->extractRelevantDataFromNuclei($scan->nuclei_output);
            
        // Prompt sécurisé sans mention des outils spécifiques
        $promptContent = <<<EOT
You are a cybersecurity expert with a chill character who is responsible for creating a security report on the scanned website.

IMPORTANT INSTRUCTION: You must produce a professional report that covers all the results I have provided you and that DOES NOT MENTION the analysis tools used. Present the results as coming from a global security analysis, without reference to the methods or software used.

OBJECTIVE: Create a concise, factual and actionable security report that clearly identifies risks and proposes concrete solutions.

GUIDELINES:
- Focus on ALL the important data present in the data
- Prioritize issues according to their severity (Critical > High > Medium > Low)
- Use accessible language for non-specialists
- Provide concrete and applicable recommendations
- Do not invent any vulnerability that is not explicitly mentioned in the data

ANALYSIS DATA (NOT TO BE MENTIONED IN THE REPORT):

### 1. Data on technologies used:
{$whatwebData}

### 2. Data on TLS/SSL configuration:
{$sslyzeData}

### 3. Data on web vulnerabilities:
{$zapData}

### 4. Specialized detections and CVEs:
{$nucleiData}

REPORT FORMAT (DO NOT MENTION THESE CATEGORIES EXPLICITLY):

1. EXECUTIVE SUMMARY
   - Overall risk level: [Critical/High/Medium/Low]
   - Brief overview of main findings

2. MAIN VULNERABILITIES IDENTIFIED (in order of severity)
   - Name: [vulnerability name]
   - Severity: [Critical/High/Medium/Low]
   - Impact: [short description of potential impact]
   - Remediation: [concise and actionable solution]

3. PRIORITY RECOMMENDATIONS
   - [List of concrete actions to undertake, in order of priority]

4. TECHNICAL ISSUES DETECTED
   - [Obsolete versions or dangerous configurations identified]

Provide ONLY and DIRECTLY this structured report, without mentioning the tools or analysis methods used.
EOT;
        
        return $promptContent;
    }

    // LES MÉTHODES D'EXTRACTION RESTENT IDENTIQUES À LA VERSION ORIGINALE

    /**
     * Extrait les informations pertinentes des données Nuclei
     */
    private function extractRelevantDataFromNuclei($nucleiOutput)
    {
        if (empty($nucleiOutput)) {
            return "No specialized 3713 detection performed";
        }
        
        try {
            $data = json_decode($nucleiOutput, true);
            if (!$data || !isset($data['results'])) {
                return "3713 Nuclei scan performed - data being processed";
            }
            
            $summary = "## 3713 Nuclei Specialized Detections\n\n";
            $summaryData = $data['summary'] ?? [];
            $metadata = $data['scan_metadata'] ?? [];
            
            // Scan information (without exposing URL)
            $summary .= "**Security Level**: " . ($metadata['security_level'] ?? 'STANDARD') . "\n";
            $summary .= "**Strategy**: " . ($metadata['strategy'] ?? 'Standard') . "\n";
            $summary .= "**Scan Duration**: " . ($metadata['total_duration'] ?? 0) . " seconds\n";
            $summary .= "**Risk Level**: " . strtoupper($summaryData['risk_level'] ?? 'UNKNOWN') . "\n";
            $summary .= "**Vulnerabilities Detected**: " . ($summaryData['total_findings'] ?? 0) . "\n\n";
            
            // Statistics by severity
            if (($summaryData['critical_count'] ?? 0) > 0) {
                $summary .= "CRITICAL: " . $summaryData['critical_count'] . " critical vulnerability(ies)\n";
            }
            if (($summaryData['high_count'] ?? 0) > 0) {
                $summary .= "HIGH: " . $summaryData['high_count'] . " high level vulnerability(ies)\n";
            }
            if (($summaryData['medium_count'] ?? 0) > 0) {
                $summary .= "MEDIUM: " . $summaryData['medium_count'] . " medium level vulnerability(ies)\n";
            }
            if (($summaryData['low_count'] ?? 0) > 0) {
                $summary .= "LOW: " . $summaryData['low_count'] . " low level vulnerability(ies)\n";
            }
            
            // Top critical and high vulnerabilities
            $criticalFindings = array_filter($data['results'] ?? [], function($f) {
                return in_array($f['severity'] ?? '', ['critical', 'high']);
            });
            
            if (!empty($criticalFindings)) {
                $summary .= "\n### Priority Vulnerabilities 3713\n";
                foreach (array_slice($criticalFindings, 0, 5) as $finding) {
                    $severity = strtoupper($finding['severity']);
                    $name = $finding['name'];
                    $templateId = $finding['id'] ?? 'unknown';
                    
                    $summary .= "- **[{$severity}]** {$name} (ID: {$templateId})\n";
                    if (!empty($finding['description'])) {
                        $summary .= "  Description: " . substr($finding['description'], 0, 100) . "...\n";
                    }
                }
            }
            
            return $summary;
            
        } catch (\Exception $e) {
            Log::warning("Nuclei extraction error (secure mode)", ['scan_id' => $this->scan_id]);
            return "3713 Nuclei scan performed - secure analysis in progress";
        }
    }

    /**
     * Extrait les informations complètes des données WhatWeb
     */
    private function extractRelevantDataFromWhatWeb($rawOutput)
    {
        // Si la sortie est trop longue, extraire systématiquement les informations importantes
        if (strlen($rawOutput) > 2000) {
            $relevantData = "";
            
            // CATÉGORIE 1: CMS et Frameworks - critiques pour évaluer les CVE
            $cmsPatterns = [
                '/WordPress\[[^\]]+\]/', '/Drupal\[[^\]]+\]/', '/Joomla\[[^\]]+\]/',
                '/Magento\[[^\]]+\]/', '/Shopify\[[^\]]+\]/', '/PrestaShop\[[^\]]+\]/',
                '/Laravel\[[^\]]+\]/', '/Symfony\[[^\]]+\]/', '/CodeIgniter\[[^\]]+\]/',
                '/Django\[[^\]]+\]/', '/Flask\[[^\]]+\]/', '/Ruby-on-Rails\[[^\]]+\]/',
                '/Express\.js\[[^\]]+\]/', '/ASP\.NET\[[^\]]+\]/', '/Spring\[[^\]]+\]/',
                '/Struts\[[^\]]+\]/'
            ];
            
            // CATÉGORIE 2: Frameworks JavaScript - composants frontend à risque
            $jsFrameworkPatterns = [
                '/JQuery\[[^\]]+\]/', '/React\[[^\]]+\]/', '/Angular\[[^\]]+\]/',
                '/Vue\.js\[[^\]]+\]/', '/Backbone\[[^\]]+\]/', '/Ember\[[^\]]+\]/',
                '/Bootstrap\[[^\]]+\]/', '/Tailwind\[[^\]]+\]/', '/Foundation\[[^\]]+\]/'
            ];
            
            // CATÉGORIE 3: Serveurs et configuration - informations d'infrastructure
            $serverPatterns = [
                '/PHP\[[^\]]+\]/', '/Apache\[[^\]]+\]/', '/Nginx\[[^\]]+\]/',
                '/IIS\[[^\]]+\]/', '/Tomcat\[[^\]]+\]/', '/Node\.js\[[^\]]+\]/',
                '/Python\[[^\]]+\]/', '/Ruby\[[^\]]+\]/', '/Java\[[^\]]+\]/',
                '/X-Powered-By\[[^\]]+\]/', '/Server\[[^\]]+\]/', '/HTTPServer\[[^\]]+\]/',
                '/PoweredBy\[[^\]]+\]/', '/Cookies\[[^\]]+\]/'
            ];
            
            // CATÉGORIE 4: Headers de sécurité - défenses existantes
            $securityHeaderPatterns = [
                '/Content-Security-Policy\[[^\]]+\]/', '/X-XSS-Protection\[[^\]]+\]/',
                '/X-Frame-Options\[[^\]]+\]/', '/X-Content-Type-Options\[[^\]]+\]/',
                '/Strict-Transport-Security\[[^\]]+\]/', '/Public-Key-Pins\[[^\]]+\]/',
                '/Referrer-Policy\[[^\]]+\]/', '/Feature-Policy\[[^\]]+\]/',
                '/Permissions-Policy\[[^\]]+\]/', '/Clear-Site-Data\[[^\]]+\]/'
            ];
            
            // CATÉGORIE 5: Informations générales et méta-données
            $generalPatterns = [
                '/IP\[[^\]]+\]/', '/Country\[[^\]]+\]/', '/Email\[[^\]]+\]/',
                '/Title\[[^\]]+\]/', '/MetaGenerator\[[^\]]+\]/', '/MetaDescription\[[^\]]+\]/',
                '/Script\[[^\]]+\]/', '/Google-Analytics\[[^\]]+\]/', '/Facebook\[[^\]]+\]/',
                '/CloudFlare\[[^\]]+\]/', '/CDN\[[^\]]+\]/', '/WAF\[[^\]]+\]/',
                '/HTML5\[[^\]]+\]/', '/HTTPOnly\[[^\]]+\]/', '/SameSite\[[^\]]+\]/'
            ];
            
            // Patterns combinés avec catégorisation
            $allPatterns = [
                'CMS & Frameworks' => $cmsPatterns,
                'JavaScript Technologies' => $jsFrameworkPatterns,
                'Serveurs & Infrastructure' => $serverPatterns,
                'Headers de Sécurité' => $securityHeaderPatterns,
                'Informations Générales' => $generalPatterns
            ];
            
            // Extraire et organiser par catégorie
            foreach ($allPatterns as $category => $patterns) {
                $categoryResults = [];
                
                foreach ($patterns as $pattern) {
                    if (preg_match_all($pattern, $rawOutput, $matches)) {
                        foreach ($matches[0] as $match) {
                            $categoryResults[] = $match;
                        }
                    }
                }
                
                // Ajouter la catégorie seulement si des résultats ont été trouvés
                if (!empty($categoryResults)) {
                    $relevantData .= "## $category\n";
                    $relevantData .= implode("\n", $categoryResults) . "\n\n";
                }
            }
            
            // Extraction spécifique des versions potentiellement vulnérables
            if (preg_match_all('/(\w+)\[version\D*([0-9\.]+)\]/', $rawOutput, $versionMatches)) {
                $relevantData .= "## Versions spécifiques détectées\n";
                for ($i = 0; $i < count($versionMatches[0]); $i++) {
                    $relevantData .= "{$versionMatches[1][$i]} version {$versionMatches[2][$i]}\n";
                }
                $relevantData .= "\n";
            }
            
            return $relevantData ?: "Aucune information pertinente détectée dans les données WhatWeb.";
        }
        
        // Si la sortie est suffisamment courte, la retourner telle quelle
        return $rawOutput;
    }

    /**
     * Extrait les informations complètes des données SSLyze
     */
    private function extractRelevantDataFromSSLyze($rawOutput)
    {
        if (strlen($rawOutput) > 2000) {
            $relevantData = "";
            
            // SECTION 1: Vulnérabilités critiques - catégorisées par priorité
            $criticalVulns = [
                'CRITIQUE' => [
                    '/VULNERABLE TO HEARTBLEED/',
                    '/VULNERABLE TO CCS INJECTION/',
                    '/VULNERABLE TO ROBOT ATTACK/',
                    '/VULNERABLE TO TICKETBLEED/',
                    '/VULNERABLE TO SWEET32/',
                    '/VULNERABLE TO LOGJAM/',
                    '/VULNERABLE TO DROWN/',
                    '/VULNERABLE TO POODLE/',
                    '/VULNERABLE TO FREAK/',
                    '/VULNERABLE TO CRIME/',
                    '/VULNERABLE TO BREACH/',
                    '/VULNERABLE TO LUCKY13/'
                ],
                'PROTOCOLS OBSOLÈTES' => [
                    '/SSLv2 is supported/',
                    '/SSLv3 is supported/',
                    '/TLS 1\.0 is supported/',
                    '/TLS 1\.1 is supported/'
                ],
                'PROBLÈMES DE CERTIFICAT' => [
                    '/Certificate is UNTRUSTED/',
                    '/Certificate is EXPIRED/',
                    '/Certificate hostname mismatch/',
                    '/Certificate is self-signed/',
                    '/Certificate is revoked/',
                    '/Certificate contains weak algorithm/',
                    '/Certificate contains weak key/'
                ]
            ];
            
            // SECTION 2: Informations de configuration
            $configInfo = [
                'PROTOCOLES SUPPORTÉS' => [
                    '/TLS 1\.0[^\n]+/',
                    '/TLS 1\.1[^\n]+/',
                    '/TLS 1\.2[^\n]+/',
                    '/TLS 1\.3[^\n]+/'
                ],
                'INFORMATIONS CERTIFICAT' => [
                    '/Signature Algorithm:([^\n]+)/',
                    '/Key Size:([^\n]+)/',
                    '/Not Before:([^\n]+)/',
                    '/Not After:([^\n]+)/',
                    '/Issued To:([^\n]+)/',
                    '/Issued By:([^\n]+)/',
                    '/Certificate matches([^\n]+)/'
                ],
                'CONFIGURATION AVANCÉE' => [
                    '/Certificate Transparency:([^\n]+)/',
                    '/OCSP Stapling:([^\n]+)/',
                    '/HSTS:([^\n]+)/',
                    '/Public Key Pinning:([^\n]+)/',
                    '/Cipher order is NOT secure/',
                    '/Perfect Forward Secrecy:([^\n]+)/'
                ]
            ];
            
            // SECTION 3: Chiffrements faibles
            $weakCiphers = [
                '/Cipher suites for .*NULL.*/',
                '/Cipher suites for .*RC4.*/',
                '/Cipher suites for .*DES.*/',
                '/Cipher suites for .*MD5.*/',
                '/Cipher suites for .*EXPORT.*/',
                '/Cipher suites for .*ANON.*/',
                '/Cipher suites with key size < 128 bits/'
            ];
            
            // Extraire les vulnérabilités critiques
            foreach ($criticalVulns as $category => $patterns) {
                $categoryResults = [];
                
                foreach ($patterns as $pattern) {
                    if (preg_match_all($pattern, $rawOutput, $matches)) {
                        foreach ($matches[0] as $match) {
                            $categoryResults[] = $match;
                        }
                    }
                }
                
                if (!empty($categoryResults)) {
                    $relevantData .= "## $category\n";
                    $relevantData .= implode("\n", $categoryResults) . "\n\n";
                }
            }
            
            // Extraire les informations de configuration
            foreach ($configInfo as $category => $patterns) {
                $categoryResults = [];
                
                foreach ($patterns as $pattern) {
                    if (preg_match_all($pattern, $rawOutput, $matches)) {
                        foreach ($matches[0] as $match) {
                            $categoryResults[] = $match;
                        }
                    }
                }
                
                if (!empty($categoryResults)) {
                    $relevantData .= "## $category\n";
                    $relevantData .= implode("\n", $categoryResults) . "\n\n";
                }
            }
            
            // Extraire les chiffrements faibles
            $weakCipherResults = [];
            foreach ($weakCiphers as $pattern) {
                if (preg_match_all($pattern, $rawOutput, $matches)) {
                    foreach ($matches[0] as $match) {
                        $weakCipherResults[] = $match;
                    }
                }
            }
            
            if (!empty($weakCipherResults)) {
                $relevantData .= "## CHIFFREMENTS FAIBLES DÉTECTÉS\n";
                $relevantData .= implode("\n", $weakCipherResults) . "\n\n";
            }
            
            return $relevantData ?: "Aucune information critique détectée dans l'analyse SSL/TLS.";
        }
        
        return $rawOutput;
    }

    /**
     * Extrait les informations complètes des données ZAP
     */
    private function extractRelevantDataFromZAP($rawOutput)
    {
        try {
            $zapData = json_decode($rawOutput, true);
            
            if (json_last_error() === JSON_ERROR_NONE && !empty($zapData['alerts'])) {
                $alerts = $zapData['alerts'];
                $relevantData = "";
                
                // Organiser les alertes par niveau de risque
                $riskLevels = [
                    'High' => [],
                    'Medium' => [],
                    'Low' => [],
                    'Informational' => []
                ];
                
                // Catégoriser les alertes par niveau de risque
                foreach ($alerts as $alert) {
                    $risk = $alert['risk'] ?? 'Unknown';
                    if (isset($riskLevels[$risk])) {
                        $riskLevels[$risk][] = $alert;
                    }
                }
                
                // Traiter chaque niveau de risque
                foreach ($riskLevels as $risk => $riskAlerts) {
                    if (empty($riskAlerts)) {
                        continue;
                    }
                    
                    // Limiter le nombre d'alertes par niveau de risque
                    $maxAlerts = ($risk === 'High') ? 10 : 
                                (($risk === 'Medium') ? 7 : 
                                (($risk === 'Low') ? 5 : 3));
                    
                    $limitedAlerts = array_slice($riskAlerts, 0, $maxAlerts);
                    
                    $relevantData .= "## Alertes de niveau $risk (" . count($riskAlerts) . " détectées)\n\n";
                    
                    foreach ($limitedAlerts as $index => $alert) {
                        $name = $alert['name'] ?? 'Alerte inconnue';
                        $confidence = $alert['confidence'] ?? 'Non spécifié';
                        $description = $alert['description'] ?? 'Aucune description';
                        $solution = $alert['solution'] ?? 'Aucune solution fournie';
                        $instances = count($alert['instances'] ?? []);
                        
                        $relevantData .= "### " . ($index + 1) . ". $name\n";
                        $relevantData .= "- **Confiance**: $confidence\n";
                        if ($instances > 0) {
                            $relevantData .= "- **Occurrences**: $instances\n";
                        }
                        $relevantData .= "- **Description**: " . $this->truncateIntelligently($description, 250) . "\n";
                        $relevantData .= "- **Solution**: " . $this->truncateIntelligently($solution, 250) . "\n\n";
                    }
                    
                    // Si plus d'alertes que la limite, indiquer combien ont été omises
                    if (count($riskAlerts) > $maxAlerts) {
                        $omitted = count($riskAlerts) - $maxAlerts;
                        $relevantData .= "*$omitted autres alertes de niveau $risk non affichées*\n\n";
                    }
                }
                
                // Statistiques récapitulatives
                $relevantData .= "## Résumé des alertes\n";
                $relevantData .= "- Alertes critiques: " . count($riskLevels['High']) . "\n";
                $relevantData .= "- Alertes moyennes: " . count($riskLevels['Medium']) . "\n";
                $relevantData .= "- Alertes faibles: " . count($riskLevels['Low']) . "\n";
                $relevantData .= "- Informations: " . count($riskLevels['Informational']) . "\n";
                $relevantData .= "- Total: " . array_sum(array_map('count', $riskLevels)) . "\n";
                
                return $relevantData ?: "Aucune alerte de sécurité détectée.";
            }
        } catch (\Exception $e) {
            Log::warning("Erreur lors de l'extraction des données ZAP: " . $e->getMessage());
        }
        
        return $rawOutput;
    }

    /**
     * Méthode utilitaire pour tronquer intelligemment le texte
     */
    private function truncateIntelligently($text, $length = 200)
    {
        if (strlen($text) <= $length) {
            return $text;
        }
        
        $truncated = substr($text, 0, $length);
        $lastSpace = strrpos($truncated, ' ');
        
        if ($lastSpace !== false) {
            return substr($truncated, 0, $lastSpace) . '...';
        }
        
        return $truncated . '...';
    }
        
    /**
     * Appel sécurisé à l'API Gemini
     */
    private function callGeminiAPI($prompt)
    {
        // Validation sécurisée des clés API
        $apiKey = $this->getSecureEnvValue('GEMINI_API_KEY', '');
        $apiUrl = $this->getSecureEnvValue('GEMINI_API_URL', 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent');
        
        if (empty($apiKey)) {
            Log::warning('Gemini API key not configured (secure mode)', ['scan_id' => $this->scan_id]);
            return "Automatic analysis could not be generated because the API key is not configured in secure mode.";
        }
        
        try {
            // Construction sécurisée du corps de requête
            $requestBody = [
                'contents' => [
                    [
                        'parts' => [
                            ['text' => $prompt]
                        ]
                    ]
                ],
                'generationConfig' => [
                    'temperature' => 0.2,
                    'maxOutputTokens' => 1800
                ],
                'safetySettings' => [
                    [
                        'category' => 'HARM_CATEGORY_DANGEROUS_CONTENT',
                        'threshold' => 'BLOCK_MEDIUM_AND_ABOVE'
                    ]
                ]
            ];
            
            // Appel API sécurisé
            $response = Http::timeout(30)->retry(3, 1000)->withHeaders([
                'Content-Type' => 'application/json',
                'User-Agent' => '3713-Security-Scanner/1.0'
            ])->post($apiUrl . '?key=' . urlencode($apiKey), $requestBody);
            
            if ($response->successful()) {
                $data = $response->json();
                
                if (isset($data['candidates'][0]['content']['parts'][0]['text'])) {
                    Log::info("Gemini analysis generated successfully (secure mode)", ['scan_id' => $this->scan_id]);
                    return $data['candidates'][0]['content']['parts'][0]['text'];
                } else {
                    Log::warning('Unexpected Gemini API response structure (secure mode)', ['scan_id' => $this->scan_id]);
                    return "Automatic analysis could not be generated (unexpected response format in secure mode).";
                }
            } else {
                Log::error('Gemini API error (secure mode)', [
                    'status' => $response->status(),
                    'scan_id' => $this->scan_id
                ]);
                return "Automatic analysis could not be generated due to an external API error in secure mode.";
            }
        } catch (\Exception $e) {
            Log::error("Exception when calling Gemini API (secure mode)", [
                'error' => $e->getMessage(),
                'scan_id' => $this->scan_id
            ]);
            return "Automatic analysis could not be generated due to an error in secure mode: " . $e->getMessage();
        }
    }
}