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
    
    // Augmenter le timeout du job
    public $timeout = 600; // 10 minutes pour l'ensemble du job (inclut l'analyse Gemini)

    public function __construct($url, $scan_id)
    {
        $this->url = $url;
        $this->scan_id = $scan_id;
    }

    public function handle()
    {
        $scan = ScanResult::where('scan_id', $this->scan_id)->first();
        if (!$scan) {
            Log::error("Scan ID {$this->scan_id} non trouvé");
            return;
        }

        Log::info("Début du scan pour l'URL: {$this->url}");

        // Mise à jour pour indiquer que le scan a commencé
        $scan->update(['status' => 'running']);

        try {
            // Appelle whatweb avec un timeout plus long
            Log::info("Démarrage de whatweb");
            $whatweb = $this->runCommand("/opt/whatweb/whatweb -v {$this->url}", 60);
            Log::info("Whatweb terminé, taille du résultat: " . strlen($whatweb));
            
            // Appelle sslyze avec un timeout plus long
            Log::info("Démarrage de sslyze");
            $sslyze = $this->runCommand("/opt/venv/bin/sslyze {$this->url}", 120);
            Log::info("Sslyze terminé, taille du résultat: " . strlen($sslyze));
            
            // Appel réel à ZAP
            Log::info("Démarrage du scan ZAP");
            $zapResults = $this->runZapScan($this->url);
            Log::info("ZAP terminé, résultats obtenus");
            
            // Mettre à jour la base de données avec les résultats
            $scan->update([
                'whatweb_output' => $whatweb ?: 'Aucun résultat',
                'sslyze_output' => $sslyze ?: 'Aucun résultat',
                'zap_output' => $zapResults ?: 'Aucun résultat',
            ]);
            
            // Générer l'analyse Gemini
            Log::info("Génération de l'analyse Gemini pour le scan {$this->scan_id}");
            try {
                // Préparer les données pour Gemini
                $prompt = $this->preparePromptFromScanData($scan);
                
                // Appeler l'API Gemini
                $analysis = $this->callGeminiAPI($prompt);
                
                // Enregistrer les résultats dans la base de données
                $scan->update([
                    'gemini_analysis' => $analysis,
                    'status' => 'completed'
                ]);
                
                Log::info("Analyse Gemini générée avec succès");
            } catch (\Exception $e) {
                Log::warning("Erreur lors de la génération de l'analyse Gemini: " . $e->getMessage());
                // On ne fait pas échouer tout le scan pour une erreur Gemini
                $scan->update([
                    'gemini_analysis' => "L'analyse automatique n'a pas pu être générée: " . $e->getMessage(),
                    'status' => 'completed'
                ]);
            }
            
            Log::info("Scan terminé avec succès pour {$this->url}");
        } catch (\Exception $e) {
            Log::error("Erreur lors du scan pour {$this->url}: " . $e->getMessage());
            $scan->update([
                'status' => 'failed',
                'error' => $e->getMessage()
            ]);
        }
    }

    protected function runZapScan($targetUrl)
    {
        $apiKey = env('ZAP_API_KEY', '13373713');
        $apiHost = env('ZAP_API_HOST', 'http://zap:8090');

        // Vérifier et normaliser l'URL 
        if (!preg_match('~^https?://~i', $targetUrl)) {
            // Si l'URL ne commence pas par http:// ou https://, ajouter http:// par défaut
            $targetUrl = 'http://' . $targetUrl;
            Log::info("URL normalisée avec protocole par défaut: {$targetUrl}");
        }

        Log::info("Connexion à ZAP sur {$apiHost} avec clé API");
        Log::info("Ciblage de l'URL: {$targetUrl}");

        try {
            // 1. Vérifier que l'API est disponible
            $apiCheckUrl = "{$apiHost}/JSON/core/view/version/?apikey={$apiKey}";
            $checkResponse = Http::timeout(10)->get($apiCheckUrl);
            
            if (!$checkResponse->successful()) {
                throw new \Exception("Impossible de se connecter à l'API ZAP: " . $checkResponse->body());
            }
            
            Log::info("API ZAP accessible, version: " . ($checkResponse->json()['version'] ?? 'inconnue'));
            
            // 2. Extraire le domaine de l'URL pour créer un contexte approprié
            $urlParts = parse_url($targetUrl);
            
            // Vérification que parse_url a retourné un tableau et non une chaîne
            if (!is_array($urlParts)) {
                throw new \Exception("Impossible de parser l'URL: {$targetUrl}");
            }
            
            // Vérification supplémentaire que parse_url a bien fonctionné
            if (!isset($urlParts['host'])) {
                throw new \Exception("URL malformée, impossible d'extraire le domaine: {$targetUrl}");
            }
            
            $domain = $urlParts['host'];
            $scheme = isset($urlParts['scheme']) ? $urlParts['scheme'] : 'http';
            
            // 3. Créer un nouveau contexte avec un nom unique
            $contextName = 'ctx_' . substr(md5($domain . time()), 0, 8);
            Log::info("Création du contexte ZAP: {$contextName} pour le domaine: {$domain}");
            
            $createContextUrl = "{$apiHost}/JSON/context/action/newContext/?apikey={$apiKey}&contextName={$contextName}";
            $contextResponse = Http::get($createContextUrl);
            
            if (!$contextResponse->successful()) {
                throw new \Exception("Échec de la création du contexte ZAP: " . $contextResponse->body());
            }
            
            // Récupérer immédiatement l'ID du contexte créé
            $contextId = null;
            if (isset($contextResponse->json()['contextId'])) {
                $contextId = $contextResponse->json()['contextId'];
                Log::info("ID du contexte '{$contextName}' créé: {$contextId}");
            } else {
                // Si l'API ne renvoie pas l'ID lors de la création, récupérer la liste des contextes
                $contextListUrl = "{$apiHost}/JSON/context/view/contextList/?apikey={$apiKey}";
                $contextListResponse = Http::get($contextListUrl);
                
                if (!$contextListResponse->successful()) {
                    throw new \Exception("Échec de la récupération de la liste des contextes: " . $contextListResponse->body());
                }
                
                $contextListData = $contextListResponse->json();
                if (!isset($contextListData['contextList']) || !is_array($contextListData['contextList'])) {
                    Log::info("Format de réponse pour la liste des contextes: " . json_encode($contextListData));
                    throw new \Exception("Format de réponse inattendu pour la liste des contextes");
                }
                
                foreach ($contextListData['contextList'] as $context) {
                    if (isset($context['name']) && $context['name'] === $contextName) {
                        $contextId = $context['id'];
                        Log::info("ID du contexte '{$contextName}' trouvé dans la liste: {$contextId}");
                        break;
                    }
                }
                
                if ($contextId === null) {
                    Log::info("Liste complète des contextes: " . json_encode($contextListData));
                    throw new \Exception("Impossible de trouver l'ID du contexte '{$contextName}' dans la liste");
                }
            }
            
            // 4. Inclure l'URL dans le contexte avec un regex simplifié
            // Créer un regex qui inclut tout le domaine
            $regex = $scheme . '://' . $domain . '.*';
            Log::info("Ajout du regex au contexte: {$regex}");
            
            $includeUrl = "{$apiHost}/JSON/context/action/includeInContext/?apikey={$apiKey}&contextName={$contextName}&regex=" . urlencode($regex);
            $includeResponse = Http::get($includeUrl);
            
            if (!$includeResponse->successful()) {
                throw new \Exception("Échec de l'ajout de l'URL au contexte: " . $includeResponse->body());
            }
            
            // 5. Accéder à l'URL pour s'assurer qu'elle est dans la session ZAP
            Log::info("Accès à l'URL: {$targetUrl}");
            $accessUrl = "{$apiHost}/JSON/core/action/accessUrl/?apikey={$apiKey}&url=" . urlencode($targetUrl);
            $accessResponse = Http::get($accessUrl);
            
            if (!$accessResponse->successful()) {
                throw new \Exception("Échec de l'accès à l'URL: " . $accessResponse->body());
            }
            
            // 6. Démarrer le spider en spécifiant le contexte
            Log::info("Démarrage du spider pour: {$targetUrl} avec contexte: {$contextName}");
            $spiderUrl = "{$apiHost}/JSON/spider/action/scan/?apikey={$apiKey}&url=" . urlencode($targetUrl) . "&contextName=" . urlencode($contextName);
            $response = Http::get($spiderUrl);
            
            if (!$response->successful()) {
                throw new \Exception("Échec du démarrage du spider ZAP: " . $response->body());
            }
            
            // Vérification que la réponse contient un JSON valide avec l'ID du scan
            $responseData = $response->json();
            if (!isset($responseData['scan'])) {
                throw new \Exception("Format de réponse inattendu pour le spider ZAP: " . $response->body());
            }
            
            $spiderId = $responseData['scan'];
            Log::info("Spider ZAP démarré avec ID: {$spiderId}");
            
            // 7. Attendre que le spider se termine
            $spiderStatusUrl = "{$apiHost}/JSON/spider/view/status/?apikey={$apiKey}&scanId={$spiderId}";
            $this->waitForCompletion($spiderStatusUrl, "Spider ZAP", 300);
            
            // 8. Vérifier à nouveau l'ID du contexte (au cas où il aurait changé)
            // Cette étape est cruciale car parfois l'ID du contexte peut changer ou être différent après le scan
            Log::info("Vérification de l'ID du contexte après le spider...");        
            $contextListUrl = "{$apiHost}/JSON/context/view/contextList/?apikey={$apiKey}";
            $contextListResponse = Http::get($contextListUrl);
            
            if (!$contextListResponse->successful()) {
                throw new \Exception("Échec de la récupération de la liste des contextes après spider: " . $contextListResponse->body());
            }
            
            $contextListData = $contextListResponse->json();
            Log::info("Liste des contextes après spider: " . json_encode($contextListData));
            
            // Réinitialisation de contextId pour s'assurer qu'on a la valeur la plus récente
            $contextId = null;
            
            if (isset($contextListData['contextList']) && is_array($contextListData['contextList'])) {
                foreach ($contextListData['contextList'] as $context) {
                    if (isset($context['name']) && $context['name'] === $contextName && isset($context['id'])) {
                        $contextId = $context['id'];
                        Log::info("ID du contexte '{$contextName}' après spider: {$contextId}");
                        break;
                    }
                }
            }
            
            if ($contextId === null) {
                // Tentative d'approche alternative: essayer de lancer le scan sans l'ID du contexte
                Log::warning("Impossible de trouver l'ID du contexte '{$contextName}'. Tentative de scan sans contexte ID.");
                
                // 9. Lancer le scan actif sans le contexte ID, juste avec l'URL cible
                Log::info("Démarrage du scan actif pour: {$targetUrl} sans contexte ID");
                $scanUrl = "{$apiHost}/JSON/ascan/action/scan/?apikey={$apiKey}&url=" . urlencode($targetUrl);
                $response = Http::get($scanUrl);
            } else {
                // 9. Lancer le scan actif avec le contexte ID
                Log::info("Démarrage du scan actif pour: {$targetUrl} avec contexte ID: {$contextId}");
                $scanUrl = "{$apiHost}/JSON/ascan/action/scan/?apikey={$apiKey}&url=" . urlencode($targetUrl) . "&contextId={$contextId}";
                $response = Http::get($scanUrl);
            }
            
            if (!$response->successful()) {
                throw new \Exception("Échec du démarrage du scan ZAP: " . $response->body());
            }
            
            $scanData = $response->json();
            if (!isset($scanData['scan'])) {
                throw new \Exception("Format de réponse inattendu pour le scan ZAP: " . $response->body());
            }
            
            $scanId = $scanData['scan'];
            Log::info("Scan ZAP actif démarré avec ID: {$scanId}");
            
            // 10. Attendre la fin du scan
            $statusUrl = "{$apiHost}/JSON/ascan/view/status/?apikey={$apiKey}&scanId={$scanId}";
            $this->waitForCompletion($statusUrl, "Scan actif ZAP", 600);
            
            // 11. Récupérer les résultats
            $resultsUrl = "{$apiHost}/JSON/core/view/alerts/?apikey={$apiKey}&baseurl=" . urlencode($targetUrl);
            $resultsResponse = Http::get($resultsUrl);
            
            if (!$resultsResponse->successful()) {
                throw new \Exception("Échec de la récupération des résultats ZAP: " . $resultsResponse->body());
            }
            
            return json_encode($resultsResponse->json(), JSON_PRETTY_PRINT);
            
        } catch (\Exception $e) {
            Log::error("Exception détaillée dans runZapScan: " . $e->getMessage());
            throw $e;
        }
    }

    protected function waitForCompletion($statusUrl, $scanType, $timeout)
    {
        $progress = 0;
        $startTime = time();
        
        Log::info("Attente de la fin du {$scanType}...");
        
        while ($progress < 100) {
            if (time() - $startTime > $timeout) {
                throw new \Exception("Timeout du {$scanType} après {$timeout} secondes");
            }
            
            sleep(5); // Vérifier toutes les 5 secondes
            
            try {
                $statusResponse = Http::timeout(10)->get($statusUrl);
                
                if (!$statusResponse->successful()) {
                    Log::warning("Erreur lors de la vérification du statut: " . $statusResponse->body());
                    continue;
                }
                
                $responseData = $statusResponse->json();
                
                // Vérification supplémentaire que la réponse est bien un tableau
                if (!is_array($responseData)) {
                    Log::warning("Réponse de statut invalide, pas un tableau JSON: " . $statusResponse->body());
                    continue;
                }
                
                if (!isset($responseData['status'])) {
                    Log::warning("Format de réponse inattendu pour le statut: " . json_encode($responseData));
                    continue;
                }
                
                // Assurer que le statut est bien un entier
                $statusValue = $responseData['status'];
                if (is_numeric($statusValue)) {
                    $progress = (int)$statusValue;
                    Log::info("Progression du {$scanType}: {$progress}%");
                } else {
                    Log::warning("Valeur de statut non numérique: " . $statusValue);
                }
            } catch (\Exception $e) {
                Log::warning("Exception lors de la vérification du statut: " . $e->getMessage());
                // Continuer la boucle malgré l'erreur
            }
        }
        
        Log::info("{$scanType} terminé avec succès");
    }

    protected function runCommand($command, $timeout = 60)
    {
        Log::info("Exécution de la commande: $command avec timeout: $timeout");
        
        // Utiliser un timeout plus strict avec un exec asynchrone
        $output = '';
        $errorOutput = '';
        
        $descriptorspec = [
            0 => ['pipe', 'r'],  // stdin
            1 => ['pipe', 'w'],  // stdout
            2 => ['pipe', 'w'],  // stderr
        ];
        
        // Ajouter l'environnement pour s'assurer que les chemins sont corrects
        $env = array_merge($_ENV, [
            'PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/whatweb:/opt/venv/bin',
        ]);
        
        $process = proc_open($command, $descriptorspec, $pipes, null, $env);
        
        if (!is_resource($process)) {
            throw new \Exception('Impossible de démarrer la commande');
        }
        
        // Mettre les flux en mode non bloquant
        stream_set_blocking($pipes[1], 0);
        stream_set_blocking($pipes[2], 0);
        
        // Fermer stdin
        fclose($pipes[0]);
        
        // Définir un délai d'attente
        $startTime = time();
        
        do {
            // Lire les sorties disponibles
            $tmpOut = fgets($pipes[1], 4096);
            if ($tmpOut !== false) $output .= $tmpOut;
            
            $tmpErr = fgets($pipes[2], 4096);
            if ($tmpErr !== false) $errorOutput .= $tmpErr;
            
            // Vérifier si le processus est toujours en cours d'exécution
            $status = proc_get_status($process);
            
            // Vérifier le timeout
            if (time() - $startTime > $timeout) {
                proc_terminate($process, 9); // SIGKILL
                throw new \Exception("La commande a dépassé le délai d'attente de {$timeout} secondes");
            }
            
            // Petite pause pour ne pas surcharger le CPU
            usleep(100000); // 100ms
            
        } while ($status['running']);
        
        // Récupérer tout ce qui reste
        while ($tmpOut = fgets($pipes[1], 4096)) {
            $output .= $tmpOut;
        }
        
        while ($tmpErr = fgets($pipes[2], 4096)) {
            $errorOutput .= $tmpErr;
        }
        
        // Fermer les flux
        fclose($pipes[1]);
        fclose($pipes[2]);
        
        // Fermer le processus
        $exitCode = proc_close($process);
        
        Log::info("Commande terminée avec code de sortie: $exitCode");
        if ($exitCode !== 0) {
            Log::warning("Erreur dans la commande (code $exitCode): " . $errorOutput);
        }
        
        if (empty($output) && empty($errorOutput)) {
            Log::warning("Aucune sortie générée par la commande");
            return "Aucune sortie générée par la commande (code $exitCode)";
        }
        
        return $output ?: $errorOutput;
    }

    /**
     * Prépare le prompt pour Gemini en fonction des données de scan
     */
    private function preparePromptFromScanData($scan)
    {
        // Extraire et sélectionner les données pertinentes du scan
        $urlData = $scan->url;
        
        // Essayer de parser les sorties JSON si disponibles
        $whatwebData = $this->extractRelevantDataFromWhatWeb($scan->whatweb_output);
        $sslyzeData = $this->extractRelevantDataFromSSLyze($scan->sslyze_output);
        $zapData = $this->extractRelevantDataFromZAP($scan->zap_output);
        
        // Construire le prompt pour Gemini
        $promptContent = "Générer un rapport synthétique et concis de sécurité pour l'URL: {$urlData}. ";
        $promptContent .= "Le rapport doit être factuel, se concentrer uniquement sur les problèmes de sécurité les plus importants, ";
        $promptContent .= "et inclure des recommandations simples et directes pour remédier aux problèmes identifiés. ";
        $promptContent .= "Évitez d'inclure des analyses excessivement techniques ou longues. ";
        $promptContent .= "Voici les données de scan qui doivent être analysées:\n\n";
        
        // Ajouter les données
        $promptContent .= "### Données WhatWeb (identification des technologies):\n";
        $promptContent .= $whatwebData . "\n\n";
        
        $promptContent .= "### Données SSLyze (analyse SSL/TLS):\n";
        $promptContent .= $sslyzeData . "\n\n";
        
        $promptContent .= "### Données ZAP (vulnérabilités):\n";
        $promptContent .= $zapData . "\n\n";
        
        $promptContent .= "Format du rapport souhaité:\n";
        $promptContent .= "1. Résumé exécutif (2-3 phrases)\n";
        $promptContent .= "2. Principales vulnérabilités détectées (3-5 maximum)\n";
        $promptContent .= "3. Recommandations clés (concises et pratiques)\n";
        
        return $promptContent;
    }
    
    /**
     * Extrait les informations pertinentes des données WhatWeb
     */
    private function extractRelevantDataFromWhatWeb($rawOutput)
    {
        // Si la sortie est trop longue, essayer de l'extraire
        // Sinon, garder telle quelle pour éviter de perdre des informations importantes
        if (strlen($rawOutput) > 2000) {
            // Essayer de trouver les informations les plus pertinentes
            $relevantData = "";
            
            // Rechercher les CMS, frameworks, serveurs, etc.
            $patterns = [
                '/WordPress\[[^\]]+\]/',
                '/Drupal\[[^\]]+\]/',
                '/Joomla\[[^\]]+\]/',
                '/PHP\[[^\]]+\]/',
                '/Apache\[[^\]]+\]/',
                '/Nginx\[[^\]]+\]/',
                '/IIS\[[^\]]+\]/',
                '/JQuery\[[^\]]+\]/',
                '/Bootstrap\[[^\]]+\]/',
                '/X-Powered-By\[[^\]]+\]/',
                '/Server\[[^\]]+\]/',
                '/IP\[[^\]]+\]/',
                '/Country\[[^\]]+\]/',
                '/HTTPServer\[[^\]]+\]/',
            ];
            
            foreach ($patterns as $pattern) {
                if (preg_match_all($pattern, $rawOutput, $matches)) {
                    foreach ($matches[0] as $match) {
                        $relevantData .= $match . "\n";
                    }
                }
            }
            
            return $relevantData ?: "Données WhatWeb trop volumineuses pour être analysées complètement.";
        }
        
        return $rawOutput;
    }
    
    /**
     * Extrait les informations pertinentes des données SSLyze
     */
    private function extractRelevantDataFromSSLyze($rawOutput)
    {
        // Si la sortie est trop longue, essayer de l'extraire
        if (strlen($rawOutput) > 2000) {
            $relevantData = "";
            
            // Rechercher les informations cruciales SSL/TLS
            $patterns = [
                '/VULNERABLE TO HEARTBLEED/',
                '/VULNERABLE TO CCS INJECTION/',
                '/VULNERABLE TO ROBOT ATTACK/',
                '/TLS 1\.0[^\n]+/',
                '/TLS 1\.1[^\n]+/',
                '/TLS 1\.2[^\n]+/',
                '/TLS 1\.3[^\n]+/',
                '/Certificate is UNTRUSTED/',
                '/Certificate is TRUSTED/',
                '/Certificate matches/',
                '/Issued To:/',
                '/Issued By:/',
                '/Signature Algorithm:/',
                '/Not After:/'
            ];
            
            foreach ($patterns as $pattern) {
                if (preg_match_all($pattern, $rawOutput, $matches)) {
                    foreach ($matches[0] as $match) {
                        $relevantData .= $match . "\n";
                    }
                }
            }
            
            return $relevantData ?: "Données SSLyze trop volumineuses pour être analysées complètement.";
        }
        
        return $rawOutput;
    }
    
    /**
     * Extrait les informations pertinentes des données ZAP
     */
    private function extractRelevantDataFromZAP($rawOutput)
    {
        // Essayer de décoder le JSON si possible
        try {
            $zapData = json_decode($rawOutput, true);
            
            // Si le décodage a fonctionné et que nous avons des alertes
            if (json_last_error() === JSON_ERROR_NONE && !empty($zapData['alerts'])) {
                // Extraire et normaliser les alertes, triées par niveau de risque
                $alerts = $zapData['alerts'];
                
                // Filtrer pour ne garder que les alertes de niveau High ou Medium
                $highRiskAlerts = array_filter($alerts, function($alert) {
                    return isset($alert['risk']) && in_array($alert['risk'], ['High', 'Medium']);
                });
                
                // Limiter aux 5 alertes les plus critiques
                $limitedAlerts = array_slice($highRiskAlerts, 0, 5);
                
                $relevantData = "";
                foreach ($limitedAlerts as $alert) {
                    $relevantData .= "- " . ($alert['name'] ?? 'Alerte inconnue') . " (Risque: " . ($alert['risk'] ?? 'Non spécifié') . ")\n";
                    $relevantData .= "  Description: " . substr(($alert['description'] ?? 'Aucune description'), 0, 100) . "...\n";
                    $relevantData .= "  Solution: " . substr(($alert['solution'] ?? 'Aucune solution fournie'), 0, 100) . "...\n\n";
                }
                
                return $relevantData ?: "Aucune alerte de sécurité critique ou moyenne détectée.";
            }
        } catch (\Exception $e) {
            Log::warning("Erreur lors de l'extraction des données ZAP: " . $e->getMessage());
        }
        
        return $rawOutput;
    }
    
    /**
     * Effectue l'appel à l'API Gemini
     */
    private function callGeminiAPI($prompt)
    {
        // Configurer votre clé API Gemini (à stocker dans .env)
        $apiKey = config('services.gemini.api_key');
        $apiUrl = config('services.gemini.api_url', 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent');
        
        // Vérifier que l'API key est configurée
        if (empty($apiKey)) {
            Log::warning('Gemini API key is not configured');
            return "L'analyse automatique n'a pas pu être générée car la clé API n'est pas configurée.";
        }
        
        try {
            // Construire le corps de la requête selon la documentation de l'API Gemini
            $requestBody = [
                'contents' => [
                    [
                        'parts' => [
                            ['text' => $prompt]
                        ]
                    ]
                ],
                'generationConfig' => [
                    'temperature' => 0.2,     // Température basse pour des réponses plus concises
                    'maxOutputTokens' => 800  // Limite la longueur de la réponse
                ]
            ];
            
            // Appeler l'API Gemini avec des timeouts et retries
            $response = Http::timeout(30)->retry(3, 1000)->withHeaders([
                'Content-Type' => 'application/json',
            ])->post($apiUrl . '?key=' . $apiKey, $requestBody);
            
            // Vérifier la réponse
            if ($response->successful()) {
                $data = $response->json();
                
                // Extraire le texte du rapport de la réponse
                if (isset($data['candidates'][0]['content']['parts'][0]['text'])) {
                    return $data['candidates'][0]['content']['parts'][0]['text'];
                } else {
                    Log::warning('Unexpected Gemini API response structure: ' . json_encode($data));
                    return "L'analyse automatique n'a pas pu être générée (format de réponse inattendu).";
                }
            } else {
                // Log de l'erreur détaillée
                Log::error('Gemini API error: ' . $response->status() . ' - ' . $response->body());
                
                // Message d'erreur générique pour l'utilisateur
                return "L'analyse automatique n'a pas pu être générée suite à une erreur de l'API externe.";
            }
        } catch (\Exception $e) {
            Log::error("Exception when calling Gemini API: " . $e->getMessage());
            return "L'analyse automatique n'a pas pu être générée suite à une erreur: " . $e->getMessage();
        }
    }
}