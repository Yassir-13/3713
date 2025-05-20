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
    
    // Augmenter considérablement le timeout du job
    public $timeout = 1800; // 30 minutes pour les cas extrêmes
    
    // Ajouter les propriétés pour la gestion des reprises
    public $tries = 2;
    public $backoff = 60; // 1 minute entre les essais

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

        // Vérifier si c'est une reprise après échec
        $isRetry = $scan->status === 'failed' || $scan->status === 'timeout';
        
        // Message pour les reprises
        if ($isRetry) {
            Log::info("Reprise du scan précédemment interrompu pour {$this->url}");
        }

        // Mise à jour pour indiquer que le scan a commencé/repris
        $scan->update([
            'status' => 'running',
            // Si c'est une reprise, stocker l'info mais ne pas effacer les erreurs précédentes
            'error' => $isRetry ? ($scan->error . "\n(Tentative de reprise le " . now() . ")") : null
        ]);

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
            $errorMessage = "Erreur lors du scan pour {$this->url}: " . $e->getMessage();
            Log::error($errorMessage);
            
            // Vérifier si c'est une erreur de timeout
            $isTimeout = stripos($e->getMessage(), 'timeout') !== false || 
                         stripos($e->getMessage(), 'timed out') !== false ||
                         $e instanceof \Illuminate\Queue\MaxAttemptsExceededException;
            
            $scan->update([
                'status' => $isTimeout ? 'timeout' : 'failed',
                'error' => $errorMessage
            ]);
            
            // Si c'est un timeout, on relance le job avec une exception qui sera attrapée
            // par le système de retry de Laravel
            if ($isTimeout && $this->attempts() < $this->tries) {
                throw $e;
            }
        }
    }

    protected function runZapScan($targetUrl)
{
    $apiKey = env('ZAP_API_KEY', '13373713');
    $apiHost = env('ZAP_API_HOST', 'http://zap:8090');
    
    // Normaliser l'URL si nécessaire
    if (!preg_match('~^https?://~i', $targetUrl)) {
        $targetUrl = 'http://' . $targetUrl;
    }
    
    try {
        // 1. Vérification rapide API + extraction domaine
        $apiCheckUrl = "{$apiHost}/JSON/core/view/version/?apikey={$apiKey}";
        $checkResponse = Http::timeout(5)->get($apiCheckUrl);
        if (!$checkResponse->successful()) {
            throw new \Exception("API ZAP inaccessible");
        }
        
        $urlParts = parse_url($targetUrl);
        $domain = $urlParts['host'];
        $scheme = $urlParts['scheme'] ?? 'http';
        
        // 2. OPTIMISATION: Configurer ZAP avant le scan
        Log::info("Configuration de ZAP pour optimisation");
        
        // Réduire le délai entre les requêtes pour accélérer le scan
        Http::get("{$apiHost}/JSON/spider/action/setOptionMaxParseSizeBytes/?apikey={$apiKey}&Integer=1048576");
        Http::get("{$apiHost}/JSON/ascan/action/setOptionMaxScanDurationInMins/?apikey={$apiKey}&Integer=10");
        
        // Configurer le scanner pour un équilibre vitesse/couverture
        Http::get("{$apiHost}/JSON/ascan/action/setOptionHandleAntiCSRFTokens/?apikey={$apiKey}&Boolean=true");
        Http::get("{$apiHost}/JSON/ascan/action/setOptionHostPerScan/?apikey={$apiKey}&Integer=3");
        Http::get("{$apiHost}/JSON/ascan/action/setOptionThreadPerHost/?apikey={$apiKey}&Integer=5");
        
        // 3. Créer et configurer le contexte (une seule fois, efficacement)
        $contextName = 'ctx_' . substr(md5($domain . time()), 0, 8);
        $createContextUrl = "{$apiHost}/JSON/context/action/newContext/?apikey={$apiKey}&contextName={$contextName}";
        $contextResponse = Http::get($createContextUrl);
        
        if (!$contextResponse->successful()) {
            throw new \Exception("Échec de la création du contexte");
        }
        
        // Extraire le contextId directement depuis la réponse
        $contextId = $contextResponse->json()['contextId'] ?? null;
        if (!$contextId) {
            throw new \Exception("ID de contexte non trouvé");
        }
        
        // 4. Configurer le contexte avec regex efficace
        $regex = $scheme . '://' . $domain . '.*';
        Http::get("{$apiHost}/JSON/context/action/includeInContext/?apikey={$apiKey}&contextName={$contextName}&regex=" . urlencode($regex));
        
        // 5. OPTIMISATION CLEF: Configurer et activer uniquement les scanners essentiels
        // Désactiver tous les scanners puis activer seulement les plus critiques
        Http::get("{$apiHost}/JSON/ascan/action/disableAllScanners/?apikey={$apiKey}&scanPolicyName=");
        
        // Activer uniquement les scanners de haute priorité
        $highPriorityScanners = [40018, 40019, 40012, 40014, 40016, 90019, 90020, 20019, 40003, 40008, 40009];
        foreach ($highPriorityScanners as $scannerId) {
            Http::get("{$apiHost}/JSON/ascan/action/enableScanners/?apikey={$apiKey}&ids={$scannerId}&scanPolicyName=");
        }
        
        // 6. OPTIMISATION: Exécuter le Spider et AJAX Spider simultanément avec l'URL directement
        // Cela évite l'appel à accessUrl et gagne du temps
        Log::info("Démarrage du spider pour: {$targetUrl}");
        $spiderParams = [
            'url' => $targetUrl,
            'maxChildren' => 10,    // Limiter pour ne pas submerger le serveur
            'recurse' => 'true',     
            'contextName' => $contextName,
            'subtreeOnly' => 'true' // Rester dans le même sous-domaine
        ];
        
        $spiderUrl = "{$apiHost}/JSON/spider/action/scan/?apikey={$apiKey}&" . http_build_query($spiderParams);
        $response = Http::get($spiderUrl);
        
        if (!$response->successful()) {
            throw new \Exception("Échec du spider: " . $response->body());
        }
        
        $spiderId = $response->json()['scan'];
        
        // 7. OPTIMISATION: Vérifier la progression avec un algorithme adaptatif
        $startTime = time();
        $progress = 0;
        $waitInterval = 1;
        $maxWait = 8;
        $spiderMaxTime = 120; // 2 minutes max pour le spider
        
        while ($progress < 100) {
            if (time() - $startTime > $spiderMaxTime) {
                Log::warning("Spider timeout après {$spiderMaxTime}s, on continue quand même");
                break;
            }
            
            sleep($waitInterval);
            $waitInterval = min($waitInterval * 1.5, $maxWait); // Augmentation adaptative
            
            $statusResponse = Http::get("{$apiHost}/JSON/spider/view/status/?apikey={$apiKey}&scanId={$spiderId}");
            if ($statusResponse->successful()) {
                $progress = (int)($statusResponse->json()['status'] ?? 0);
                Log::info("Spider: {$progress}%");
            }
        }
        
        // 8. Lancer le scan actif avec paramètres optimisés
        Log::info("Démarrage du scan actif: {$targetUrl}");
        $scanParams = [
            'url' => $targetUrl,
            'contextId' => $contextId,
            'recurse' => 'true',
            'inScopeOnly' => 'true',
            'scanPolicyName' => '', // Policy par défaut (qu'on a ajusté avant)
            'method' => 'GET'
        ];
        
        $scanUrl = "{$apiHost}/JSON/ascan/action/scan/?apikey={$apiKey}&" . http_build_query($scanParams);
        $scanResponse = Http::get($scanUrl);
        
        if (!$scanResponse->successful()) {
            throw new \Exception("Échec du scan: " . $scanResponse->body());
        }
        
        $scanId = $scanResponse->json()['scan'];
        
        // 9. Attente adaptative pour le scan actif
        $startTime = time();
        $progress = 0;
        $waitInterval = 2;
        $scanMaxTime = 420; // 7 minutes maximum (pour rester dans les 10 minutes totales)
        
        while ($progress < 100) {
            if (time() - $startTime > $scanMaxTime) {
                Log::warning("Scan actif timeout après {$scanMaxTime}s, on récupère les résultats disponibles");
                break;
            }
            
            sleep($waitInterval);
            $waitInterval = min($waitInterval * 1.5, 15); // Augmentation adaptative avec plafond plus élevé
            
            $statusResponse = Http::get("{$apiHost}/JSON/ascan/view/status/?apikey={$apiKey}&scanId={$scanId}");
            if ($statusResponse->successful()) {
                $progress = (int)($statusResponse->json()['status'] ?? 0);
                Log::info("Scan actif: {$progress}%");
            }
        }
        
        // 10. Récupérer les résultats filtrés (uniquement high et medium pour optimiser)
        $resultsUrl = "{$apiHost}/JSON/core/view/alerts/?apikey={$apiKey}&baseurl=" . urlencode($targetUrl) . "&riskFilter=high,medium";
        $resultsResponse = Http::get($resultsUrl);
        
        if (!$resultsResponse->successful()) {
            throw new \Exception("Échec récupération résultats: " . $resultsResponse->body());
        }
        
        return json_encode($resultsResponse->json(), JSON_PRETTY_PRINT);
        
    } catch (\Exception $e) {
        Log::error("Exception ZAP: " . $e->getMessage());
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
    $urlData = $scan->url;
    
    // Extraire les données comme avant
    $whatwebData = $this->extractRelevantDataFromWhatWeb($scan->whatweb_output);
    $sslyzeData = $this->extractRelevantDataFromSSLyze($scan->sslyze_output);
    $zapData = $this->extractRelevantDataFromZAP($scan->zap_output);
    
    // Prompt sans mention des outils spécifiques
    $promptContent = <<<EOT
Tu es un expert en cybersécurité chargé de créer un rapport sur la sécurité du site: {$urlData}.

CONSIGNE IMPORTANTE: Tu dois produire un rapport professionnel qui NE MENTIONNE PAS les outils d'analyse utilisés. Présente les résultats comme venant d'une analyse de sécurité globale, sans référence aux méthodes ou logiciels employés.

OBJECTIF: Créer un rapport de sécurité concis, factuel et actionnable qui identifie clairement les risques et propose des solutions concrètes.

DIRECTIVES:
- Concentre-toi uniquement sur les vulnérabilités réelles présentes dans les données
- Priorise les problèmes selon leur gravité (Critique > Élevé > Moyen > Faible)
- Utilise un langage accessible pour les non-spécialistes
- Fournis des recommandations concrètes et applicables
- N'invente aucune vulnérabilité qui n'est pas explicitement mentionnée dans les données

DONNÉES D'ANALYSE (À NE PAS MENTIONNER DANS LE RAPPORT):

### 1. Données sur les technologies utilisées:
{$whatwebData}

### 2. Données sur la configuration TLS/SSL:
{$sslyzeData}

### 3. Données sur les vulnérabilités web:
{$zapData}

FORMAT DU RAPPORT (NE PAS MENTIONNER CES CATÉGORIES EXPLICITEMENT):

1. RÉSUMÉ EXÉCUTIF (2-3 phrases)
   - Niveau de risque global: [Critique/Élevé/Moyen/Faible]
   - Bref aperçu des principales conclusions

2. PRINCIPALES VULNÉRABILITÉS IDENTIFIÉES (maximum 5, par ordre de gravité)
   - Nom: [nom de la vulnérabilité]
   - Gravité: [Critique/Élevé/Moyen/Faible]
   - Impact: [description courte de l'impact potentiel]
   - Remédiation: [solution concise et actionnable]

3. RECOMMANDATIONS PRIORITAIRES
   - [Liste de 3-5 actions concrètes à entreprendre, par ordre de priorité]

4. PROBLÈMES TECHNIQUES DÉTECTÉS
   - [Versions obsolètes ou configurations dangereuses identifiées]

Fournir UNIQUEMENT ce rapport structuré, sans mentionner les outils ni les méthodes d'analyse utilisés.
EOT;
    
    return $promptContent;
}
    
    /**
     * Extrait les informations pertinentes des données WhatWeb
     */
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
    
    // Trouver la fin de la dernière phrase complète avant la limite
    $truncated = substr($text, 0, $length);
    $lastPeriod = strrpos($truncated, '.');
    
    if ($lastPeriod !== false && $lastPeriod > $length * 0.5) {
        return substr($truncated, 0, $lastPeriod + 1) . '...';
    }
    
    // Si pas de phrase complète, couper au dernier espace
    $lastSpace = strrpos($truncated, ' ');
    
    if ($lastSpace !== false) {
        return substr($truncated, 0, $lastSpace) . '...';
    }
    
    // En dernier recours, couper à la longueur exacte
    return $truncated . '...';
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