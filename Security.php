<?php
class Security
{
    // Caractères interdits par défaut pour certaines fonctions de filtrage.
    // Cette constante rend la configuration plus facile et plus lisible.
    private const DEFAULT_FORBIDDEN_CHARACTERS = ["<", "?", "!", ">", "--", "$", "§"];

    /**
     * Filtre et formate une chaîne de caractères pour un affichage HTML sécurisé.
     * Supprime certains caractères interdits, échappe les entités HTML et met la première lettre en majuscule.
     *
     * @param string $text La chaîne à filtrer.
     * @return string La chaîne formatée et sécurisée pour HTML.
     */
    public static function formatInputText(string $text): string
    {
        // Utilisation de str_replace avec un tableau pour de meilleures performances
        // et une syntaxe plus concise par rapport à une boucle foreach.
        $text = str_replace(self::DEFAULT_FORBIDDEN_CHARACTERS, "", $text);
        
        // Utilisation de htmlspecialchars en premier pour échapper toutes les entités HTML,
        // puis ucfirst pour la première lettre en majuscule.
        // L'ordre est important pour éviter que ucfirst n'affecte des entités déjà échappées.
        $text = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
        $text = ucfirst($text);
        
        return $text;
    }

    /**
     * Affiche des données en les nettoyant de toute balise HTML et en échappant les caractères spéciaux HTML.
     *
     * @param string $data Les données à afficher.
     * @return string Les données nettoyées et sécurisées pour l'affichage HTML.
     */
    public static function displaySanitizedData(string $data): string
    {
        // Supprime toutes les balises HTML.
        $txt = strip_tags($data);
        // Échappe les caractères spéciaux HTML pour prévenir les attaques XSS.
        $text = htmlspecialchars($txt, ENT_QUOTES, 'UTF-8');
        return $text;
    }

    /**
     * Supprime tous les espaces (simples, multiples, tabulations, retours à la ligne) d'une chaîne.
     *
     * @param string $text La chaîne dont il faut supprimer les espaces.
     * @return string La chaîne sans espaces.
     */
    public static function removeSpaces(string $text): string
    {
        // Rendre la méthode statique car elle n'utilise aucune propriété d'instance.
        // Utilisation de preg_replace pour une suppression efficace de tous types d'espaces.
        return preg_replace('/\s+/', '', $text);
    }

    /**
     * Génère un jeton aléatoire alphanumérique d'une longueur spécifiée.
     * Utilise random_int pour une meilleure cryptographie que mt_rand.
     *
     * @param int $length La longueur souhaitée du jeton.
     * @return string Le jeton alphanumérique généré.
     */
    public static function generateRandomAlphaNumericToken(int $length): string
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $randomString = '';
        $maxIndex = strlen($characters) - 1;

        for ($i = 0; $i < $length; $i++) {
            // random_int est cryptographiquement plus sécurisé que mt_rand.
            $randomIndex = random_int(0, $maxIndex);
            $randomString .= $characters[$randomIndex];
        }

        return $randomString;
    }

    /**
     * Génère un jeton CSRF cryptographiquement sécurisé.
     *
     * @return string Le jeton CSRF généré.
     */
    public static function generateCSRFToken(): string
    {
        // Utilisation de random_bytes et bin2hex pour un jeton robuste.
        return bin2hex(random_bytes(32));
    }

    /**
     * Démarre la session et vérifie l'état de la connexion utilisateur et la présence du jeton CSRF en session.
     * Redirige l'utilisateur vers la page de déconnexion si les vérifications échouent.
     *
     * @return void
     */
    public static function startSecurePage(): void
    {
       
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if (!isset($_SESSION['user']['id'])) {
                header('Location: ' . RACINE_SITE . 'vues/app/login.php');
            exit();
        }

        // Le jeton CSRF devrait être généré et stocké en session avant d'arriver ici,
        // idéalement au moment de la première connexion ou du chargement de la page.
        // Cette vérification s'assure qu'il est présent.
        if (!isset($_SESSION['csrf_token']) || empty($_SESSION['csrf_token'])) {
            header('Location: ' . RACINE_SITE . 'vues/app/login.php');
            exit();
        }
        // Note: La validation du jeton envoyé par le client se fait avec verifyCSRFToken.
        // Il est recommandé de stocker le token CSRF sous une clé plus générique comme 'csrf_token'
        // au lieu de 'securite']['csrfToken'] pour une meilleure cohérence.
    }

    /**
     * Formate une chaîne de recherche en majuscules et supprime les espaces, virgules et points.
     *
     * @param string $input La chaîne de recherche à formater.
     * @return string La chaîne de recherche formatée.
     */
    public static function formatSearchInput(string $input): string
    {
        // Applique le nettoyage XSS avant toute autre manipulation.
        $sanitizedInput = self::sanitizeInput($input);
        // Convertit en majuscules.
        $upperInput = strtoupper($sanitizedInput);
        // Supprime les espaces, virgules et points.
        $formattedInput = preg_replace('/[ ,.]/', '', $upperInput);
        return $formattedInput;
    }

    /**
     * Valide une adresse email en utilisant filter_var avec FILTER_VALIDATE_EMAIL.
     * C'est la méthode recommandée en PHP pour la validation d'email car elle gère de nombreux cas.
     *
     * @param string $email L'adresse email à valider.
     * @return bool True si l'email est valide, sinon false.
     */
    public static function validateEmail(string $email): bool
    {
        // filter_var est la méthode préférée pour la validation d'emails en PHP.
        // Elle est plus robuste que la plupart des expressions régulières simples.
        $isValid = filter_var($email, FILTER_VALIDATE_EMAIL);

        if ($isValid === false) {
            // Ne pas afficher de message directement dans une fonction de validation.
            // Laisser l'appelant gérer l'affichage des erreurs.
            // echo 'Format email non valide'; // Supprimé
        }
        return (bool) $isValid;
    }

    /**
 * Valide une adresse e-mail sans dépendances externes.
 * 
 * @param string $email    L'adresse e-mail à valider.
 * @param bool   $checkDNS Si true, vérifie l'existence d'un enregistrement MX ou A pour le domaine.
 * @return bool Vrai si l'e-mail passe tous les contrôles, faux sinon.
 */
public static function isEmail(string $email, bool $checkDNS = false): bool
{
    // 1. Vidage et nettoyage
    $email = trim($email);
    if ($email === '') {
        return false;
    }

    // 2. Explosion locale / domaine
    if (substr_count($email, '@') !== 1) {
        return false;
    }
    list($local, $domain) = explode('@', $email, 2);

    // 3. Longueur
    if (strlen($local) > 64 || strlen($domain) > 255 || strlen($email) > 254) {
        return false;
    }

    // 4. Gestion des IDN (domaines accentués)
    //    Utilise la bibliothèque intl (PHP ≥ 5.3.0)
    if (function_exists('idn_to_ascii')) {
        $asciiDomain = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($asciiDomain === false) {
            return false;
        }
        $domain = $asciiDomain;
    }

    // 5. Vérification basique de structure RFC via filter_var
    //    Note : on ne met pas strtolower() sur $local (RFC sensible à la casse)
    $normalized = $local . '@' . strtolower($domain);
    if (!filter_var($normalized, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    // 6. Regex combinée pour :
    //    - pas de point initial/final ou consécutif dans le local
    //    - aucun caractère interdit
    //    - domaine avec au moins un point
    $pattern = '/^(?:"[^"]+"|[a-zA-Z0-9!#$%&\'*+\/=?^_`{|}~.-]+)'
             . '@'
             . '(?=.{1,255}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
             . '(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/D';
    if (!preg_match($pattern, $normalized)) {
        return false;
    }

    // 7. (Optionnel) Vérification DNS
    if ($checkDNS) {
        // On accepte MX ou, à défaut, A
        if (!checkdnsrr($domain, 'MX') && !checkdnsrr($domain, 'A')) {
            return false;
        }
    }

    // Tous les contrôles sont passés
    return true;
}


    /**
     * Vérifie si un jeton CSRF est valide.
     * Utilise hash_equals pour une comparaison sécurisée contre les attaques de temporisation.
     *
     * @param string $submittedToken Le jeton CSRF soumis par le client.
     * @return bool True si le jeton est valide, sinon false.
     */
    public static function verifyCSRFToken(string $submittedToken): bool
    {
        // Assurez-vous que 'csrf_token' est la clé utilisée pour stocker le token en session.
        // Il est important de régénérer le token en session après chaque vérification réussie
        // pour prévenir les attaques "double submit".
        if (isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $submittedToken)) {
            // Optionnel : Régénérer le token après une utilisation réussie pour une sécurité accrue.
            // $_SESSION['csrf_token'] = self::generateCSRFToken();
            return true;
        }
        return false;
    }

    /**
     * Échappe les données pour prévenir les attaques XSS.
     *
     * @param string $data Les données à échapper.
     * @return string Les données échappées.
     */
    public static function sanitizeInput(string $data): string
    {
        // ENT_QUOTES convertit les guillemets simples et doubles.
        // 'UTF-8' est l'encodage recommandé.
        return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Valide une URL pour prévenir les attaques XSS et s'assurer de sa conformité.
     *
     * @param string $url L'URL à valider.
     * @return string|false L'URL validée ou false si elle est invalide.
     */
    public static function validateURL(string $url)
    {
        // filter_var avec FILTER_VALIDATE_URL est la méthode standard et recommandée.
        return filter_var($url, FILTER_VALIDATE_URL);
    }

    /**
     * Valide une chaîne de caractères pour vérifier l'absence de caractères potentiellement dangereux.
     *
     * @param string $string La chaîne à valider.
     * @return bool True si la chaîne ne contient pas de caractères interdits, sinon false.
     */
    public static function isValidInput(string $string): bool
    {
        // Utilise la constante pour la liste des caractères interdits.
        // str_contains est plus moderne et potentiellement plus performante que strpos pour vérifier la présence.
        foreach (self::DEFAULT_FORBIDDEN_CHARACTERS as $char) {
            if (str_contains($string, $char)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Échappe les données pour prévenir les injections SQL.
     * Cette méthode est un exemple. La meilleure pratique est d'utiliser les requêtes préparées de PDO.
     *
     * @param PDO $pdo L'objet PDO pour interagir avec la base de données.
     * @param mixed $data Les données à échapper (peut être une chaîne ou un tableau).
     * @return mixed Les données échappées.
     */
    public static function sanitizeSQL(PDO $pdo, $data)
    {
        if (is_array($data)) {
            return array_map(fn($item) => self::sanitizeSQL($pdo, $item), $data);
        }
        // Pour les chaînes, PDO::quote est utilisé. Pour d'autres types, cela ne fera rien.
        // Important: Cette méthode est à utiliser en dernier recours.
        // Les requêtes préparées avec des paramètres liés sont toujours la méthode préférée.
        return $pdo->quote($data);
    }

    /**
     * Échappe les caractères spéciaux pour prévenir les attaques CSS.
     * Cette méthode supprime des caractères et des extensions de fichier potentiellement dangereux.
     *
     * @param string $value La valeur à échapper.
     * @return string La valeur échappée.
     */
    public static function escapeCSS(string $value): string
    {
        // Suppression des caractères de contrôle et extensions de fichier courantes.
        // Note: Pour du CSS inline, utiliser des fonctions d'échappement spécifiques au contexte CSS
        // peut être plus robuste. Ceci est une approche plus générique.
        $value = str_replace(["\n", "\r", "\t", '"', "'", '\\', '<', '>', '.php', '.txt', '.js', '.sql'], '', $value);

        if (is_numeric($value)) {
            return $value;
        }

        // Entourer la valeur de guillemets simples pour un usage dans des propriétés CSS si ce n'est pas un nombre.
        // Attention à l'injection si la valeur peut contenir des guillemets.
        // Une meilleure approche serait de s'assurer que la valeur est saine pour chaque propriété CSS spécifique.
        return "'" . $value . "'";
    }

    /**
     * Crypte une chaîne de caractères à l'aide d'AES-256-CBC.
     *
     * @param string $data Les données à crypter.
     * @param string $key La clé secrète pour le cryptage.
     * @return string Les données cryptées et encodées en base64 (IV inclus).
     */
    public static function encrypt(string $data, string $key): string
    {
        $ivLength = openssl_cipher_iv_length('aes-256-cbc');
        $iv = openssl_random_pseudo_bytes($ivLength);
        
        $encryptedData = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
        
        // Retourne IV + données cryptées, encodées en base64.
        return base64_encode($iv . $encryptedData);
    }

    /**
     * Décrypte une chaîne de caractères cryptée avec AES-256-CBC.
     *
     * @param string $data Les données cryptées et encodées en base64.
     * @param string $key La clé secrète utilisée pour le cryptage.
     * @return string|false Les données décryptées ou false en cas d'échec.
     */
    public static function decrypt(string $data, string $key)
    {
        $decodedData = base64_decode($data);
        
        $ivLength = openssl_cipher_iv_length('aes-256-cbc');
        $iv = substr($decodedData, 0, $ivLength);
        $encryptedData = substr($decodedData, $ivLength);
        
        return openssl_decrypt($encryptedData, 'aes-256-cbc', $key, 0, $iv);
    }

    /**
     * Crypte une chaîne de caractères pour être utilisée dans une URL.
     *
     * @param string $data Les données à crypter.
     * @param string $secret_key La clé secrète.
     * @param string $secret_iv La clé IV secrète.
     * @return string Les données cryptées, encodées en base64 et url-encodées.
     */
    public static function encryptForUrl(string $data, string $secret_key, string $secret_iv): string
    {
        $encryptMethod = "AES-256-CBC";
        $key = hash('sha256', $secret_key);
        $iv = substr(hash('sha256', $secret_iv), 0, 16);
        
        $encryptedData = openssl_encrypt($data, $encryptMethod, $key, 0, $iv);
        return urlencode(base64_encode($encryptedData));
    }

    /**
     * Décrypte une chaîne de caractères provenant d'une URL.
     *
     * @param string $data Les données cryptées, url-encodées et encodées en base64.
     * @param string $secret_key La clé secrète.
     * @param string $secret_iv La clé IV secrète.
     * @return string|false Les données décryptées ou false en cas d'échec.
     */
    public static function decryptFromUrl(string $data, string $secret_key, string $secret_iv)
    {
        $encryptMethod = "AES-256-CBC";
        $key = hash('sha256', $secret_key);
        $iv = substr(hash('sha256', $secret_iv), 0, 16);
        
        $decryptedData = openssl_decrypt(base64_decode(urldecode($data)), $encryptMethod, $key, 0, $iv);
        return $decryptedData;
    }
}
