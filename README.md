# security_php
Security.php – Classe de gestion de la sécurité web

Description

Security.php est une classe PHP dédiée à la gestion de la sécurité au sein de vos applications web. Elle propose des mécanismes de protection contre :

XSS (Cross-Site Scripting)

CSRF (Cross-Site Request Forgery)

Injection CSS

Sanitization et Validation

Cette classe vise à simplifier l'intégration de bonnes pratiques de sécurité et à réduire les risques d'attaques courantes.

Fonctionnalités

Échappement des sortiesMéthodes pour échapper automatiquement les données destinées à l'affichage HTML, JavaScript et CSS.

Protection CSRFGénération et validation de tokens CSRF pour sécuriser les formulaires.

Filtrage XSSNettoyage des entrées utilisateur afin d'éliminer les scripts malveillants.

Validation des donnéesVérification des formats (email, URL, nombres, etc.) et filtrage des caractères indésirables.

Gestion des en-têtes de sécuritéAjout automatique des headers HTTP recommandés (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, etc.).

Installation

Téléchargez ou clonez ce dépôt dans votre projet :

git clone https://github.com/votre-utilisateur/votre-repo.git

Incluez la classe dans votre code :

require_once __DIR__ . '/path/to/Security.php';
use VotreNamespace\Security;

Utilisation

use VotreNamespace\Security;

// Instanciation
$sec = new Security();

// Échappement d’une chaîne pour affichage HTML
$safeHtml = $sec->escapeHtml($userInput);

// Génération d’un token CSRF
$token = $sec->generateCsrfToken();

// Validation du token CSRF lors de la soumission
if (!$sec->validateCsrfToken($_POST['csrf_token'])) {
    die('Requête invalide (CSRF).');
}

// Ajout des en-têtes de sécurité
$sec->applySecurityHeaders();

Configuration

La classe peut être configurée via un tableau associatif :

$config = [
    'csrf_token_lifetime' => 3600,   // Durée de vie du token CSRF en secondes
    'content_security_policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'",
    // ... autres options
];

$sec = new Security($config);

Tests

Des tests unitaires sont fournis via PHPUnit :

composer install --dev
vendor/bin/phpunit tests

Contribuer

Les contributions sont les bienvenues ! Merci de :

Forker le dépôt

Créer une branche (git checkout -b feature/ma-fonctionnalite)

Commit vos modifications (git commit -am 'Ajout d'une fonctionnalité')

Pousser sur la branche (git push origin feature/ma-fonctionnalite)

Ouvrir une Pull Request

Auteur

Nenad PETROVIC
