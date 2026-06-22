<?php
/**
 * router.php — Routeur PHP built-in pour iRemovalClone
 *
 * Usage:
 *   php -S 127.0.0.1:8080 -t standalone router.php
 *
 * Reproduit l'ensemble des 9 endpoints du serveur d'origine.
 */

// Fallback pour le serveur PHP built-in — sert les fichiers statiques
// si demandé (utile pour /tickets/xxxx.json).
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

// Servir un fichier statique s'il existe (var/tickets/...)
if (preg_match('#^/tickets/([a-f0-9]+\.json)$#', $path, $m)) {
    $file = __DIR__ . '/var/' . $m[1];
    if (file_exists($file)) {
        header('Content-Type: application/json');
        readfile($file);
        exit;
    }
    http_response_code(404);
    echo "Ticket not found";
    exit;
}

// Sert les autres fichiers PHP du dossier standalone
$candidate = __DIR__ . $path;
if (str_ends_with($path, '.php') && file_exists($candidate)) {
    require $candidate;
    return;
}

// Sinon, redirige vers la racine
require __DIR__ . '/iact8.php';
