<?php
/**
 * iact8.php — Reconstruction de l'endpoint iact8.php du serveur s13.iremovalpro.com
 *
 * VERSION STANDALONE — pas besoin de Symfony.
 * Reproduit le comportement observé par probe réseau :
 *   - Réponse 200 OK
 *   - Content-Type: text/html; charset=UTF-8
 *   - Body: 24 caractères base64 (= 16 octets random = nonce C)
 *   - Server: 5.252.32.98
 *
 * Mode d'emploi :
 *   php -S 127.0.0.1:8080 router.php
 *   curl -X POST http://127.0.0.1:8080/iremovalActivation/iact8.php \
 *        -d '{"udid":"...","serial":"..."}'
 *
 * @author IremoveClone
 */

declare(strict_types=1);

require __DIR__ . '/lib/CryptoService.php';
require __DIR__ . '/lib/SessionManager.php';
require __DIR__ . '/lib/KeyManager.php';
require __DIR__ . '/lib/PlistBuilder.php';

use App\Clone\CryptoService;
use App\Clone\SessionManager;
use App\Clone\KeyManager;
use App\Clone\PlistBuilder;

// --- Bootstrap ---
$crypto   = new CryptoService();
$keys     = new KeyManager(__DIR__ . '/var/keys');
$sessions = new SessionManager(__DIR__ . '/var/sessions');
$plist    = new PlistBuilder();

session_start();

// --- Routing (très simple) ---
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// --- Logging ---
function log_hit(string $endpoint, array $ctx = []): void {
    $logFile = __DIR__ . '/var/iremo-server.log';
    $line = sprintf("[%s] %s %s %s\n",
        date('Y-m-d H:i:s'),
        $_SERVER['REQUEST_METHOD'] ?? '?',
        $endpoint,
        json_encode($ctx, JSON_UNESCAPED_SLASHES)
    );
    @file_put_contents($logFile, $line, FILE_APPEND);
}

// --- 9 Endpoints ---

if (str_ends_with($path, '/version33.txt')) {
    // GET /version33.txt
    header('Content-Type: text/plain');
    header('Server: 5.252.32.98');
    echo "7.2";
    log_hit('version33');
    exit;
}

if (str_ends_with($path, '/Payax0.php')) {
    // POST /Payax0.php (paiement)
    header('Content-Type: application/json');
    $body = json_decode(file_get_contents('php://input') ?: '{}', true) ?: [];
    log_hit('Payax0', $body);
    echo json_encode(['status' => 'ok', 'msg' => 'payment received']);
    exit;
}

if (str_ends_with($path, '/pub.php')) {
    // POST/GET /pub.php — endpoint public
    header('Content-Type: text/html; charset=UTF-8');
    header('Server: 5.252.32.98');
    $body = json_decode(file_get_contents('php://input') ?: '{}', true) ?: [];
    log_hit('pub', $body);
    echo base64_encode($crypto->generateNonce());
    exit;
}

if (preg_match('#/iremovalActivation/(\w+\.php)$#', $path, $m)) {
    $endpoint = $m[1];
    $body = json_decode(file_get_contents('php://input') ?: '{}', true) ?: [];

    // Get or create session
    $sessionId = $_COOKIE['PHPSESSID'] ?? null;
    if ($sessionId) {
        $session = $sessions->get($sessionId) ?? $sessions->create();
    } else {
        $session = $sessions->create();
    }
    setcookie('PHPSESSID', $session['id'], 0, '/', '', false, true);

    // Dispatch per endpoint
    switch ($endpoint) {
        case 'ars2.php':
            // Register state
            $sessions->update($session['id'], ['last_endpoint' => 'ars2']);
            log_hit('ars2', $body);
            break;

        case 'auth3.php':
            // Auth + nonce A
            $sessions->update($session['id'], [
                'state'        => 'AUTHENTICATED',
                'udid'         => $body['udid']         ?? null,
                'model'        => $body['model']        ?? null,
                'ios_version'  => $body['ios']          ?? null,
                'nonce_a'      => base64_encode($crypto->generateNonce()),
            ]);
            log_hit('auth3', $body);
            break;

        case 'checkm8.php':
            // Exploit ack + nonce B + derive nonce C
            $sessionData = $sessions->get($session['id']);
            $nonceB = $crypto->generateNonce();
            $nonceC = $crypto->deriveSessionKey(
                $session['id'],
                base64_decode($sessionData['nonce_a']),
                $nonceB
            );
            $sessions->update($session['id'], [
                'state'   => 'EXPLOITED',
                'nonce_b' => base64_encode($nonceB),
                'nonce_c' => base64_encode($nonceC),
                'serial'  => $body['serial'] ?? null,
                'imei'    => $body['imei']   ?? null,
                'meid'    => $body['meid']   ?? null,
                'ecid'    => $body['ecid']   ?? null,
                'apnonce' => $body['apnonce'] ?? null,
            ]);
            log_hit('checkm8', $body);
            break;

        case 'iact8.php':
            // ** THE CORE: generate forged activation ticket **
            $sessionData = $sessions->get($session['id']);
            if (($sessionData['state'] ?? '') !== 'EXPLOITED') {
                http_response_code(400);
                echo "Session not in EXPLOITED state";
                exit;
            }

            // Build the activation record
            $record = $plist->buildActivationRecord(
                $sessionData['udid']    ?? ($body['udid']   ?? '0000000000000000000000000000000000000000'),
                $sessionData['serial']  ?? ($body['serial'] ?? 'F2LXXXXXXXXX'),
                $sessionData['imei']    ?? ($body['imei']   ?? '000000000000000'),
                $sessionData['meid']    ?? ($body['meid']   ?? '00000000000000'),
                $sessionData['ecid']    ?? ($body['ecid']   ?? '0'),
                $sessionData['ios_version'] ?? '15.0',
                $sessionData['model']   ?? 'iPhone14,2',
                '0000000000000000000000000000000000000000',  // MLB
                '00000',  // ChipID
                $sessionData['apnonce'] ?? '',
            );

            // Sign with RSA-1024
            $signature = $crypto->signActivationTicket(
                $record,
                $keys->getPrivateKey()
            );

            // Save the ticket for the iOS side to fetch
            $ticket = [
                'iRemovalRecord'    => base64_encode($record),
                'iRemovalSignature' => base64_encode($signature),
                'publicKey'         => $keys->getPublicKey(),
                'algorithm'         => 'RSA-1024 PKCS#1 v1.5 / SHA-1',
            ];
            $sessions->update($session['id'], [
                'state'  => 'ACTIVATED',
                'ticket' => $ticket,
            ]);

            // Optional: also save to disk for later retrieval
            $ticketDir = __DIR__ . '/var/tickets';
            if (!is_dir($ticketDir)) mkdir($ticketDir, 0700, true);
            file_put_contents(
                $ticketDir . '/' . $session['id'] . '.json',
                json_encode($ticket, JSON_PRETTY_PRINT)
            );

            log_hit('iact8', [
                'udid'    => $sessionData['udid'] ?? null,
                'sig_len' => strlen($signature),
            ]);
            break;

        case 'mf5.php':
            // Transport (nonce B reused)
            $sessions->update($session['id'], ['last_endpoint' => 'mf5']);
            log_hit('mf5', $body);
            break;

        case 'mf6.php':
            // Activation phase 2
            $sessions->update($session['id'], ['state' => 'MF6_HIT']);
            log_hit('mf6', $body);
            break;

        case 'mf7.php':
            // Activation phase 3
            $sessions->update($session['id'], ['state' => 'MF7_HIT']);
            log_hit('mf7', $body);
            break;

        default:
            http_response_code(404);
            echo "Unknown endpoint: $endpoint";
            exit;
    }

    // Generate fresh nonce for response (matches original 16-byte response)
    $nonce = $crypto->generateNonce();
    header('Content-Type: text/html; charset=UTF-8');
    header('Server: 5.252.32.98');
    echo base64_encode($nonce);
    exit;
}

// Root
header('Content-Type: text/plain');
echo "iRemovalClone standalone server\nEndpoints:\n";
echo "  GET  /version33.txt\n";
echo "  POST /iremovalActivation/{ars2,auth3,checkm8,iact8,mf5,mf6,mf7}.php\n";
echo "  POST /pub.php\n";
echo "  POST /Payax0.php\n";
echo "  GET  /tickets/{sessionId}.json  — fetch generated ticket\n";
