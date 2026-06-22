<?php
/**
 * SessionManager — Gestionnaire de sessions bypass iCloud
 *
 * Reproduit la machine à états du serveur d'origine :
 *
 *   ┌─────────┐  auth3.php   ┌─────────────┐  checkm8.php  ┌────────────┐
 *   │ CREATED ├─────────────►│  AUTHENTICATED├─────────────►│ EXPLOITED  │
 *   └─────────┘              └─────────────┘              └─────┬──────┘
 *                                                                │ iact8.php
 *                                                                ▼
 *                                                          ┌─────────────┐
 *                                                          │  ACTIVATED  │
 *                                                          └─────────────┘
 *
 * @author IremoveClone
 */

declare(strict_types=1);

namespace App\Service;

use Psr\Log\LoggerInterface;

final class SessionManager
{
    public const STATE_CREATED       = 'CREATED';
    public const STATE_AUTHENTICATED = 'AUTHENTICATED';
    public const STATE_EXPLOITED     = 'EXPLOITED';
    public const STATE_ACTIVATED     = 'ACTIVATED';
    public const STATE_FAILED        = 'FAILED';

    public function __construct(
        private readonly CryptoService $crypto,
        private readonly LoggerInterface $logger,
        private readonly string $storageDir = '/tmp/iremovalclone-sessions'
    ) {
        if (!is_dir($this->storageDir)) {
            @mkdir($this->storageDir, 0700, true);
        }
    }

    /**
     * Crée une nouvelle session, retourne sessionId + nonceA.
     */
    public function createSession(): array
    {
        $sessionId = bin2hex(random_bytes(16));
        $nonceA = $this->crypto->generateNonce();

        $session = [
            'session_id'  => $sessionId,
            'state'       => self::STATE_CREATED,
            'nonce_a'     => base64_encode($nonceA),
            'nonce_b'     => null,
            'nonce_c'     => null,
            'created_at'  => time(),
            'updated_at'  => time(),
            'device_info' => [],
        ];

        $this->save($session);
        $this->logger->info('Session created', ['session_id' => $sessionId]);

        return $session;
    }

    public function getSession(string $sessionId): ?array
    {
        $path = $this->getPath($sessionId);
        if (!file_exists($path)) {
            return null;
        }
        $data = @file_get_contents($path);
        return $data ? json_decode($data, true) : null;
    }

    public function markAuthenticated(string $sessionId): void
    {
        $session = $this->getSession($sessionId);
        if (!$session) {
            throw new \RuntimeException("Session not found: $sessionId");
        }
        $session['state']      = self::STATE_AUTHENTICATED;
        $session['updated_at'] = time();
        $this->save($session);
        $this->logger->info('Session authenticated', ['session_id' => $sessionId]);
    }

    public function storeDeviceInfo(string $sessionId, array $deviceInfo): void
    {
        $session = $this->getSession($sessionId);
        if (!$session) {
            throw new \RuntimeException("Session not found: $sessionId");
        }
        $session['device_info'] = array_merge($session['device_info'] ?? [], $deviceInfo);
        $this->save($session);
    }

    public function getOrCreateSessionByCookie(string $cookieValue): array
    {
        $sessionId = $this->extractSessionId($cookieValue);
        $session = $this->getSession($sessionId);
        if (!$session) {
            // Create new if not found (matches original server behavior)
            $session = $this->createSession();
        }
        return $session;
    }

    private function extractSessionId(string $cookie): string
    {
        // Parse "PHPSESSID=xxx" or just "xxx"
        if (strpos($cookie, '=') !== false) {
            [, $value] = explode('=', $cookie, 2);
            return $value;
        }
        return $cookie;
    }

    /**
     * Marque la session comme "exploitée" et stocke nonceB.
     * Déclenche la dérivation de nonceC si nonceA est présent.
     */
    public function markExploited(string $sessionId): string
    {
        $session = $this->getSession($sessionId);
        if (!$session) {
            throw new \RuntimeException("Session not found: $sessionId");
        }
        if ($session['state'] !== self::STATE_AUTHENTICATED) {
            throw new \RuntimeException("Invalid state transition: $session[state] -> EXPLOITED");
        }

        $nonceB = $this->crypto->generateNonce();
        $session['nonce_b'] = base64_encode($nonceB);
        $session['state']   = self::STATE_EXPLOITED;
        $session['updated_at'] = time();

        // Pre-derive nonceC (PBKDF2 is slow — do it now to amortize)
        $nonceC = $this->crypto->deriveSessionKey(
            $session['session_id'],
            base64_decode($session['nonce_a']),
            $nonceB
        );
        $session['nonce_c'] = base64_encode($nonceC);

        $this->save($session);
        $this->logger->info('Session exploited, nonceC derived', [
            'session_id' => $sessionId,
            'nonce_c'    => $session['nonce_c'],
        ]);

        return $nonceC;
    }

    /**
     * Récupère nonceC pour la signature des requêtes iact8/mf6/mf7.
     */
    public function getNonceC(string $sessionId): string
    {
        $session = $this->getSession($sessionId);
        if (!$session || !$session['nonce_c']) {
            throw new \RuntimeException("Session $sessionId has no nonceC");
        }
        return base64_decode($session['nonce_c']);
    }

    public function markActivated(string $sessionId, array $result): void
    {
        $session = $this->getSession($sessionId);
        if (!$session) {
            throw new \RuntimeException("Session not found: $sessionId");
        }
        $session['state']      = self::STATE_ACTIVATED;
        $session['updated_at'] = time();
        $session['result']     = $result;
        $this->save($session);
        $this->logger->info('Session activated', ['session_id' => $sessionId]);
    }

    private function save(array $session): void
    {
        $path = $this->getPath($session['session_id']);
        file_put_contents($path, json_encode($session, JSON_PRETTY_PRINT), LOCK_EX);
    }

    private function getPath(string $sessionId): string
    {
        return $this->storageDir . '/' . preg_replace('/[^a-f0-9]/', '', $sessionId) . '.json';
    }
}
