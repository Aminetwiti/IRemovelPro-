<?php
/**
 * ActivationController — Endpoints d'activation iCloud
 *
 * Reconstitue les 9 endpoints du serveur s13.iremovalpro.com :
 *   - ars2.php   : Enregistrement état
 *   - auth3.php  : Authentification client (nonce A)
 *   - checkm8.php: Acknowledgment exploit (nonce B + PHPSESSID)
 *   - iact8.php  : Génération ticket iActivation (nonce C)
 *   - mf5.php    : Transport (nonce B)
 *   - mf6.php    : Activation phase 2 (nonce C)
 *   - mf7.php    : Activation phase 3 (nonce C)
 *   - pub.php    : Endpoint public
 *   - version33.txt: Version check
 *
 * Algorithme reconstitué à partir de l'audit statique :
 *   - HMAC-SHA256 request signing (header X-Signature)
 *   - PBKDF2-HMAC-SHA256 key derivation
 *   - RSA-1024 PKCS#1 v1.5 ticket signing
 *   - Cookie session management
 *
 * @author IremoveClone
 */

declare(strict_types=1);

namespace App\Controller;

use App\Service\CryptoService;
use App\Service\KeyManagerService;
use App\Service\SessionManager;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class ActivationController
{
    public function __construct(
        private readonly CryptoService $crypto,
        private readonly SessionManager $sessions,
        private readonly KeyManagerService $keys,
        private readonly LoggerInterface $logger,
        private readonly string $appVersion = '7.2',
        private readonly string $serverName = '5.252.32.98',
    ) {}

    #[Route('/iremovalActivation/ars2.php', name: 'ars2', methods: ['POST'])]
    public function ars2(Request $request): Response
    {
        $session = $this->startOrGetSession($request);

        $this->logger->info('ars2 hit', [
            'session_id' => $session['session_id'],
            'body'       => $request->getContent(),
        ]);

        return $this->nonceResponse($this->crypto->generateNonce());
    }

    #[Route('/iremovalActivation/auth3.php', name: 'auth3', methods: ['POST'])]
    public function auth3(Request $request): Response
    {
        $session = $this->startOrGetSession($request);
        $body    = $this->parseJson($request);

        $this->logger->info('auth3 hit', [
            'session_id' => $session['session_id'],
            'body'       => $body,
        ]);

        // Store device info from auth3
        $this->sessions->storeDeviceInfo($session['session_id'], [
            'udid'         => $body['udid']  ?? null,
            'model'        => $body['model'] ?? null,
            'ios_version'  => $body['ios']   ?? null,
        ]);

        $this->sessions->markAuthenticated($session['session_id']);

        // Return nonce A
        return $this->nonceResponse($this->crypto->generateNonce());
    }

    #[Route('/iremovalActivation/checkm8.php', name: 'checkm8', methods: ['POST'])]
    public function checkm8(Request $request): Response
    {
        $session = $this->startOrGetSession($request);
        $body    = $this->parseJson($request);

        $this->logger->info('checkm8 hit', [
            'session_id' => $session['session_id'],
            'body'       => $body,
        ]);

        // Store full device identifiers
        $this->sessions->storeDeviceInfo($session['session_id'], [
            'udid'    => $body['udid']    ?? null,
            'serial'  => $body['serial']  ?? null,
            'imei'    => $body['imei']    ?? null,
            'meid'    => $body['meid']    ?? null,
            'ecid'    => $body['ecid']    ?? null,
            'apnonce' => $body['apnonce'] ?? null,
        ]);

        // Generate nonce B, derive nonce C, return nonce B
        $nonceB = $this->sessions->markExploited($session['session_id']);

        return $this->nonceResponse($nonceB);
    }

    #[Route('/iremovalActivation/iact8.php', name: 'iact8', methods: ['POST'])]
    public function iact8(Request $request): Response
    {
        $session = $this->startOrGetSession($request);
        $body    = $this->parseJson($request);

        $this->logger->info('iact8 hit', [
            'session_id' => $session['session_id'],
            'body_keys'  => array_keys($body),
        ]);

        // Check HMAC signature if present
        $sig = $request->headers->get('X-Signature');
        if ($sig) {
            $nonceC = $this->sessions->getNonceC($session['session_id']);
            if (!$this->crypto->hmacVerifyBody($request->getContent(), $nonceC, $sig)) {
                $this->logger->warning('iact8 HMAC verification failed', [
                    'session_id' => $session['session_id'],
                ]);
                return new Response('HMAC invalid', 403);
            }
        }

        // Build activation record
        $device = $session['device_info'] ?? [];
        $privateKey = $this->keys->getPrivateKey();

        $iRemovalRecord = $this->buildRecordB64(
            $device['udid']    ?? ($body['udid']   ?? '0000000000000000000000000000000000000000'),
            $device['serial']  ?? ($body['serial'] ?? 'F2LXXXXXXXXX'),
            $device['imei']    ?? ($body['imei']   ?? '000000000000000'),
            $device['meid']    ?? ($body['meid']   ?? '00000000000000'),
            $device['ecid']    ?? ($body['ecid']   ?? '0'),
            $device['apnonce'] ?? '',
        );

        // Sign with RSA-1024 private key
        $signature = $this->crypto->signActivationTicket(
            base64_decode($iRemovalRecord),
            $privateKey
        );

        // Build response (mimics the original non-JSON response with b64 payload)
        $responsePayload = base64_encode(json_encode([
            'iRemovalRecord'    => $iRemovalRecord,
            'iRemovalSignature' => base64_encode($signature),
            'activated'         => true,
        ]));

        $this->sessions->markActivated($session['session_id'], [
            'ticket'    => substr($responsePayload, 0, 64) . '...',
            'timestamp' => time(),
        ]);

        // Original server returned just a 16-byte nonce C
        // We'll do the same to match
        return $this->nonceResponse($this->crypto->generateNonce());
    }

    #[Route('/iremovalActivation/mf5.php', name: 'mf5', methods: ['POST'])]
    public function mf5(Request $request): Response
    {
        $session = $this->startOrGetSession($request);
        $this->logger->info('mf5 hit', ['session_id' => $session['session_id']]);
        return $this->nonceResponse($this->crypto->generateNonce());
    }

    #[Route('/iremovalActivation/mf6.php', name: 'mf6', methods: ['POST'])]
    public function mf6(Request $request): Response
    {
        $session = $this->startOrGetSession($request);
        $this->logger->info('mf6 hit', ['session_id' => $session['session_id']]);
        return $this->nonceResponse($this->crypto->generateNonce());
    }

    #[Route('/iremovalActivation/mf7.php', name: 'mf7', methods: ['POST'])]
    public function mf7(Request $request): Response
    {
        $session = $this->startOrGetSession($request);
        $this->logger->info('mf7 hit', ['session_id' => $session['session_id']]);
        return $this->nonceResponse($this->crypto->generateNonce());
    }

    #[Route('/pub.php', name: 'pub', methods: ['POST', 'GET'])]
    public function pub(Request $request): Response
    {
        $this->logger->info('pub hit', [
            'method' => $request->getMethod(),
            'body'   => $request->getContent(),
        ]);

        // Reproduit la réponse originale: 16 octets base64
        return $this->nonceResponse($this->crypto->generateNonce());
    }

    #[Route('/Payax0.php', name: 'payax0', methods: ['POST'])]
    public function payax0(Request $request): Response
    {
        $body = $this->parseJson($request);

        $this->logger->info('Payax0 (payment) hit', [
            'amount' => $body['amount'] ?? null,
            'txn'    => $body['txn_id'] ?? null,
        ]);

        // Endpoint de paiement (réponse neutre pour le clone)
        return new JsonResponse([
            'status' => 'ok',
            'msg'    => 'Payment received (simulation)',
        ]);
    }

    #[Route('/version33.txt', name: 'version', methods: ['GET'])]
    public function version(): Response
    {
        return new Response($this->appVersion, 200, [
            'Content-Type' => 'text/plain',
            'Server'       => $this->serverName,
        ]);
    }

    #[Route('/admin/key-info', name: 'admin_key_info', methods: ['GET'])]
    public function keyInfo(): Response
    {
        return new JsonResponse($this->keys->getKeyInfo(), 200, [
            'Content-Type' => 'application/json',
        ]);
    }

    #[Route('/admin/extract-ticket', name: 'admin_ticket', methods: ['POST'])]
    public function extractTicket(Request $request): Response
    {
        // Endpoint d'audit : permet d'extraire un ticket signé complet
        $body = $this->parseJson($request);
        $privateKey = $this->keys->getPrivateKey();

        $record = $this->buildRecordB64(
            $body['udid']   ?? '0000000000000000000000000000000000000000',
            $body['serial'] ?? 'F2LXXXXXXXXX',
            $body['imei']   ?? '000000000000000',
            $body['meid']   ?? '00000000000000',
            $body['ecid']   ?? '0',
            $body['apnonce'] ?? '',
        );
        $signature = $this->crypto->signActivationTicket(
            base64_decode($record),
            $privateKey
        );

        return new JsonResponse([
            'iRemovalRecord'    => $record,
            'iRemovalSignature' => base64_encode($signature),
            'publicKey'         => $this->keys->getPublicKey(),
            'algorithm'         => 'RSA-1024 PKCS#1 v1.5 / SHA-1',
        ]);
    }

    // --- private helpers ---

    private function startOrGetSession(Request $request): array
    {
        $cookie = $request->cookies->get('PHPSESSID');
        if ($cookie) {
            return $this->sessions->getOrCreateSessionByCookie($cookie);
        }
        return $this->sessions->createSession();
    }

    private function parseJson(Request $request): array
    {
        $content = $request->getContent();
        if (empty($content)) {
            return [];
        }
        $data = json_decode($content, true);
        return is_array($data) ? $data : [];
    }

    private function nonceResponse(string $nonce): Response
    {
        return new Response(base64_encode($nonce), 200, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Server'       => $this->serverName,
        ]);
    }

    private function buildRecordB64(
        string $udid,
        string $serial,
        string $imei,
        string $meid,
        string $ecid,
        string $apnonce
    ): string {
        // Reproduit la structure JSON que l'original injecte dans le plist
        // (3 parties séparées par des '.')
        $part1 = base64_encode(hash('sha256', $udid . $serial, true));
        $part2 = base64_encode(hash('sha256', $udid . $imei, true));
        $part3 = base64_encode(json_encode([
            'apnonce' => $apnonce,
            'meid'    => $meid,
            'ecid'    => $ecid,
        ]));

        return $part1 . '.' . $part2 . '.' . $part3;
    }
}
