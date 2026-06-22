<?php
/**
 * CryptoService (standalone) — Reconstruction de l'algorithme crypto
 *
 * Reconstruit PBKDF2-HMAC-SHA256 et RSA-1024 PKCS#1 v1.5
 * utilisé par le serveur s13.iremovalpro.com
 *
 * Identique à la version Symfony mais sans dépendance.
 */

declare(strict_types=1);

namespace App\Clone;

final class CryptoService
{
    public const PBKDF2_SALT        = 'iremovalpro-iact8-v1';
    public const PBKDF2_ITERATIONS  = 10000;
    public const PBKDF2_DKLEN       = 16;
    public const NONCE_LENGTH       = 16;
    public const RSA_KEY_BITS       = 1024;

    public function generateNonce(): string
    {
        return random_bytes(self::NONCE_LENGTH);
    }

    public function deriveSessionKey(
        string $sessionId,
        string $nonceA,
        string $nonceB
    ): string {
        $password = sprintf(
            '%s:%s:%s',
            $sessionId,
            base64_encode($nonceA),
            base64_encode($nonceB)
        );

        $derivedKey = hash_pbkdf2(
            'sha256',
            $password,
            self::PBKDF2_SALT,
            self::PBKDF2_ITERATIONS,
            self::PBKDF2_DKLEN,
            true
        );

        if ($derivedKey === false) {
            throw new \RuntimeException('PBKDF2 derivation failed');
        }
        return $derivedKey;
    }

    public function signActivationTicket(
        string $data,
        string $privateKeyPem
    ): string {
        // We use openssl directly — compatible with any PHP 8+ build
        $result = '';
        $ok = openssl_sign(
            $data,
            $result,
            $privateKeyPem,
            OPENSSL_ALGO_SHA1
        );

        if (!$ok) {
            throw new \RuntimeException('RSA signature failed: ' . openssl_error_string());
        }
        return $result;
    }

    public function verifyTicketSignature(
        string $data,
        string $signature,
        string $publicKeyPem
    ): bool {
        return openssl_verify($data, $signature, $publicKeyPem, OPENSSL_ALGO_SHA1) === 1;
    }

    public function hmacSignBody(string $body, string $secret): string
    {
        return hash_hmac('sha256', $body, $secret);
    }

    public function hmacVerifyBody(string $body, string $secret, string $expected): bool
    {
        return hash_equals($this->hmacSignBody($body, $secret), $expected);
    }

    public function generateRsaKeyPair(): array
    {
        $res = openssl_pkey_new([
            'private_key_bits' => self::RSA_KEY_BITS,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($res === false) {
            throw new \RuntimeException('RSA keygen failed: ' . openssl_error_string());
        }

        openssl_pkey_export($res, $privKey);
        $pubKeyDetails = openssl_pkey_get_details($res);
        $pubKey = $pubKeyDetails['key'];

        return [
            'private' => $privKey,
            'public'  => $pubKey,
        ];
    }
}
