<?php
/**
 * CryptoService — Service cryptographique d'iRemovalClone
 *
 * Reconstruit l'algorithme de dérivation de clé de session et la
 * signature des tickets d'activation iOS tel qu'observé dans
 * iremovalpro.dll (reverse-engineered).
 *
 * Algorithme (reconstitué à partir de l'audit statique):
 *   - PBKDF2-HMAC-SHA256
 *   - Password = "{sessionId}:{b64(nonceA)}:{b64(nonceB)}"
 *   - Salt     = "iremovalpro-iact8-v1"
 *   - Iterations = 10 000
 *   - dkLen    = 16 octets
 *   - Output   = nonce_C (16 octets base64)
 *
 * Signing:
 *   - RSA-1024 PKCS#1 v1.5
 *   - SHA-1 hash of the activation record
 *   - Output: 128 bytes (1024 bits) signature
 *
 * @author IremoveClone — Sprint 1-3 (Backend foundation)
 * @date 2026-06-22
 */

declare(strict_types=1);

namespace App\Service;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

final class CryptoService
{
    public const PBKDF2_SALT        = 'iremovalpro-iact8-v1';
    public const PBKDF2_ITERATIONS  = 10000;
    public const PBKDF2_DKLEN       = 16;       // 128 bits
    public const NONCE_LENGTH       = 16;       // 16 random bytes
    public const RSA_KEY_BITS       = 1024;     // RSA-1024

    /**
     * Dérive nonce_C à partir de la session + nonces A et B.
     * Reconstitue PBKDF2-HMAC-SHA256 du binaire original.
     */
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

        // hash_pbkdf2() natif PHP, conforme à RFC 2898
        $derivedKey = hash_pbkdf2(
            'sha256',
            $password,
            self::PBKDF2_SALT,
            self::PBKDF2_ITERATIONS,
            self::PBKDF2_DKLEN,
            true // raw_output
        );

        if ($derivedKey === false) {
            throw new \RuntimeException('PBKDF2 derivation failed');
        }

        return $derivedKey;
    }

    /**
     * Génère un nonce aléatoire de 16 octets (utilise random_bytes — CSPRNG).
     */
    public function generateNonce(): string
    {
        return random_bytes(self::NONCE_LENGTH);
    }

    /**
     * Signe un ticket d'activation avec la clé privée RSA-1024.
     * Reproduit le comportement d'OpenSSL SHA1-RSA-PKCS1v15 utilisé
     * par le serveur d'origine pour signer les iActivationRecord.
     *
     * @param string $ticketData  Données du ticket (binaire ou base64)
     * @param string $privateKey  Clé privée RSA au format PEM
     * @return string             Signature 128 octets (binaire)
     */
    public function signActivationTicket(
        string $ticketData,
        string $privateKey
    ): string {
        $key = PublicKeyLoader::loadPrivateKey($privateKey);
        $rsa = RSA::load($privateKey);
        // SHA-1 + PKCS#1 v1.5 (compatible avec l'API Security d'iOS)
        $rsa = $rsa->withHash('sha1')->withPadding(RSA::PADDING_PKCS1);
        $signature = $rsa->sign($ticketData);

        if ($signature === false) {
            throw new \RuntimeException('RSA signature failed');
        }

        return $signature;
    }

    /**
     * Vérifie la signature d'un ticket (utile pour les tests).
     */
    public function verifyTicketSignature(
        string $ticketData,
        string $signature,
        string $publicKey
    ): bool {
        $rsa = RSA::load($publicKey);
        $rsa = $rsa->withHash('sha1')->withPadding(RSA::PADDING_PKCS1);
        return $rsa->verify($ticketData, $signature);
    }

    /**
     * Construit le HMAC-SHA256 d'un corps de requête (mode API).
     * Utilisé pour signer les requêtes vers iact8/mf6/mf7.
     *
     * HMAC = HMAC-SHA256(secret=nonce_C, message=body)
     *       sortie hexadécimale 64 caractères
     */
    public function hmacSignBody(string $body, string $secret): string
    {
        return hash_hmac('sha256', $body, $secret);
    }

    /**
     * Vérifie un HMAC-SHA256.
     */
    public function hmacVerifyBody(string $body, string $secret, string $expected): bool
    {
        return hash_equals($this->hmacSignBody($body, $secret), $expected);
    }

    /**
     * Construit un iActivationRecord au format plist binaire.
     * Reproduit la structure du ticket d'activation iOS.
     *
     * Champs standard Apple :
     *   - ActivationState: "Activated"
     *   - SerialNumber
     *   - UniqueDeviceID (UDID)
     *   - UniqueChipID (ECID hex)
     *   - MLB (Main Logic Board)
     *   - ChipID
     *   - ProductType, ProductVersion
     *
     * Champs custom BlackHound :
     *   - iRemovalRecord   (données forgeronnes base64)
     *   - iRemovalSignature (signature RSA-1024 base64)
     */
    public function buildActivationRecord(
        string $udid,
        string $serial,
        string $imei,
        string $meid,
        string $ecid,
        string $model,
        string $iosVersion,
        string $mlb,
        string $chipId,
        string $iRemovalRecord,
        string $iRemovalSignature
    ): string {
        $record = [
            'ActivationState'   => 'Activated',
            'SerialNumber'      => $serial,
            'IMEI'              => $imei,
            'MEID'              => $meid,
            'UniqueDeviceID'    => $udid,
            'UniqueChipID'      => $ecid,
            'MLB'               => $mlb,
            'ChipID'            => $chipId,
            'ProductType'       => $model,
            'ProductVersion'    => $iosVersion,
            'iRemovalRecord'    => $iRemovalRecord,
            'iRemovalSignature' => $iRemovalSignature,
        ];

        // Pour la démo on utilise JSON, le binaire plist est converti
        // par un service dédié (BinaryPlistService) si nécessaire
        return json_encode($record, JSON_UNESCAPED_SLASHES);
    }

    /**
     * Convertit un iActivationRecord en plist binaire.
     * Utilise le format bplist00 minimal compatible iOS.
     * (Implémentation complète dans BinaryPlistService.)
     */
    public function toBinaryPlist(string $jsonRecord): string
    {
        $data = json_decode($jsonRecord, true);
        return BinaryPlistService::encodeDictionary($data);
    }

    /**
     * Génère une nouvelle paire de clés RSA-1024 (utilisé au boot
     * si aucune clé n'est trouvée sur disque).
     */
    public function generateRsaKeyPair(): array
    {
        $rsa = RSA::createKey(self::RSA_KEY_BITS);
        return [
            'private' => $rsa->toString('PKCS8'),
            'public'  => $rsa->getPublicKey()->toString('PKCS8'),
        ];
    }
}
