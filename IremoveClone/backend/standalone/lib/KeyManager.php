<?php
/**
 * KeyManager (standalone) — Gestion de la paire RSA-1024 bypass
 *
 * Charge/génère la clé privée qui signe les tickets iActivation forgés.
 * La clé publique correspond à celle extraite du dylib iOS :
 *   04_EXTRACTED/blackhound_rsa_pubkey.pem
 */

declare(strict_types=1);

namespace App\Clone;

use App\Clone\CryptoService;

final class KeyManager
{
    private readonly string $keysDir;
    private readonly CryptoService $crypto;

    public function __construct(string $keysDir)
    {
        $this->keysDir  = $keysDir;
        $this->crypto  = new CryptoService();
        if (!is_dir($this->keysDir)) {
            @mkdir($this->keysDir, 0700, true);
        }
    }

    public function getPrivateKey(): string
    {
        $path = $this->keysDir . '/bypass_private.pem';
        if (!file_exists($path)) {
            error_log('[KeyManager] No private key found, generating RSA-1024 key pair...');
            $keys = $this->crypto->generateRsaKeyPair();
            file_put_contents($path, $keys['private'], LOCK_EX);
            chmod($path, 0600);
            file_put_contents($this->keysDir . '/bypass_public.pem', $keys['public']);
            chmod($this->keysDir . '/bypass_public.pem', 0644);
        }
        return file_get_contents($path);
    }

    public function getPublicKey(): string
    {
        $path = $this->keysDir . '/bypass_public.pem';
        if (!file_exists($path)) {
            $this->getPrivateKey();
        }
        return file_get_contents($path);
    }

    public function getKeyInfo(): array
    {
        $key = openssl_pkey_get_public($this->getPublicKey());
        $details = openssl_pkey_get_details($key);

        return [
            'bits'         => $details['bits'] ?? 0,
            'type'         => $details['type'] ?? 0,
            'modulus_hex'  => bin2hex($details['rsa']['n'] ?? ''),
            'modulus_b64'  => base64_encode($details['rsa']['n'] ?? ''),
            'exponent'     => $details['rsa']['e'] ?? 0,
            'sha1_fpr'     => openssl_x509_fingerprint($this->getPublicKey()),
        ];
    }
}
