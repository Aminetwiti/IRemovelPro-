<?php
/**
 * KeyManagerService — Gestion des clés RSA-1024 bypass
 *
 * Responsabilités :
 *   - Charger la paire de clés RSA-1024 (public/privé) depuis le disque
 *   - La générer à la première installation
 *   - Servir la clé publique (équivalent de l'offset 0x7960 dans le dylib)
 *
 * Emplacement des clés : var/keys/
 *   - bypass_private.pem (privée — 600)
 *   - bypass_public.pem  (publique — 644, distribuée au client iOS)
 *
 * Le dylib iOS embarque une COPIE de la clé publique (extraite dans
 * 04_EXTRACTED/blackhound_rsa_pubkey.pem). La privée reste sur le
 * serveur et signe les tickets d'activation forgés.
 *
 * @author IremoveClone
 */

declare(strict_types=1);

namespace App\Service;

use Psr\Log\LoggerInterface;

final class KeyManagerService
{
    private readonly string $keysDir;

    public function __construct(
        private readonly CryptoService $crypto,
        private readonly LoggerInterface $logger,
        string $projectDir = '/var/www/iremo'
    ) {
        $this->keysDir = $projectDir . '/var/keys';
        if (!is_dir($this->keysDir)) {
            @mkdir($this->keysDir, 0700, true);
        }
    }

    /**
     * Récupère (ou génère) la clé privée du serveur de signature.
     */
    public function getPrivateKey(): string
    {
        $path = $this->keysDir . '/bypass_private.pem';
        if (!file_exists($path)) {
            $this->logger->warning('No private key found, generating new RSA-1024 key pair');
            $keys = $this->crypto->generateRsaKeyPair();
            file_put_contents($path, $keys['private'], LOCK_EX);
            chmod($path, 0600);
            file_put_contents($this->keysDir . '/bypass_public.pem', $keys['public']);
            chmod($this->keysDir . '/bypass_public.pem', 0644);
        }
        return file_get_contents($path);
    }

    /**
     * Récupère la clé publique (à distribuer au client iOS).
     */
    public function getPublicKey(): string
    {
        $path = $this->keysDir . '/bypass_public.pem';
        if (!file_exists($path)) {
            // Force la génération via getPrivateKey()
            $this->getPrivateKey();
        }
        return file_get_contents($path);
    }

    /**
     * Renvoie la clé publique au format PEM subjectPublicKeyInfo
     * (celle embarquée dans le dylib iOS, à comparer avec
     * 04_EXTRACTED/blackhound_rsa_pubkey.pem).
     */
    public function getPublicKeyAsn1(): string
    {
        $pem = $this->getPublicKey();
        // Strip PKCS#8 headers and re-encode as SPKI
        $der = self::pemToDer($pem);
        // Wrap as SubjectPublicKeyInfo (RSA-1024)
        $spki = self::wrapAsSubjectPublicKeyInfo($der);
        return self::derToPem($spki, 'PUBLIC KEY');
    }

    public function getKeyInfo(): array
    {
        $pub = $this->getPublicKey();
        $key = openssl_pkey_get_public($pub);
        $details = openssl_pkey_get_details($key);

        return [
            'bits'         => $details['bits'] ?? 0,
            'key_type'     => $details['type'] ?? OPENSSL_KEYTYPE_RSA,
            'modulus_hex'  => bin2hex($details['rsa']['n'] ?? ''),
            'exponent_hex' => bin2hex($details['rsa']['e'] ?? ''),
            'modulus_b64'  => base64_encode($details['rsa']['n'] ?? ''),
            'exponent'     => $details['rsa']['e'] ?? 0,
        ];
    }

    private static function pemToDer(string $pem): string
    {
        $lines = explode("\n", $pem);
        $b64 = '';
        foreach ($lines as $line) {
            if (strpos($line, '-----') === false) {
                $b64 .= trim($line);
            }
        }
        return base64_decode($b64);
    }

    private static function derToPem(string $der, string $type): string
    {
        $b64 = base64_encode($der);
        $lines = "-----BEGIN $type-----\n";
        foreach (str_split($b64, 64) as $chunk) {
            $lines .= $chunk . "\n";
        }
        $lines .= "-----END $type-----\n";
        return $lines;
    }

    private static function wrapAsSubjectPublicKeyInfo(string $rsaPubKeyDer): string
    {
        // RSA OID 1.2.840.113549.1.1.1
        $algId = hex2bin('300d06092a864886f70d0101010500');
        $bitString = "\x00" . $rsaPubKeyDer;
        $bitStringWrapped = "\x03" . self::encodeLength(strlen($bitString)) . $bitString;
        $spki = "\x30" . self::encodeLength(strlen($algId) + strlen($bitStringWrapped))
              . $algId
              . $bitStringWrapped;
        return $spki;
    }

    private static function encodeLength(int $length): string
    {
        if ($length < 0x80) return chr($length);
        if ($length < 0x100) return "\x81" . chr($length);
        return "\x82" . pack('n', $length);
    }
}
