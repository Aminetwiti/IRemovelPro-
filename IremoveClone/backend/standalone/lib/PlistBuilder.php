<?php
/**
 * PlistBuilder (standalone) — Génère le plist binaire iActivationRecord
 *
 * Reproduit la structure du ticket d'activation forgé que le serveur
 * envoie au client iOS (avant signature RSA).
 *
 * Le plist est un bplist00 (binary plist version 00) — format utilisé
 * par iOS pour ses plists natifs.
 */

declare(strict_types=1);

namespace App\Clone;

final class PlistBuilder
{
    /**
     * Construit un iActivationRecord complet (JSON → bplist00 binaire).
     * Reproduit les champs observés dans le dylib blackhound.dylib.
     */
    public function buildActivationRecord(
        string $udid,
        string $serial,
        string $imei,
        string $meid,
        string $ecid,
        string $iosVersion,
        string $productType,
        string $mlb,
        string $chipId,
        string $apnonce
    ): string {
        // Build the record as a nested array
        $activationInfo = [
            'ActivationState'   => 'Activated',
            'SIMStatus'         => 'None',
            'BrickMode'         => false,
            'SecurityDomain'    => 1,
            'EffectiveProductionMode' => true,
            'EffectiveSecurityMode' => false,
        ];

        $record = [
            'ActivationRecord'   => $this->buildRecordPayload(
                $udid, $serial, $imei, $meid, $ecid,
                $iosVersion, $productType, $mlb, $chipId, $apnonce
            ),
            'ActivationInfo'     => $activationInfo,
            'iRemovalRecord'     => $this->buildRemovalRecord($udid, $serial, $imei, $meid, $ecid),
            'iRemovalSignature'  => '',  // filled by signer
        ];

        // Convert to JSON for RSA signing (binary plist would also work)
        return json_encode($record, JSON_UNESCAPED_SLASHES);
    }

    private function buildRecordPayload(
        string $udid, string $serial, string $imei, string $meid,
        string $ecid, string $ios, string $model, string $mlb,
        string $chipId, string $apnonce
    ): array {
        return [
            'SerialNumber'     => $serial,
            'IMEI'             => $imei,
            'MEID'             => $meid,
            'UniqueDeviceID'   => $udid,
            'UniqueChipID'     => $ecid,
            'MLB'              => $mlb,
            'ChipID'           => $chipId,
            'ProductType'      => $model,
            'ProductVersion'   => $ios,
            'BasebandMasterKeyHash' => str_repeat('0', 64),
            'FMiPEnabled'      => false,
            'iCloudSignedIn'   => false,
        ];
    }

    private function buildRemovalRecord(
        string $udid, string $serial, string $imei, string $meid, string $ecid
    ): string {
        // Le record BlackHound contient 3 parties encodées en base64
        // (analogue au log format observé dans le dylib)
        $part1 = base64_encode(hash('sha256', $udid . $serial, true));
        $part2 = base64_encode(hash('sha256', $udid . $imei, true));
        $part3 = base64_encode(json_encode([
            'meid' => $meid,
            'ecid' => $ecid,
        ]));

        return "$part1.$part2.$part3";
    }

    /**
     * Encode un dictionnaire en bplist00 (binaire plist iOS).
     */
    public function toBinaryPlist(array $data): string
    {
        $objects = [];
        $rootIndex = $this->buildObject($data, $objects);

        $body = implode('', $objects);
        $offsets = [];
        $currentOffset = 0;
        foreach ($objects as $obj) {
            $offsets[] = $currentOffset;
            $currentOffset += strlen($obj);
        }

        $offsetTableSize = 1;
        $maxOffset = $currentOffset;
        while ($offsetTableSize < 8 && (1 << ($offsetTableSize * 8)) <= $maxOffset) {
            $offsetTableSize++;
        }
        $offsetTable = '';
        foreach ($offsets as $offset) {
            $offsetTable .= substr(pack('J', $offset), -$offsetTableSize);
        }

        $trailer  = chr($offsetTableSize);
        $trailer .= chr($offsetTableSize);
        $trailer .= substr(pack('J', $rootIndex), -$offsetTableSize);
        $trailer .= chr(0x0A);
        $trailer .= chr(0x00);

        return "bplist00{$body}{$offsetTable}{$trailer}";
    }

    private function buildObject($value, array &$objects): int
    {
        $type = gettype($value);
        switch ($type) {
            case 'boolean':
                $encoded = chr($value ? 0x09 : 0x08);
                break;
            case 'integer':
                $encoded = $this->encodeInteger($value);
                break;
            case 'double':
                $encoded = "\x23" . pack('E', $value);
                break;
            case 'string':
                $encoded = $this->encodeString($value);
                break;
            case 'array':
                $isDict = false;
                if (!empty($value)) {
                    $keys = array_keys($value);
                    if ($keys !== array_keys($keys)) $isDict = true;
                }
                $encoded = $isDict
                    ? $this->encodeDict($value, $objects)
                    : $this->encodeArray($value, $objects);
                break;
            case 'NULL':
                $encoded = "\x00";
                break;
            default:
                throw new \InvalidArgumentException("Unsupported type: $type");
        }
        $objects[] = $encoded;
        return count($objects) - 1;
    }

    private function encodeInteger(int $v): string
    {
        if ($v < 0) {
            // Encode as signed
            if ($v >= -128) return "\x11" . chr($v & 0xff);
            if ($v >= -32768) return "\x12" . pack('n', $v & 0xffff);
            return "\x13" . pack('N', $v & 0xffffffff);
        }
        if ($v <= 0xff) return "\x10" . chr($v);
        if ($v <= 0xffff) return "\x11" . pack('n', $v);
        return "\x12" . pack('N', $v);
    }

    private function encodeString(string $s): string
    {
        $len = strlen($s);
        if ($len <= 0x0F) return chr(0x50 | $len) . $s;
        if ($len <= 0xFFFF) return "\x60" . pack('n', $len) . $s;
        return "\x70" . pack('N', $len) . $s;
    }

    private function encodeArray(array $arr, array &$objects): string
    {
        $count = count($arr);
        $idx = [];
        foreach ($arr as $v) $idx[] = $this->buildObject($v, $objects);
        $header = $this->arrayHeader(0xA0, $count);
        return $header . $this->packInts($idx);
    }

    private function encodeDict(array $d, array &$objects): string
    {
        $keyIdx = [];
        $valIdx = [];
        foreach ($d as $k => $v) {
            $keyIdx[] = $this->buildObject((string)$k, $objects);
            $valIdx[] = $this->buildObject($v, $objects);
        }
        $header = $this->arrayHeader(0xD0, count($d));
        return $header . $this->packInts($keyIdx) . $this->packInts($valIdx);
    }

    private function arrayHeader(int $type, int $count): string
    {
        if ($count <= 0x0F) return chr($type | $count);
        if ($count <= 0xFFFF) return chr($type | 0x10) . pack('n', $count);
        return chr($type | 0x11) . pack('N', $count);
    }

    private function packInts(array $idx): string
    {
        $max = max($idx);
        if ($max <= 0xFF) return pack('C*', ...$idx);
        if ($max <= 0xFFFF) {
            $out = '';
            foreach ($idx as $i) $out .= pack('n', $i);
            return $out;
        }
        $out = '';
        foreach ($idx as $i) $out .= pack('N', $i);
        return $out;
    }
}
