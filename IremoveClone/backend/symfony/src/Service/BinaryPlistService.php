<?php
/**
 * BinaryPlistService — Encodeur/décodeur plist binaire (bplist00) simplifié
 *
 * Implémente un encodeur bplist00 minimal compatible avec iOS, suffisant
 * pour sérialiser le dictionnaire d'activation iActivationRecord. Le
 * format bplist00 est documenté par Apple dans
 * https://opensource.apple.com/source/CF/CF-1153.18/CFBinaryPList.c
 *
 * Supporte les types :
 *   - dict, array
 *   - string (UTF-8)
 *   - integer
 *   - boolean
 *   - data (binaire)
 *   - real
 *   - date
 *
 * @author IremoveClone
 */

declare(strict_types=1);

namespace App\Service;

final class BinaryPlistService
{
    // Type markers (bplist00)
    public const TYPE_NULL      = 0x00;
    public const TYPE_FALSE     = 0x08;
    public const TYPE_TRUE      = 0x09;
    public const TYPE_UINT      = 0x10;
    public const TYPE_REAL      = 0x20;
    public const TYPE_DATE      = 0x30;
    public const TYPE_DATA      = 0x40;
    public const TYPE_STRING    = 0x50;
    public const TYPE_UID       = 0x70;
    public const TYPE_ARRAY     = 0xA0;
    public const TYPE_DICT      = 0xD0;

    public static function encodeDictionary(array $dict): string
    {
        // Flatten all objects, collect them
        $objects = [];
        $rootIndex = self::buildObject($dict, $objects);

        // Trailer: 6 bytes (offset table size, root index, marker, version)
        $objectCount = count($objects);

        // Calculate offset table
        $offsets = [];
        $currentOffset = 0;
        foreach ($objects as $obj) {
            $offsets[] = $currentOffset;
            $currentOffset += strlen($obj);
        }

        // Sort offset table by index
        ksort($offsets);

        // Build offset table
        $offsetTable = '';
        $offsetTableSize = 1;
        $maxOffset = $currentOffset;
        while ($offsetTableSize < 8 && (1 << ($offsetTableSize * 8)) <= $maxOffset) {
            $offsetTableSize++;
        }
        foreach ($offsets as $offset) {
            // Pack as big-endian
            $offsetTable .= pack('C' . $offsetTableSize, $offset);
        }

        // Build the body
        $body = implode('', $objects);

        // Build the trailer
        $trailer = '';
        $trailer .= pack('C', $offsetTableSize);  // size of offset ints
        $trailer .= pack('C', $offsetTableSize);  // dup
        $trailer .= self::packBigEndianUInt($rootIndex, $offsetTableSize);  // root index
        $trailer .= pack('C', 0x0A);  // marker
        $trailer .= pack('C', 0x00);  // version 00

        // Final output
        return 'bplist00' . $body . $offsetTable . $trailer;
    }

    private static function buildObject($value, array &$objects): int
    {
        $type = gettype($value);

        switch ($type) {
            case 'boolean':
                $encoded = $value ? chr(self::TYPE_TRUE) : chr(self::TYPE_FALSE);
                break;

            case 'integer':
                $encoded = self::encodeInteger($value);
                break;

            case 'double':
                $encoded = self::encodeReal($value);
                break;

            case 'string':
                $encoded = self::encodeString($value);
                break;

            case 'array':
                // Distinguish between indexed array (list) and assoc (dict)
                $isDict = false;
                if (!empty($value)) {
                    $keys = array_keys($value);
                    if (array_keys($keys) !== $keys) {
                        $isDict = true;
                    }
                }
                if ($isDict) {
                    $encoded = self::encodeDict($value, $objects);
                } else {
                    $encoded = self::encodeArray($value, $objects);
                }
                break;

            case 'NULL':
                $encoded = chr(self::TYPE_NULL);
                break;

            default:
                throw new \InvalidArgumentException("Unsupported type: $type");
        }

        $objects[] = $encoded;
        return count($objects) - 1;
    }

    private static function encodeInteger(int $value): string
    {
        if ($value < 0) {
            throw new \InvalidArgumentException("Negative integers not supported in this encoder");
        }
        if ($value <= 0xFF) {
            return chr(self::TYPE_UINT) . chr($value);
        }
        if ($value <= 0xFFFF) {
            return chr(self::TYPE_UINT | 0x01) . pack('n', $value);
        }
        if ($value <= 0xFFFFFFFF) {
            return chr(self::TYPE_UINT | 0x02) . pack('N', $value);
        }
        // 8 bytes
        return chr(self::TYPE_UINT | 0x03) . pack('J', $value);
    }

    private static function encodeReal(float $value): string
    {
        return chr(self::TYPE_REAL | 0x03) . pack('E', $value);
    }

    private static function encodeString(string $value): string
    {
        $len = strlen($value);
        if ($len <= 0x0F) {
            return chr(self::TYPE_STRING | $len) . $value;
        }
        if ($len <= 0xFFFF) {
            return chr(self::TYPE_STRING | 0x10) . pack('n', $len) . $value;
        }
        return chr(self::TYPE_STRING | 0x11) . pack('N', $len) . $value;
    }

    private static function encodeArray(array $array, array &$objects): string
    {
        $count = count($array);
        $indexes = [];
        foreach ($array as $item) {
            $indexes[] = self::buildObject($item, $objects);
        }

        $header = self::arrayHeader(self::TYPE_ARRAY, $count);
        return $header . self::packInts($indexes);
    }

    private static function encodeDict(array $dict, array &$objects): string
    {
        $count = count($dict);

        // Encode keys and values
        $keyIndexes = [];
        $valueIndexes = [];
        foreach ($dict as $key => $value) {
            $keyIndexes[] = self::buildObject((string)$key, $objects);
            $valueIndexes[] = self::buildObject($value, $objects);
        }

        $header = self::arrayHeader(self::TYPE_DICT, $count);
        return $header . self::packInts($keyIndexes) . self::packInts($valueIndexes);
    }

    private static function arrayHeader(int $type, int $count): string
    {
        if ($count <= 0x0F) {
            return chr($type | $count);
        }
        if ($count <= 0xFFFF) {
            return chr($type | 0x10) . pack('n', $count);
        }
        return chr($type | 0x11) . pack('N', $count);
    }

    private static function packInts(array $indexes): string
    {
        $maxIdx = max($indexes);
        if ($maxIdx <= 0xFF) {
            return pack('C*', ...$indexes);
        }
        if ($maxIdx <= 0xFFFF) {
            $out = '';
            foreach ($indexes as $i) {
                $out .= pack('n', $i);
            }
            return $out;
        }
        $out = '';
        foreach ($indexes as $i) {
            $out .= pack('N', $i);
        }
        return $out;
    }

    private static function packBigEndianUInt(int $value, int $bytes): string
    {
        if ($bytes === 1) {
            return pack('C', $value);
        }
        if ($bytes === 2) {
            return pack('n', $value);
        }
        if ($bytes === 3 || $bytes === 4) {
            return substr(pack('N', $value), -$bytes);
        }
        if ($bytes <= 8) {
            return substr(pack('J', $value), -$bytes);
        }
        throw new \InvalidArgumentException("Too many bytes: $bytes");
    }
}
