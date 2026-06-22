<?php
/**
 * SessionManager (standalone) — Sessions bypass (file-based)
 *
 * Reproduit la machine à états du serveur d'origine :
 *   CREATED → AUTHENTICATED → EXPLOITED → ACTIVATED
 */

declare(strict_types=1);

namespace App\Clone;

final class SessionManager
{
    private readonly string $dir;

    public function __construct(string $dir)
    {
        $this->dir = $dir;
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0700, true);
        }
    }

    public function create(): array
    {
        $id = bin2hex(random_bytes(16));
        $session = [
            'id'         => $id,
            'state'      => 'CREATED',
            'created_at' => time(),
            'updated_at' => time(),
        ];
        $this->save($id, $session);
        return $session;
    }

    public function get(string $id): ?array
    {
        $path = $this->path($id);
        if (!file_exists($path)) return null;
        $data = json_decode(file_get_contents($path), true);
        return is_array($data) ? $data : null;
    }

    public function update(string $id, array $patch): void
    {
        $session = $this->get($id) ?? ['id' => $id, 'created_at' => time()];
        $session = array_merge($session, $patch);
        $session['updated_at'] = time();
        $this->save($id, $session);
    }

    public function all(): array
    {
        $sessions = [];
        foreach (glob($this->dir . '/*.json') as $f) {
            $data = json_decode(file_get_contents($f), true);
            if ($data) $sessions[] = $data;
        }
        return $sessions;
    }

    private function save(string $id, array $session): void
    {
        file_put_contents(
            $this->path($id),
            json_encode($session, JSON_PRETTY_PRINT),
            LOCK_EX
        );
    }

    private function path(string $id): string
    {
        return $this->dir . '/' . preg_replace('/[^a-f0-9]/', '', $id) . '.json';
    }
}
