<?php declare(strict_types=1);

namespace mii\auth;

use Hybridauth\Storage\StorageInterface;

class SocialStorage implements StorageInterface
{
    public const SOCIAL_KEYS = 'SOCIALKEYS';

    /**
     * Retrieve a item from storage
     *
     * @param string $key
     *
     * @return mixed
     */
    public function get($key)
    {
        $keys = \Mii::$app->session->get(static::SOCIAL_KEYS, []);

        return $keys[$key] ?? null;
    }

    /**
     * Add or Update an item to storage
     *
     * @param string $key
     * @param string $value
     */
    public function set($key, $value)
    {
        $keys = \Mii::$app->session->get(static::SOCIAL_KEYS, []);
        $keys[$key] = $value;
        \Mii::$app->session->set(static::SOCIAL_KEYS, $keys);
    }

    /**
     * Delete an item from storage
     *
     * @param string $key
     */
    public function delete($key)
    {
        $keys = \Mii::$app->session->get(static::SOCIAL_KEYS, []);
        if (isset($keys[$key])) {
            unset($keys[$key]);
            \Mii::$app->session->set(static::SOCIAL_KEYS, $keys);
        }
    }

    /**
     * Delete a item from storage
     *
     * @param string $key
     */
    public function deleteMatch($key)
    {
        $keys = \Mii::$app->session->get(static::SOCIAL_KEYS, []);
        foreach ($keys as $k => $v) {
            if (\strstr($k, $key)) {
                unset($keys[$k]);
            }
        }
        \Mii::$app->session->set(static::SOCIAL_KEYS, $keys);
    }

    /**
     * Clear all items in storage
     */
    public function clear()
    {
        \Mii::$app->session->delete(static::SOCIAL_KEYS);
    }
}
