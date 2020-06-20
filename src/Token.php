<?php declare(strict_types=1);

namespace mii\auth;

use mii\db\ORM;
use mii\db\Query;
use mii\util\Text;

/**
 * Class Token
 * @package levmorozov\auth
 *
 * @property int    $id
 * @property int    $user_id
 * @property string $token
 * @property int    $expires
 */
class Token extends ORM
{
    public static function table(): string
    {
        return 'user_tokens';
    }

    public function onCreate()
    {
        $this->token = Text::b64Encode(random_bytes(24));

        if (mt_rand(1, 100) === 1) {
            // Do garbage collection
            static::deleteExpired();
        }
    }

    /**
     * Deletes all expired tokens.
     */
    public static function deleteExpired() : void
    {
        static::query()
            ->delete()
            ->where('expires', '<', time())
            ->execute();
    }


    public static function deleteAllUserTokens(int $user_id)
    {
        return static::query()
            ->delete()
            ->where('user_id', '=', $user_id)
            ->execute();
    }


    /**
     * Loads a token.
     *
     * @param string $token
     * @return    Token
     * @return    null
     */
    public static function getToken(string $token): ?Token
    {
        return static::find()->where('token', '=', $token)->one();
    }
}
