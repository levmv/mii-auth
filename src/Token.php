<?php declare(strict_types=1);

namespace mii\auth;

use mii\db\ORM;
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
    public static $table = 'user_tokens';

    public function on_create()
    {
        $this->token = Text::base64url_encode(random_bytes(24));

        if (mt_rand(1, 100) === 1) {
            // Do garbage collection
            $this->delete_expired();
        }
    }

    /**
     * Deletes all expired tokens.
     *
     * @throws \mii\db\DatabaseException
     */
    public function delete_expired(): Token
    {
        static::query()
            ->delete()
            ->where('expires', '<', time())
            ->execute();

        return $this;
    }


    /**
     * Loads a token.
     *
     * @param string $token
     * @return    Token
     * @return    null
     * @throws \mii\db\ModelNotFoundException
     */
    public function get_token(string $token): ?Token
    {
        return static::find()->where('token', '=', $token)->one();
    }

}
