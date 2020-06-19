<?php declare(strict_types=1);

namespace mii\auth;

use mii\db\ORM;

/**
 * Class UserSocial
 * @package app\models
 *
 * @property int    $id
 * @property int    $user_id
 * @property string $network
 * @property string $identity
 */
class UserSocial extends ORM
{
    public static function table(): string
    {
        return 'user_socials';
    }
}
