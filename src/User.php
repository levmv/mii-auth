<?php declare(strict_types=1);

namespace mii\auth;

use Mii;
use mii\db\ORM;
use mii\util\Text;

abstract class User extends ORM
{
    public const ROLE_LOGIN = 1;

    protected function onCreate()
    {
        if (!$this->get('roles')) {
            $this->roles = 0;
        }
    }

    protected function onChange()
    {
        if ($this->changed('password')) {
            $this->password = Mii::$app->auth->hash($this->password);
        }
    }

    abstract public function completeLogin();

    abstract public function canLogin(): bool;

    public static function findUser($username): ?self
    {
        return static::find()->where('username', '=', $username)->one();
    }

    public function addRole(int $role)
    {
        \assert(isset(static::$role_names[$role]), 'Неизвестная роль');

        if ($this->get('roles') === null) {
            $this->roles = $role;
        } else {
            $this->roles |= $role;
        }
    }


    public function hasRole($roles): bool
    {
        if (!\is_array($roles)) {
            $roles = (array) $roles;
        }

        foreach ($roles as $role) {
            if ((int) $this->roles & $role) {
                return true;
            }
        }

        return false;
    }

    public function updateRoles(array $roles): void
    {
        $this->roles = 0;

        foreach ($roles as $role) {
            $this->roles |= $role;
        }
    }


    public function getRoles(): array
    {
        $list = [];
        $this->roles = (int) $this->roles;
        foreach (static::$role_names as $role => $name) {
            if ($this->roles & $role) {
                $list[] = $role;
            }
        }

        return $list;
    }


    public function getRolesDesc(): array
    {
        $list = [];
        $this->roles = (int) $this->roles;
        foreach (static::$role_names as $role => $name) {
            if ($this->roles & $role) {
                $list[] = $name;
            }
        }

        return $list;
    }

    /**
     * Generates random token where first 16 random bytes and then time of generation
     *
     * @return string
     * @throws \Exception
     */
    public static function genExpiringToken(): string
    {
        // Nevermind. Just reducing time accuracy by 2 times
        $time = \pack('N', \time() >> 1);
        return Text::b64Encode(\random_bytes(16) . $time);
    }

    /**
     * Checks validity of token from gen_expiring_token()
     * @param string $token
     * @param int    $ttl
     * @return bool
     */
    public static function isValidToken(string $token, int $ttl = 3600 * 24): bool
    {
        $token = Text::b64Decode($token);
        if (\strlen($token) !== 20) {
            return false;
        }

        $data = \unpack('Ntime', \substr($token, 16, 4));

        $time = $ttl + $data['time'];

        return ($time > \time() >> 1);
    }


    /**
     * Delete all expired verify_codes
     * @param bool $force
     */
    public static function deleteExpiredReminders(bool $force = false): void
    {
        if ($force || \mt_rand(1, 10) === 1) {
            return;
        }

        $tonull = [];

        $codes = static::find()
            ->select(['id', 'verify_code'])
            ->where('verify_code', 'IS NOT', null)
            ->get()
            ->each(static function (User $u) use ($tonull) {
                if (!self::isValidToken($u->verify_code)) {
                    $tonull[] = $u->id;
                }
            });

        if (!\count($tonull)) {
            return;
        }

        static::query()
             ->update()
             ->set(
                 [
                     'verify_code' => null,
                 ]
             )
             ->where('id', 'IN', $tonull)
             ->execute();

        Mii::info($tonull, __METHOD__);
    }

    public function avatarFromUrl(string $file)
    {
    }


    public static function createUserFromSocial(SocialProfile $pf): User
    {
        $user = new static([
            'name' => e($pf->firstName),
            'surname' => e($pf->lastName),
            'username' => $pf->email ?: $pf->identifier,
            'password' => Text::b64Encode(\random_bytes(10)),
            'roles' => 1,
        ]);

        $user->create();

        if ($pf->photoURL) {
            $user->avatarFromUrl($pf->photoURL);
        }

        return $user;
    }
}
