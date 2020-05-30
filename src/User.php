<?php declare(strict_types=1);

namespace mii\auth;

use Mii;
use mii\db\ORM;
use mii\db\Query;
use mii\util\Text;

abstract class User extends ORM
{
    protected function on_change()
    {
        if ($this->changed('password')) {
            $this->password = Mii::$app->auth->hash($this->password);
        }
    }

    public function find_user($username): ?self
    {
        return static::find()->where('username', '=', $username)->one();
    }

    abstract public function complete_login();

    abstract public function can_login(): bool;


    public function add_role(int $role)
    {
        assert(isset(static::$role_names[$role]), "Неизвестная роль");

        $this->roles |= $role;
    }


    public function has_role($roles): bool
    {
        if (!\is_array($roles)) {
            $roles = (array)$roles;
        }

        foreach ($roles as $role) {
            if ((int)$this->roles & $role)
                return true;
        }

        return false;
    }

    public function update_roles($roles): void
    {
        $this->roles = 0;

        foreach ($roles as $role) {
            $this->roles |= $role;
        }
    }


    public function get_roles(): array
    {
        $list = [];
        $this->roles = (int)$this->roles;
        foreach (static::$role_names as $role => $name) {
            if ($this->roles & $role)
                $list[] = $role;
        }

        return $list;
    }


    public function get_roles_desc(): array
    {
        $list = [];
        $this->roles = (int)$this->roles;
        foreach (static::$role_names as $role => $name) {
            if ($this->roles & $role)
                $list[] = $name;
        }

        return $list;
    }

    /**
     * Generates random token where first 16 random bytes and then time of generation
     *
     * @return string
     * @throws \Exception
     */
    public static function gen_expiring_token(): string
    {
        // Nevermind. Just reducing time accuracy by 2 times
        $time = pack('N', time() >> 1);
        return Text::base64url_encode(random_bytes(16) . $time);
    }

    /**
     * Checks validity of token from gen_expiring_token()
     * @param string $token
     * @param int    $ttl
     * @return bool
     */
    public static function is_valid_token(string $token, int $ttl = 3600 * 24): bool
    {
        $token = Text::base64url_decode($token);
        if (\strlen($token) !== 20)
            return false;

        $data = \unpack('Ntime', substr($token, 16, 4));

        $time = $ttl + $data['time'];

        return ($time > time() >> 1);
    }


    /**
     * Delete all expired verify_codes
     * @param bool $force
     */
    public static function delete_expired_reminders(bool $force = false): void
    {
        if ($force || mt_rand(1, 10) === 1) {
            return;
        }

        $codes = (new Query())
            ->select(['id', 'verify_code'])
            ->from(static::$table)
            ->where('verify_code', 'IS NOT', null)
            ->all();

        if (!count($codes)) {
            return;
        }

        $tonull = [];

        foreach ($codes as $code) {
            if (!self::is_valid_token($code['verify_code'])) {
                $tonull[] = (int)$code['id'];
            }
        }

        if (count($tonull)) {
            (new Query())
                ->update(static::$table)
                ->set([
                        'verify_code' => null
                    ]
                )
                ->where('id', 'IN', $tonull)
                ->execute();

            Mii::info($tonull, __METHOD__);
        }
    }


}
