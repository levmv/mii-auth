<?php declare(strict_types=1);

namespace levmorozov\auth;

use Mii;
use mii\db\DB;
use mii\db\ORM;
use mii\db\Query;

abstract class User extends ORM
{
    public function on_change() {
        if ($this->changed('password')) {
            $this->password = Mii::$app->auth->hash($this->password);
        }
    }

    public function find_user($username) {
        return static::find()->where('username', '=', $username)->one();
    }

    abstract public function complete_login();
    abstract public function can_login() : bool;


    public function add_role(int $role) {
        assert(isset(static::$role_names[$role]), "Неизвестная роль");

        $this->roles |= $role;
    }


    public function has_role($roles): bool {

        if (!\is_array($roles)) {
            $roles = (array)$roles;
        }

        foreach ($roles as $role) {
            if ((int)$this->roles & $role)
                return true;
        }

        return false;
    }

    public function update_roles($roles) : void {

        $this->roles = 0;

        foreach ($roles as $role) {
            $this->roles |= $role;
        }
    }


    public function get_roles() : array
    {
        $list = [];
        $this->roles = (int) $this->roles;
        foreach (static::$role_names as $role => $name) {
            if($this->roles & $role)
                $list[] = $role;
        }

        return $list;
    }


    public function get_roles_desc() {
        $list = [];
        $this->roles = (int) $this->roles;
        foreach (static::$role_names as $role => $name) {
            if($this->roles & $role)
                $list[] = $name;
        }

        return $list;
    }

}