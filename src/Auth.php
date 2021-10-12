<?php declare(strict_types=1);

namespace mii\auth;

use Mii;
use mii\core\Component;
use mii\db\Query;
use mii\log\Logger;
use mii\web\Session;

/**
 * User authorization library. Handles user login and logout, as well as secure
 * password hashing.
 *
 */
class Auth extends Component
{
    protected ?Session $_session = null;

    protected ?User $_user = null;

    protected string $user_model = 'app\models\User';

    protected int $hash_cost = 8;

    protected int $lifetime = 2592000;

    protected string $session_key = 'misk';

    protected string $token_cookie = 'mitc';


    /**
     * Loads Session and configuration options.
     *
     * @param array $config Config Options
     */
    public function init(array $config = []): void
    {
        parent::init($config);
    }


    public function session(): Session
    {
        if(!$this->_session) {
            $this->_session = \Mii::$app->session;
        }
        return $this->_session;
    }


    /**
     * Gets the currently logged in user from the session (with auto_login check).
     * Returns FALSE if no user is currently logged in.
     *
     * @return  mixed
     * @throws \mii\db\ModelNotFoundException
     */
    public function getUser(bool $autoLogin = true): ?User
    {
        if ($this->_user) {
            return $this->_user;
        }

        if ($this->session()->checkCookie()) {
            try {
                $this->_user = $this->session()->get($this->session_key);
            } catch (\Throwable $e) {
                $this->_user = null;
                $this->session()->delete($this->session_key);
                Mii::error($e, __METHOD__);
                return null;
            }
        }

        // check for "remembered" login
        if ($autoLogin && !$this->_user && Mii::$app->request->getCookie($this->token_cookie, false)) {
            $this->autoLogin();
        }
        // If somehow our user was corrupted
        if (!\is_object($this->_user) || !$this->_user->id) {
            $this->_user = null;
        }

        return $this->_user;
    }


    /**
     * Set current user and store him in session
     * @param User $user
     */
    public function setUser(User $user): void
    {
        $this->session()->set($this->session_key, $user);
        $this->_user = $user;
    }


    /**
     * Attempt to log in a user by using an ORM object and plain-text password.
     *
     * @param string  $username Username to log in
     * @param string  $password Password to check against
     * @param boolean $remember Enable autologin
     * @return  boolean
     */
    public function login(string $username, string $password, bool $remember = true): bool
    {
        if (empty($password)) {
            return false;
        }

        $username = \mb_strtolower($username);

        $user = $this->getUserModel()->findUser($username);

        if (!$user) {
            return false;
        }

        if ($user->id && $user->canLogin() && $this->verifyPassword($password, $user->password)) {
            if ($remember === true) {
                $this->setAutologin($user->id);
            }

            // Finish the login
            $this->completeLogin($user);

            return true;
        }

        // Login failed
        return false;
    }

    public function getUserModel() : User
    {
        return new $this->user_model;
    }


    /**
     * Log a user out and remove any autologin cookies.
     *
     * @param boolean $destroy completely destroy the session
     * @param boolean $logout_all remove all tokens for user
     * @return  boolean
     * @throws \mii\core\Exception
     * @throws \mii\db\DatabaseException
     * @throws \mii\db\ModelNotFoundException
     */
    public function logout($destroy = false, $logout_all = false): bool
    {
        // Set by force_login()
        $this->session()->delete('auth_forced');

        if ($token = Mii::$app->request->getCookie($this->token_cookie)) {
            // Delete the autologin cookie to prevent re-login
            Mii::$app->request->deleteCookie($this->token_cookie);

            // Clear the autologin token from the database
            $token = Token::getToken($token);

            if ($logout_all && $token) {
                (new Query)->delete($token::table())->where('user_id', '=', $token->user_id)->execute();
            } elseif ($token) {
                $token->delete();
            }
        }

        if ($destroy === true) {
            // Destroy the session completely
            $this->session()->destroy();
        } else {
            // Remove the user from the session
            $this->session()->delete($this->session_key);

            // Regenerate session_id
            $this->session()->regenerate();
        }

        $this->_user = null;

        // Double check
        return !$this->loggedIn();
    }

    public function setAutologin($user_id)
    {
        // Create a new autologin token
        $token = (new Token)->set([
            'user_id' => $user_id,
            'expires' => \time() + $this->lifetime,
        ]);
        $token->create();

        // Set the autologin cookie
        Mii::$app->request->setCookie($this->token_cookie, $token->token, $this->lifetime);
    }


    /**
     * Check if there is an active session. Optionally allows checking for a
     * specific role. By default checking for «login» role.
     */
    public function loggedIn($role = null): bool
    {
        // Get the user from the session
        $user = $this->getUser();

        return $user and ($role !== null ? $user->hasRole($role) : true);
    }


    /**
     *
     * @param string $password password to hash
     * @return  string
     */
    public function hash(string $password): string
    {
        return \password_hash($password, \PASSWORD_BCRYPT, ['cost' => $this->hash_cost]);
    }


    public function verifyPassword(string $password, string $hash): bool
    {
        return \password_verify($password, $hash);
    }


    protected function completeLogin(User $user): bool
    {
        // Regenerate session_id
        $this->session()->regenerate();

        $this->setUser($user);

        $user->completeLogin();

        return true;
    }


    /**
     * Compare password with original (hashed). Works for current (logged in) user
     *
     * @param string $password
     * @return  boolean
     * @throws \mii\db\ModelNotFoundException
     */
    public function checkPassword($password): bool
    {
        $user = $this->getUser();

        if (!$user) {
            return false;
        }

        return ($this->hash($password) === $user->password);
    }


    /**
     * Forces a user to be logged in, without specifying a password.
     *
     * @param User    $user
     * @param boolean $mark_session_as_forced mark the session as forced
     * @return  boolean
     */
    public function forceLogin(User $user, $mark_session_as_forced = false)
    {
        if ($mark_session_as_forced === true) {
            // Mark the session as forced, to prevent users from changing account information
            $this->session()->set('auth_forced', true);
        }

        $this->setAutologin($user->id);

        // Run the standard completion
        $this->completeLogin($user);

        return true;
    }

    /**
     * Logs a user in, based on the token cookie.
     *
     * @return  mixed
     * @throws \mii\db\ModelNotFoundException
     */
    public function autoLogin(): ?User
    {
        $token_str = Mii::$app->request->getCookie($this->token_cookie);

        if (!$token_str) {
            return null;
        }

        // Load the token and user
        $token = Token::where(['token', '=', $token_str])->one();

        if ($token !== null) {
            $user = \call_user_func([$this->user_model, 'one'], $token->user_id);

            if ($user !== null) {
                // Gen new token
                $this->setAutologin($token->user_id);

                // Complete the login with the found data
                $this->completeLogin($user);

                $token->delete();

                // Automatic login was successful
                return $user;
            }
        }

        Mii::log(Logger::NOTICE, 'Token is invalid'.$token_str, __METHOD__);
        \Mii::$app->request->deleteCookie($this->token_cookie);
        return null;
    }
}
