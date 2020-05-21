<?php declare(strict_types=1);

namespace mii\auth;

use Mii;
use mii\core\Component;
use mii\db\Query;
use mii\web\Session;

/**
 * User authorization library. Handles user login and logout, as well as secure
 * password hashing.
 *
 */
class Auth extends Component
{
    /**
     * @var Session
     */
    protected $_session;

    protected ?User $_user = null;

    protected $user_model = 'app\models\User';

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
        $this->_session = \Mii::$app->session;
    }


    /**
     * Gets the currently logged in user from the session (with auto_login check).
     * Returns FALSE if no user is currently logged in.
     *
     * @return  mixed
     * @throws \mii\db\ModelNotFoundException
     */
    public function get_user(): ?User
    {
        if ($this->_user)
            return $this->_user;

        if ($this->_session->check_cookie()) {
            try {
                $this->_user = $this->_session->get($this->session_key);
            } catch (\Throwable $t) {
                $this->_user = null;
                $this->_session->delete($this->session_key);
                return null;
            }
        }

        if (!$this->_user and Mii::$app->request->get_cookie($this->token_cookie, false)) {
            // check for "remembered" login
            $this->auto_login();
        }
        // If somehow our user was corrupted
        if (!\is_object($this->_user) || !$this->_user->id)
            $this->_user = null;

        return $this->_user;
    }


    /**
     * Set current user and store him in session
     * @param User $user
     */
    public function set_user(User $user): void
    {
        $this->_session->set($this->session_key, $user);
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
    public function login($username, $password, $remember = true): bool
    {
        if (empty($password))
            return false;

        $username = mb_strtolower($username);

        $user = (new $this->user_model)->find_user($username);

        if (!$user)
            return false;

        if ($user->id && $user->can_login() && $this->verify_password($password, $user->password)) {
            if ($remember === true) {
                $this->set_autologin($user->id);
            }

            // Finish the login
            $this->complete_login($user);

            return true;
        }

        // Login failed
        return false;
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
        $this->_session->delete('auth_forced');

        if ($token = Mii::$app->request->get_cookie($this->token_cookie)) {
            // Delete the autologin cookie to prevent re-login
            Mii::$app->request->delete_cookie($this->token_cookie);

            // Clear the autologin token from the database
            $token = (new Token)->get_token($token);

            if ($token and $token->loaded() and $logout_all) {
                (new Query)->delete($token->get_table())->where('user_id', '=', $token->user_id)->execute();
            } elseif ($token and $token->loaded()) {
                $token->delete();
            }
        }

        if ($destroy === true) {
            // Destroy the session completely
            $this->_session->destroy();
        } else {
            // Remove the user from the session
            $this->_session->delete($this->session_key);

            // Regenerate session_id
            $this->_session->regenerate();
        }

        $this->_user = null;

        // Double check
        return !$this->logged_in();
    }

    public function set_autologin($user_id)
    {
        // Create a new autologin token
        $token = (new Token)->set([
            'user_id' => $user_id,
            'expires' => time() + $this->lifetime
        ]);
        $token->create();

        // Set the autologin cookie
        Mii::$app->request->set_cookie($this->token_cookie, $token->token, $this->lifetime);
    }


    /**
     * Check if there is an active session. Optionally allows checking for a
     * specific role. By default checking for «login» role.
     */
    public function logged_in($role = null): bool
    {
        // Get the user from the session
        $user = $this->get_user();

        return $user and ($role !== null ? $user->has_role($role) : true);
    }


    /**
     *
     * @param string $password password to hash
     * @return  string
     */
    public function hash(string $password): string
    {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => $this->hash_cost]);
    }


    public function verify_password(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }


    protected function complete_login(User $user): bool
    {
        // Regenerate session_id
        $this->_session->regenerate();

        $this->set_user($user);

        $user->complete_login();

        return true;
    }


    /**
     * Compare password with original (hashed). Works for current (logged in) user
     *
     * @param string $password
     * @return  boolean
     * @throws \mii\db\ModelNotFoundException
     */
    public function check_password($password): bool
    {
        $user = $this->get_user();

        if (!$user)
            return false;

        return ($this->hash($password) === $user->password);
    }


    /**
     * Forces a user to be logged in, without specifying a password.
     *
     * @param User    $user
     * @param boolean $mark_session_as_forced mark the session as forced
     * @return  boolean
     */
    public function force_login(User $user, $mark_session_as_forced = false)
    {

        if ($mark_session_as_forced === true) {
            // Mark the session as forced, to prevent users from changing account information
            $this->_session->set('auth_forced', true);
        }

        // Run the standard completion
        $this->complete_login($user);

        return true;
    }

    /**
     * Logs a user in, based on the token cookie.
     *
     * @return  mixed
     * @throws \mii\db\ModelNotFoundException
     */
    public function auto_login(): ?User
    {
        $token_str = Mii::$app->request->get_cookie($this->token_cookie);

        if (!$token_str)
            return null;

        // Load the token and user
        $token = Token::find(['token', '=', $token_str])->one();

        if ($token !== null) {
            $user = \call_user_func([$this->user_model, 'one'], $token->user_id);

            if ($user !== null) {
                // Gen new token
                $this->set_autologin($token->user_id);

                // Complete the login with the found data
                $this->complete_login($user);

                $token->delete();

                // Automatic login was successful
                return $user;
            }
        }

        // Token is invalid
        \Mii::$app->request->delete_cookie($this->token_cookie);
        return null;
    }
}
