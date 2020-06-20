<?php declare(strict_types=1);

namespace mii\auth;

use Hybridauth\User\Profile;
use mii\util\UTF8;

class SocialProfile
{
    public $network = '';

    /**
     * The Unique user's ID on the connected provider
     *
     * @var integer
     */
    public $identifier = null;

    /**
     * URL link to user photo or avatar
     *
     * @var string
     */
    public $photoURL = null;


    /**
     * User's first name
     *
     * @var string
     */
    public $firstName = null;

    /**
     * User's last name
     *
     * @var string
     */
    public $lastName = null;

    /**
     * male or female
     *
     * @var string
     */
    public $gender = null;

    /**
     * User email. Note: not all of IDp grant access to the user email
     *
     * @var string
     */
    public $email = null;

    /**
     * Phone number
     *
     * @var string
     */
    public $phone = null;


    public function __construct(Profile $profile, string $network = '')
    {
        $this->network = $network;
        $this->identifier = $profile->identifier;
        $this->photoURL = $profile->photoURL;
        $this->firstName = UTF8::strip4b($profile->firstName);
        $this->lastName = UTF8::strip4b($profile->lastName);

        if (! $this->lastName && mb_strpos($this->firstName, ' ') !== false) {
            [$this->firstName, $this->lastName] = explode(' ', $this->firstName, 2);
        }

        $this->gender   = $profile->gender;
        $this->email    = $profile->email;
        $this->phone    = $profile->phone;
    }
}
