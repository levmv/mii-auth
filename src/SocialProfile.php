<?php declare(strict_types=1);

namespace mii\auth;

use Hybridauth\User\Profile;
use mii\util\UTF8;

class SocialProfile
{
    public string $network = '';

    /**
     * The Unique user's ID on the connected provider
     *
     * @var integer
     */
    public $identifier = null;

    /**
     * URL link to user photo or avatar
     */
    public ?string $photoURL = null;


    /**
     * User's first name
     */
    public ?string $firstName = null;

    /**
     * User's last name
     */
    public ?string $lastName = null;

    /**
     * male or female
     */
    public ?string $gender = null;

    /**
     * User email. Note: not all of IDp grant access to the user email
     */
    public ?string $email = null;

    /**
     * Phone number
     */
    public ?string $phone = null;


    public function __construct(Profile $profile, string $network = '')
    {
        $this->network = $network;
        $this->identifier = $profile->identifier;
        $this->photoURL = $profile->photoURL;
        $this->firstName = UTF8::strip4b((string) $profile->firstName);
        $this->lastName = UTF8::strip4b((string) $profile->lastName);

        if (!$this->lastName && \mb_strpos($this->firstName, ' ') !== false) {
            [$this->firstName, $this->lastName] = \explode(' ', $this->firstName, 2);
        }

        $this->gender   = $profile->gender;
        $this->email    = $profile->email;
        $this->phone    = $profile->phone;
    }
}
